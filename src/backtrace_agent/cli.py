from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
import webbrowser
from pathlib import Path

from .analysis import analyze_run, compare_runs, evaluate_policy, focus_incident, render_markdown_summary
from .bundle import verify_evidence_bundle, write_evidence_bundle
from .ci import render_junit_xml
from .core import build_restart_brief, detect_signals, parse_trace, slice_run, suppress_content
from .report import write_report


INTEGER_POLICY_KEYS = {"max_failures", "max_unresolved_failures", "max_destructive_actions", "max_repetitions", "max_stalls", "max_total_tokens"}
NUMBER_POLICY_KEYS = {"max_failure_rate", "max_tokens_per_action", "min_cache_ratio"}
BOOLEAN_POLICY_KEYS = {"require_evidence", "fail_on_regression"}
POLICY_KEYS = INTEGER_POLICY_KEYS | NUMBER_POLICY_KEYS | BOOLEAN_POLICY_KEYS


def nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return parsed


def nonnegative_float(value: str) -> float:
    parsed = float(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return parsed


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="backtrace-agent", description="Turn raw AI-agent logs into evidence-backed diagnostics and restart context.")
    parser.add_argument("trace", type=Path, nargs="?", help="JSON/JSONL trace. Omit to use the newest local Codex session.")
    parser.add_argument("--verify-bundle", type=Path, metavar="ZIP", help="Verify an evidence bundle's structure, sizes, and hashes, then exit")
    parser.add_argument("--verify-source", type=Path, metavar="TRACE", help="With --verify-bundle, prove that TRACE matches the recorded source fingerprint")
    parser.add_argument("--watch", action="store_true", help="Regenerate outputs whenever the trace file changes; stop with Ctrl-C")
    parser.add_argument("--watch-interval", type=positive_float, default=1.0, metavar="SECONDS", help="Polling interval for --watch (default: 1.0)")
    parser.add_argument("--output", "-o", type=Path, default=Path("backtrace-report.html"), help="HTML report path")
    parser.add_argument("--json", action="store_true", help="Print privacy-safe normalized data as JSON")
    parser.add_argument("--normalized-output", type=Path, help="Write privacy-safe normalized JSON")
    parser.add_argument("--summary-output", type=Path, help="Write an evidence-backed Markdown run summary")
    parser.add_argument("--junit-output", type=Path, metavar="XML", help="Write quality-gate checks as JUnit XML for CI test reporters")
    parser.add_argument("--bundle", type=Path, metavar="ZIP", help="Write a sanitized evidence bundle with report, JSON, summary, and hash manifest")
    parser.add_argument("--policy", type=Path, metavar="JSON", help="Load reusable quality-gate thresholds from a validated JSON policy")
    parser.add_argument("--compare", type=Path, metavar="BASELINE", help="Compare this run with a baseline JSON/JSONL trace")
    parser.add_argument("--from-event", metavar="EVENT_ID", help="Focus generated artifacts at this normalized event ID (inclusive)")
    parser.add_argument("--to-event", metavar="EVENT_ID", help="Focus generated artifacts at this normalized event ID (inclusive)")
    parser.add_argument("--agent", action="append", default=[], metavar="NAME", help="Include only this agent in a focused report; repeatable")
    parser.add_argument("--incident", metavar="EVENT_OR_INCIDENT_ID", help="Automatically focus the complete incident containing this failure or recovery")
    parser.add_argument("--context-events", type=nonnegative_int, metavar="N", help="Include N events before and after --incident evidence (default: 3)")
    parser.add_argument("--suppress", action="append", default=[], metavar="TERM", help="Remove lines and paths containing TERM from every generated artifact; repeatable")
    parser.add_argument("--restart-at", metavar="EVENT_ID", help="Also write a restart brief at an event ID")
    parser.add_argument("--brief-output", type=Path, default=Path("restart-brief.md"), help="Restart brief path")
    parser.add_argument("--open", action="store_true", help="Open the generated report in the default browser")
    parser.add_argument("--fail-on-errors", action="store_true", help="Exit 1 when the trace contains failed actions (useful in CI)")
    parser.add_argument("--max-failures", type=nonnegative_int, metavar="N", help="Fail the quality gate when failed actions exceed N")
    parser.add_argument("--max-unresolved-failures", type=nonnegative_int, metavar="N", help="Fail when operation-level failures lack later successful recovery evidence")
    parser.add_argument("--max-destructive-actions", type=nonnegative_int, metavar="N", help="Fail when explicit destructive-action attempts exceed N")
    parser.add_argument("--max-repetitions", type=nonnegative_int, metavar="N", help="Fail the quality gate when repeated-action signals exceed N")
    parser.add_argument("--max-stalls", type=nonnegative_int, metavar="N", help="Fail the quality gate when within-turn stalls exceed N")
    parser.add_argument("--max-failure-rate", type=nonnegative_float, metavar="PERCENT", help="Fail when failed actions exceed this percentage of actions")
    parser.add_argument("--require-evidence", action="store_true", help="Require at least one successful test, build, package, push, or deployment proof")
    parser.add_argument("--fail-on-regression", action="store_true", help="Fail when --compare produces a regressed verdict")
    parser.add_argument("--max-total-tokens", type=nonnegative_int, metavar="N", help="Fail when the recorded cumulative token counter exceeds N")
    parser.add_argument("--max-tokens-per-action", type=nonnegative_float, metavar="N", help="Fail when recorded tokens per meaningful action exceed N")
    parser.add_argument("--min-cache-ratio", type=nonnegative_float, metavar="PERCENT", help="Fail when cached input is below this percentage of input tokens")
    return parser


def newest_codex_session() -> Path:
    root = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")) / "sessions"
    candidates = list(root.rglob("*.jsonl")) if root.exists() else []
    if not candidates:
        raise ValueError(f"No Codex sessions found under {root}. Pass a trace path explicitly.")
    return max(candidates, key=lambda path: path.stat().st_mtime)


def load_policy(path: Path) -> dict:
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read policy {path}: {exc}") from exc
    if not isinstance(policy, dict):
        raise ValueError("Policy must be a JSON object.")
    unknown = sorted(set(policy) - POLICY_KEYS)
    if unknown:
        raise ValueError(f"Unknown policy key(s): {', '.join(unknown)}")
    for key, value in policy.items():
        if key in BOOLEAN_POLICY_KEYS and not isinstance(value, bool):
            raise ValueError(f"Policy key {key} must be true or false.")
        if key in INTEGER_POLICY_KEYS and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
            raise ValueError(f"Policy key {key} must be a nonnegative integer.")
        if key in NUMBER_POLICY_KEYS and (isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0):
            raise ValueError(f"Policy key {key} must be a nonnegative number.")
    return policy


def build_policy_spec(args: argparse.Namespace) -> dict:
    policy = load_policy(args.policy) if args.policy else {}
    cli_values = {
        "max_failures": args.max_failures,
        "max_unresolved_failures": args.max_unresolved_failures,
        "max_destructive_actions": args.max_destructive_actions,
        "max_repetitions": args.max_repetitions,
        "max_stalls": args.max_stalls,
        "max_failure_rate": args.max_failure_rate,
        "max_total_tokens": args.max_total_tokens,
        "max_tokens_per_action": args.max_tokens_per_action,
        "min_cache_ratio": args.min_cache_ratio,
    }
    policy.update({key: value for key, value in cli_values.items() if value is not None})
    if args.require_evidence:
        policy["require_evidence"] = True
    if args.fail_on_regression:
        policy["fail_on_regression"] = True
    if args.fail_on_errors:
        policy["max_failures"] = 0
    return policy


def _atomic_write_text(destination: Path, content: str) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    os.close(descriptor)
    try:
        Path(temporary).write_text(content, encoding="utf-8")
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _process_once(args: argparse.Namespace, trace: Path, *, allow_open: bool = True) -> int:
    try:
        run = parse_trace(trace)
        baseline = parse_trace(args.compare) if args.compare else None
        focused = bool(args.from_event or args.to_event or args.agent or args.incident)
        if focused and baseline:
            raise ValueError("Focused slicing cannot be combined with --compare because event ranges are run-specific.")
        if args.incident and (args.from_event or args.to_event):
            raise ValueError("--incident chooses its own boundaries and cannot be combined with --from-event or --to-event.")
        if args.context_events is not None and not args.incident:
            raise ValueError("--context-events requires --incident.")
        if args.incident:
            run = focus_incident(run, args.incident, context_events=args.context_events if args.context_events is not None else 3, agents=args.agent)
        elif focused:
            run = slice_run(run, from_event=args.from_event, to_event=args.to_event, agents=args.agent)
        if args.suppress:
            run = suppress_content(run, args.suppress)
            baseline = suppress_content(baseline, args.suppress) if baseline else None
        policy_spec = build_policy_spec(args)
    except (OSError, ValueError) as exc:
        print(f"backtrace-agent: {exc}", file=sys.stderr)
        return 2
    signals = detect_signals(run.events)
    analysis = analyze_run(run)
    comparison = compare_runs(run, baseline) if baseline else None
    quality_gate = evaluate_policy(run, policy_spec, comparison)
    if args.policy:
        quality_gate["policy_source"] = args.policy.name
    export = {"run": run.as_dict(), "analysis": analysis, "comparison": comparison, "quality_gate": quality_gate}
    if args.json:
        print(json.dumps(export, indent=2, ensure_ascii=False))
    report = write_report(run, args.output, comparison=comparison, quality_gate=quality_gate)
    print(f"Report: {report.resolve()}")
    counts = analysis["counts"]
    print(f"Source: {trace.resolve()}")
    print(f"Turns: {counts['turns']} · Meaningful events: {counts['events']} · Actions: {counts['actions']} · Failed: {counts['failures']} · Signals: {len(signals)}")
    if analysis["privacy"]["secret_findings"]:
        print(f"Privacy: redacted {analysis['privacy']['secret_findings']} recognized secret occurrence(s) from generated outputs")
    suppression = run.metadata.get("custom_suppression") or {}
    if suppression:
        print(f"Custom suppression: removed {suppression.get('removed_items', 0)} matching line(s), path(s), or metadata item(s)")
    scope = run.metadata.get("scope") or {}
    if scope.get("active"):
        agent_text = f" · agents: {', '.join(scope['agents'])}" if scope.get("agents") else ""
        print(f"Focus: {scope['selected_event_count']}/{scope['source_event_count']} events · {scope['from_event']} → {scope['to_event']}{agent_text}")
        incident = scope.get("incident") or {}
        if incident:
            print(f"Incident: {incident['operation']} · {incident['status']} · {len(incident['failure_event_ids'])} failed attempt(s) · context ±{incident['context_events']}")
    if comparison:
        summary = comparison["summary"]
        print(f"Comparison: {comparison['verdict']} · {summary['regressions']} regression(s) · {summary['improvements']} improvement(s) vs {args.compare.resolve()}")
    if quality_gate["configured"]:
        gate = quality_gate["summary"]
        print(f"Quality gate: {'passed' if quality_gate['passed'] else 'FAILED'} · {gate['passed']} passed · {gate['failed']} failed")
        if args.policy:
            print(f"Policy: {args.policy.resolve()}")
    if args.normalized_output:
        _atomic_write_text(args.normalized_output, json.dumps(export, indent=2, ensure_ascii=False))
        print(f"Normalized JSON: {args.normalized_output.resolve()}")
    if args.summary_output:
        _atomic_write_text(args.summary_output, render_markdown_summary(run, comparison, quality_gate))
        print(f"Summary: {args.summary_output.resolve()}")
    if args.junit_output:
        _atomic_write_text(args.junit_output, render_junit_xml(run, quality_gate))
        print(f"JUnit: {args.junit_output.resolve()}")
    if args.bundle:
        bundle = write_evidence_bundle(run, args.bundle, comparison=comparison, quality_gate=quality_gate)
        print(f"Evidence bundle: {bundle.resolve()}")
    if args.restart_at:
        try:
            brief = build_restart_brief(run, args.restart_at)
        except ValueError as exc:
            print(f"backtrace-agent: {exc}", file=sys.stderr)
            return 2
        _atomic_write_text(args.brief_output, brief)
        print(f"Restart brief: {args.brief_output.resolve()}")
    if args.open and allow_open:
        webbrowser.open(report.resolve().as_uri())
    return 1 if quality_gate["configured"] and not quality_gate["passed"] else 0


def _watch(args: argparse.Namespace, trace: Path, *, _sleep=time.sleep, _max_cycles: int | None = None) -> int:
    last_signature: tuple[int, int] | None = None
    last_exit = 0
    opened = False
    cycles = 0
    print(f"Watching: {trace.resolve()} · every {args.watch_interval:g}s · Ctrl-C to stop")
    try:
        while True:
            try:
                stat = trace.stat()
                signature = (stat.st_mtime_ns, stat.st_size)
            except OSError as exc:
                print(f"backtrace-agent: {exc}", file=sys.stderr)
                return 2
            if signature != last_signature:
                print(f"Trace changed: {stat.st_size:,} bytes · regenerating")
                last_exit = _process_once(args, trace, allow_open=not opened)
                opened = opened or last_exit != 2
                last_signature = signature
            cycles += 1
            if _max_cycles is not None and cycles >= _max_cycles:
                return last_exit
            _sleep(args.watch_interval)
    except KeyboardInterrupt:
        print(f"Watch stopped · last exit status {last_exit}")
        return last_exit


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.verify_source and not args.verify_bundle:
        print("backtrace-agent: --verify-source requires --verify-bundle", file=sys.stderr)
        return 2
    if args.verify_bundle:
        if args.trace or args.watch:
            print("backtrace-agent: do not pass a trace or --watch with --verify-bundle", file=sys.stderr)
            return 2
        result = verify_evidence_bundle(args.verify_bundle, source_trace=args.verify_source)
        if result["valid"]:
            source_status = " · source trace matched" if result["source_verified"] else ""
            print(f"Bundle verification: PASS · {result['files_verified']} payload(s) verified{source_status} · {args.verify_bundle.resolve()}")
            return 0
        print(f"Bundle verification: FAIL · {args.verify_bundle.resolve()}", file=sys.stderr)
        for error in result["errors"]:
            print(f"- {error}", file=sys.stderr)
        return 1
    try:
        trace = args.trace or newest_codex_session()
    except (OSError, ValueError) as exc:
        print(f"backtrace-agent: {exc}", file=sys.stderr)
        return 2
    return _watch(args, trace) if args.watch else _process_once(args, trace)


if __name__ == "__main__":
    raise SystemExit(main())

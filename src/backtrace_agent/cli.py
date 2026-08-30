from __future__ import annotations

import argparse
import json
import os
import sys
import webbrowser
from pathlib import Path

from .analysis import analyze_run, compare_runs, evaluate_policy, render_markdown_summary
from .core import build_restart_brief, detect_signals, parse_trace, suppress_content
from .report import write_report


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="backtrace-agent", description="Turn raw AI-agent logs into evidence-backed diagnostics and restart context.")
    parser.add_argument("trace", type=Path, nargs="?", help="JSON/JSONL trace. Omit to use the newest local Codex session.")
    parser.add_argument("--output", "-o", type=Path, default=Path("backtrace-report.html"), help="HTML report path")
    parser.add_argument("--json", action="store_true", help="Print privacy-safe normalized data as JSON")
    parser.add_argument("--normalized-output", type=Path, help="Write privacy-safe normalized JSON")
    parser.add_argument("--summary-output", type=Path, help="Write an evidence-backed Markdown run summary")
    parser.add_argument("--compare", type=Path, metavar="BASELINE", help="Compare this run with a baseline JSON/JSONL trace")
    parser.add_argument("--suppress", action="append", default=[], metavar="TERM", help="Remove lines and paths containing TERM from every generated artifact; repeatable")
    parser.add_argument("--restart-at", metavar="EVENT_ID", help="Also write a restart brief at an event ID")
    parser.add_argument("--brief-output", type=Path, default=Path("restart-brief.md"), help="Restart brief path")
    parser.add_argument("--open", action="store_true", help="Open the generated report in the default browser")
    parser.add_argument("--fail-on-errors", action="store_true", help="Exit 1 when the trace contains failed actions (useful in CI)")
    parser.add_argument("--max-failures", type=nonnegative_int, metavar="N", help="Fail the quality gate when failed actions exceed N")
    parser.add_argument("--max-unresolved-failures", type=nonnegative_int, metavar="N", help="Fail when operation-level failures lack later successful recovery evidence")
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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        trace = args.trace or newest_codex_session()
        run = parse_trace(trace)
        baseline = parse_trace(args.compare) if args.compare else None
        if args.suppress:
            run = suppress_content(run, args.suppress)
            baseline = suppress_content(baseline, args.suppress) if baseline else None
    except (OSError, ValueError) as exc:
        print(f"backtrace-agent: {exc}", file=sys.stderr)
        return 2
    signals = detect_signals(run.events)
    analysis = analyze_run(run)
    comparison = compare_runs(run, baseline) if baseline else None
    policy_spec = {
        "max_failures": 0 if args.fail_on_errors else args.max_failures,
        "max_unresolved_failures": args.max_unresolved_failures,
        "max_repetitions": args.max_repetitions,
        "max_stalls": args.max_stalls,
        "max_failure_rate": args.max_failure_rate,
        "require_evidence": args.require_evidence,
        "fail_on_regression": args.fail_on_regression,
        "max_total_tokens": args.max_total_tokens,
        "max_tokens_per_action": args.max_tokens_per_action,
        "min_cache_ratio": args.min_cache_ratio,
    }
    quality_gate = evaluate_policy(run, policy_spec, comparison)
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
    if comparison:
        summary = comparison["summary"]
        print(f"Comparison: {comparison['verdict']} · {summary['regressions']} regression(s) · {summary['improvements']} improvement(s) vs {args.compare.resolve()}")
    if quality_gate["configured"]:
        gate = quality_gate["summary"]
        print(f"Quality gate: {'passed' if quality_gate['passed'] else 'FAILED'} · {gate['passed']} passed · {gate['failed']} failed")
    if args.normalized_output:
        args.normalized_output.write_text(json.dumps(export, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Normalized JSON: {args.normalized_output.resolve()}")
    if args.summary_output:
        args.summary_output.write_text(render_markdown_summary(run, comparison, quality_gate), encoding="utf-8")
        print(f"Summary: {args.summary_output.resolve()}")
    if args.restart_at:
        try:
            brief = build_restart_brief(run, args.restart_at)
        except ValueError as exc:
            print(f"backtrace-agent: {exc}", file=sys.stderr)
            return 2
        args.brief_output.write_text(brief, encoding="utf-8")
        print(f"Restart brief: {args.brief_output.resolve()}")
    if args.open:
        webbrowser.open(report.resolve().as_uri())
    return 1 if quality_gate["configured"] and not quality_gate["passed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

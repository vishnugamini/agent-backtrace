from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
import tempfile
import time
import webbrowser
from pathlib import Path

from .analysis import analyze_run, catalog_incidents, compare_runs, evaluate_policy, focus_incident, render_markdown_summary, search_events
from .bundle import verify_evidence_bundle, write_evidence_bundle
from .ci import render_fleet_junit_xml, render_junit_xml
from .core import build_restart_brief, detect_signals, inspect_source_health, parse_trace, slice_run, suppress_content
from .fleet import evaluate_fleet_gate, scan_traces, update_fleet_history, write_fleet_report
from .notify import build_fleet_notification, deliver_webhook, format_fleet_notification, serialize_webhook_payload, validate_webhook_url
from .report import write_report


INTEGER_POLICY_KEYS = {"max_failures", "max_unresolved_failures", "max_destructive_actions", "max_repetitions", "max_stalls", "max_total_tokens", "max_unsupported_items", "max_malformed_records", "max_duplicate_event_ids"}
NUMBER_POLICY_KEYS = {"max_failure_rate", "max_tokens_per_action", "min_cache_ratio"}
BOOLEAN_POLICY_KEYS = {"require_evidence", "fail_on_regression"}
POLICY_KEYS = INTEGER_POLICY_KEYS | NUMBER_POLICY_KEYS | BOOLEAN_POLICY_KEYS
FLEET_INTEGER_GATE_KEYS = {"max_fleet_needs_attention", "max_fleet_unresolved", "max_fleet_source_issues", "max_new_attention"}


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


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="backtrace-agent", description="Turn raw AI-agent logs into evidence-backed diagnostics and restart context.")
    parser.add_argument("trace", type=Path, nargs="?", help="JSON/JSONL trace. Omit to use the newest local Codex session.")
    parser.add_argument("--verify-bundle", type=Path, metavar="ZIP", help="Verify an evidence bundle's structure, sizes, and hashes, then exit")
    parser.add_argument("--verify-source", type=Path, metavar="TRACE", help="With --verify-bundle, prove that TRACE matches the recorded source fingerprint")
    parser.add_argument("--scan", type=Path, metavar="DIR", help="Build a risk-ranked dashboard across recent JSON/JSONL traces below DIR")
    parser.add_argument("--scan-limit", type=positive_int, default=50, metavar="N", help="Maximum newest trace files to inspect with --scan (default: 50)")
    parser.add_argument("--history", type=Path, metavar="JSON", help="With --scan, append a privacy-minimized snapshot and show fleet trends")
    parser.add_argument("--history-limit", type=positive_int, default=50, metavar="N", help="Maximum snapshots retained by --history (default: 50)")
    parser.add_argument("--max-fleet-needs-attention", type=nonnegative_int, metavar="N", help="With --scan, fail when more than N runs need attention")
    parser.add_argument("--max-fleet-unresolved", type=nonnegative_int, metavar="N", help="With --scan, fail when unresolved incidents exceed N")
    parser.add_argument("--max-fleet-source-issues", type=nonnegative_int, metavar="N", help="With --scan, fail when source-integrity issues exceed N")
    parser.add_argument("--max-new-attention", type=nonnegative_int, metavar="N", help="With --scan and --history, fail when new risky runs exceed N")
    parser.add_argument("--fail-on-fleet-regression", action="store_true", help="With --scan and --history, fail when any existing run's status worsens")
    parser.add_argument("--webhook-url-env", metavar="ENV_VAR", help="With fleet gates, read the destination URL from this environment variable")
    parser.add_argument("--webhook-signing-secret-env", metavar="ENV_VAR", help="Read an optional HMAC signing secret from this environment variable")
    parser.add_argument("--notify-on", choices=("failure", "always"), default="failure", help="Send the fleet webhook on gate failure or every decision (default: failure)")
    parser.add_argument("--webhook-timeout", type=positive_float, default=10.0, metavar="SECONDS", help="Webhook request timeout (default: 10)")
    parser.add_argument("--webhook-retries", type=nonnegative_int, default=2, metavar="N", help="Transient webhook retries after the first attempt (default: 2)")
    parser.add_argument("--webhook-format", choices=("generic", "slack", "teams"), default="generic", help="Exact outbound message shape (default: generic)")
    parser.add_argument("--webhook-payload-output", type=Path, metavar="JSON", help="Write the exact privacy-safe request body without requiring a destination")
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
    parser.add_argument("--list-incidents", action="store_true", help="Print a compact incident catalog with stable --incident references, then exit")
    parser.add_argument("--incident-status", choices=("all", "recovered", "unresolved"), default="all", help="Filter --list-incidents by recovery status (default: all)")
    parser.add_argument("--find", metavar="TEXT", help="Search normalized event evidence and print stable event IDs without writing a report")
    parser.add_argument("--event-kind", action="append", default=[], metavar="KIND", help="With --find, include only this normalized event kind; repeatable")
    parser.add_argument("--event-status", choices=("all", "ok", "error", "warning"), default="all", help="Filter --find by event status (default: all)")
    parser.add_argument("--find-limit", type=positive_int, default=20, metavar="N", help="Maximum --find results to return (default: 20)")
    parser.add_argument("--audit-ingestion", action="store_true", help="Inspect parser coverage and unsupported provider item types without writing a report")
    parser.add_argument("--doctor", action="store_true", help="Inspect source integrity, malformed records, duplicate IDs, and timestamp order without writing a report")
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
    parser.add_argument("--max-unsupported-items", type=nonnegative_int, metavar="N", help="Fail when more than N completed semantic items use unsupported provider types")
    parser.add_argument("--max-malformed-records", type=nonnegative_int, metavar="N", help="Fail when more than N source records cannot be decoded as JSON")
    parser.add_argument("--max-duplicate-event-ids", type=nonnegative_int, metavar="N", help="Fail when more than N normalized event IDs are duplicated")
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
        "max_unsupported_items": args.max_unsupported_items,
        "max_malformed_records": args.max_malformed_records,
        "max_duplicate_event_ids": args.max_duplicate_event_ids,
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


def _list_incidents(args: argparse.Namespace, trace: Path) -> int:
    try:
        run = parse_trace(trace)
        if args.suppress:
            run = suppress_content(run, args.suppress)
        catalog = catalog_incidents(run, agents=args.agent, status=args.incident_status)
    except (OSError, ValueError) as exc:
        print(f"backtrace-agent: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(catalog, indent=2, ensure_ascii=False))
        return 0
    summary = catalog["summary"]
    filters = catalog["filters"]
    filter_text = f" · status: {filters['status']}"
    if filters["agents"]:
        filter_text += f" · agents: {', '.join(filters['agents'])}"
    print(f"Incidents: {summary['total']} · {summary['unresolved']} unresolved · {summary['recovered']} recovered{filter_text}")
    print(f"Source: {trace.resolve()}")
    if not catalog["incidents"]:
        print("No matching failure incidents detected.")
        return 0
    for item in catalog["incidents"]:
        recovery = item["recovery_event_id"] or "not recovered"
        print(f"{item['number']:>2}. {item['status'].upper():<10} {item['operation']} · {item['failed_attempts']} failed · agents: {', '.join(item['agents'])}")
        print(f"    Reference: {item['focus_reference']} · Recovery: {recovery}")
        print(f"    Focus: backtrace-agent {shlex.quote(str(trace))} --incident {shlex.quote(item['focus_reference'])} -o incident-report.html")
    return 0


def _find_events(args: argparse.Namespace, trace: Path) -> int:
    try:
        run = parse_trace(trace)
        if args.suppress:
            run = suppress_content(run, args.suppress)
        results = search_events(
            run, args.find, agents=args.agent, kinds=args.event_kind,
            status=args.event_status, limit=args.find_limit,
        )
    except (OSError, ValueError) as exc:
        print(f"backtrace-agent: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return 0
    summary = results["summary"]
    print(f"Matches: {summary['returned']} of {summary['total_matches']} · query: {results['query']!r}")
    print(f"Source: {trace.resolve()}")
    if not results["events"]:
        print("No matching normalized events detected.")
        return 0
    for index, event in enumerate(results["events"], 1):
        seconds = max(0, round(event["at_ms"] / 1000))
        timestamp = f"{seconds // 60:02d}:{seconds % 60:02d}"
        print(f"{index:>2}. [{event['status'].upper()}] {timestamp} · {event['agent']} · {event['kind']} · {event['title']}")
        print(f"    Event: {event['id']}" + (f" · Operation: {event['operation']}" if event["operation"] else ""))
        if event["files"]:
            print(f"    Files: {', '.join(event['files'][:5])}")
        if event["preview"]:
            print(f"    Evidence: {event['preview']}")
        print(f"    Slice: backtrace-agent {shlex.quote(str(trace))} --from-event {shlex.quote(event['id'])} --to-event {shlex.quote(event['id'])} -o focused-report.html")
    if summary["truncated"]:
        print(f"Showing the first {summary['returned']} ranked matches; increase --find-limit to return more.")
    return 0


def _audit_ingestion(args: argparse.Namespace, trace: Path) -> int:
    try:
        run = parse_trace(trace)
        if args.suppress:
            run = suppress_content(run, args.suppress)
        ingestion = analyze_run(run)["ingestion"]
    except (OSError, ValueError) as exc:
        print(f"backtrace-agent: {exc}", file=sys.stderr)
        return 2
    result = {
        "source": str(trace.resolve()),
        "source_wide": True,
        **ingestion,
    }
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    print(f"Ingestion audit: {ingestion['adapter']} adapter · source-wide")
    print(f"Source: {trace.resolve()}")
    print(f"Raw records: {ingestion['total_records']} · bookkeeping separated: {ingestion['bookkeeping_records']}")
    print(
        f"Semantic candidates: {ingestion['semantic_candidates']} · normalized: {ingestion['normalized_events']} "
        f"· materialized: {ingestion['semantic_coverage_percent']}% · adapter coverage: {ingestion['adapter_coverage_percent']}%"
    )
    print(
        f"Unsupported completed items: {ingestion['unsupported_completed_items']} "
        f"· supported empty items omitted: {ingestion['omitted_supported_items']}"
    )
    if ingestion["unsupported_item_types"]:
        print("Unsupported provider item types:")
        for item in ingestion["unsupported_item_types"]:
            print(f"- {item['type']}: {item['count']}")
    else:
        print("Unsupported provider item types: none detected")
    if ingestion["omitted_supported_item_types"]:
        print("Supported item types omitted for empty content:")
        for item in ingestion["omitted_supported_item_types"]:
            print(f"- {item['type']}: {item['count']}")
    return 0


def _doctor(args: argparse.Namespace, trace: Path) -> int:
    try:
        run = parse_trace(trace)
        if args.suppress:
            run = suppress_content(run, args.suppress)
        health = analyze_run(run)["input_health"]
    except ValueError:
        try:
            health = inspect_source_health(trace)
        except OSError as exc:
            print(f"backtrace-agent: {exc}", file=sys.stderr)
            return 2
    except OSError as exc:
        print(f"backtrace-agent: {exc}", file=sys.stderr)
        return 2
    result = {"source": str(trace.resolve()), **health}
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    print(f"Trace doctor: {'HEALTHY' if health['healthy'] else 'ISSUES DETECTED'} · {health['format']}")
    print(f"Source: {trace.resolve()}")
    print(f"Parsed objects: {health['parsed_object_records']} · lines: {health['total_lines']} · blank: {health['blank_lines']}")
    print(
        f"Malformed: {health['malformed_records']} · non-object: {health['non_object_records']} "
        f"· encoding replacements: {health['encoding_replacement_characters']}"
    )
    if health["normalization_available"]:
        print(f"Duplicate event IDs: {health['duplicate_event_ids']} · timestamp regressions: {health['timestamp_regressions']}")
    else:
        print("Normalized ID and timestamp checks: unavailable because no event object could be parsed")
    if health["malformed_line_numbers"]:
        print("Malformed lines: " + ", ".join(str(value) for value in health["malformed_line_numbers"]))
    if health["trailing_partial_record"]:
        print("Trailing partial record: yes (the active writer may not have finished the final line)")
    if health["duplicate_event_id_samples"]:
        print("Duplicate ID samples: " + ", ".join(health["duplicate_event_id_samples"]))
    return 0


def _scan(args: argparse.Namespace) -> int:
    try:
        fleet = scan_traces(args.scan, limit=args.scan_limit, suppress=args.suppress)
        if args.history:
            fleet["history"] = update_fleet_history(fleet, args.history, limit=args.history_limit)
        gate_spec = {key: getattr(args, key) for key in FLEET_INTEGER_GATE_KEYS}
        gate_spec["fail_on_fleet_regression"] = args.fail_on_fleet_regression
        fleet["quality_gate"] = evaluate_fleet_gate(fleet, gate_spec)
        fleet["notification"] = {"configured": False, "status": "not_configured", "format": args.webhook_format, "payload_written": False, "attempts": 0, "status_code": None, "error": None, "event_id": None}
        if args.webhook_url_env or args.webhook_payload_output:
            payload = build_fleet_notification(fleet)
            formatted_payload = format_fleet_notification(payload, args.webhook_format)
            payload_written = bool(args.webhook_payload_output)
            if args.webhook_payload_output:
                _atomic_write_text(args.webhook_payload_output, serialize_webhook_payload(formatted_payload))
            should_send = args.notify_on == "always" or not fleet["quality_gate"]["passed"]
            if not args.webhook_url_env:
                fleet["notification"] = {"configured": True, "status": "previewed", "format": args.webhook_format, "payload_written": payload_written, "attempts": 0, "status_code": None, "error": None, "event_id": payload["event_id"]}
            elif should_send:
                fleet["notification"] = deliver_webhook(
                    formatted_payload,
                    args._webhook_url,
                    event_id=payload["event_id"],
                    signing_secret=args._webhook_signing_secret,
                    timeout=args.webhook_timeout,
                    retries=args.webhook_retries,
                )
                fleet["notification"].update({"format": args.webhook_format, "payload_written": payload_written})
            else:
                fleet["notification"] = {"configured": True, "status": "skipped", "format": args.webhook_format, "payload_written": payload_written, "attempts": 0, "status_code": None, "error": "Gate passed and --notify-on is failure.", "event_id": payload["event_id"]}
        report = write_fleet_report(fleet, args.output)
        if args.junit_output:
            _atomic_write_text(args.junit_output, render_fleet_junit_xml(fleet, fleet["quality_gate"]))
    except (OSError, ValueError) as exc:
        print(f"backtrace-agent: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(fleet, indent=2, ensure_ascii=False))
    else:
        summary = fleet["summary"]
        print(
            f"Session fleet: {summary['runs']} run(s) · {summary['needs_attention']} need attention "
            f"· {summary['unresolved_incidents']} unresolved · {fleet['parse_errors']} unreadable"
        )
        if fleet.get("history"):
            trend = fleet["history"]["trend"]
            if trend["has_baseline"]:
                deltas = trend["deltas"]
                print(
                    f"Fleet trend: {trend['regressed_runs']} regressed · {trend['improved_runs']} improved "
                    f"· {trend['new_runs']} new ({trend['new_runs_needing_attention']} need attention) "
                    f"· {trend['left_scan_window']} left scan window · unresolved {deltas['unresolved_incidents']:+d}"
                )
            else:
                print(f"Fleet trend: first snapshot recorded · {trend['new_runs']} run(s) · no previous baseline")
        if fleet["quality_gate"]["configured"]:
            gate_summary = fleet["quality_gate"]["summary"]
            print(
                f"Fleet gate: {'PASS' if fleet['quality_gate']['passed'] else 'FAILED'} · "
                f"{gate_summary['passed']} passed · {gate_summary['failed']} failed · {gate_summary['skipped']} skipped"
            )
        if fleet["notification"]["configured"]:
            notification = fleet["notification"]
            suffix = f" · HTTP {notification['status_code']}" if notification["status_code"] is not None else ""
            preview = " · payload written" if notification["payload_written"] else ""
            print(f"Fleet webhook: {notification['status'].upper()} · {notification['format']} · {notification['attempts']} attempt(s){suffix}{preview}")
        for item in fleet["runs"][:10]:
            print(
                f"- [{item['status'].upper()}] risk {item['risk_score']:>3} · {item['path']} "
                f"· {item['failures']} failed · {item['unresolved_incidents']} unresolved"
            )
        print(f"Fleet report: {report.resolve()}")
        if args.junit_output:
            print(f"Fleet JUnit: {args.junit_output.resolve()}")
    if args.open:
        webbrowser.open(report.resolve().as_uri())
    if fleet["notification"]["status"] == "failed":
        return 2
    return 1 if fleet["quality_gate"]["configured"] and not fleet["quality_gate"]["passed"] else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    fleet_gate_requested = args.fail_on_fleet_regression or any(getattr(args, key) is not None for key in FLEET_INTEGER_GATE_KEYS)
    if fleet_gate_requested and not args.scan:
        print("backtrace-agent: fleet gate options require --scan", file=sys.stderr)
        return 2
    if args.history and not args.scan:
        print("backtrace-agent: --history requires --scan", file=sys.stderr)
        return 2
    if (args.fail_on_fleet_regression or args.max_new_attention is not None) and not args.history:
        print("backtrace-agent: trend gate options require --history", file=sys.stderr)
        return 2
    notification_requested = bool(args.webhook_url_env or args.webhook_payload_output)
    if notification_requested and (not args.scan or not fleet_gate_requested):
        print("backtrace-agent: webhook notification options require --scan and at least one fleet gate", file=sys.stderr)
        return 2
    if args.webhook_signing_secret_env and not args.webhook_url_env:
        print("backtrace-agent: --webhook-signing-secret-env requires --webhook-url-env", file=sys.stderr)
        return 2
    if args.webhook_url_env:
        webhook_url = os.environ.get(args.webhook_url_env)
        if not webhook_url:
            print(f"backtrace-agent: environment variable {args.webhook_url_env} is missing or empty", file=sys.stderr)
            return 2
        try:
            validate_webhook_url(webhook_url)
        except ValueError as exc:
            print(f"backtrace-agent: {exc}", file=sys.stderr)
            return 2
        args._webhook_url = webhook_url
        args._webhook_signing_secret = None
        if args.webhook_signing_secret_env:
            signing_secret = os.environ.get(args.webhook_signing_secret_env)
            if not signing_secret:
                print(f"backtrace-agent: environment variable {args.webhook_signing_secret_env} is missing or empty", file=sys.stderr)
                return 2
            args._webhook_signing_secret = signing_secret
    if args.verify_source and not args.verify_bundle:
        print("backtrace-agent: --verify-source requires --verify-bundle", file=sys.stderr)
        return 2
    if args.verify_bundle:
        if args.trace or args.watch or args.scan:
            print("backtrace-agent: do not pass a trace, --watch, or --scan with --verify-bundle", file=sys.stderr)
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
    if args.scan:
        gate_values = any(getattr(args, key) is not None for key in INTEGER_POLICY_KEYS | NUMBER_POLICY_KEYS)
        conflicting = (
            args.trace or args.watch or args.compare or args.from_event or args.to_event or args.agent
            or args.incident or args.context_events is not None or args.list_incidents or args.find
            or args.audit_ingestion or args.doctor or args.restart_at or args.bundle or args.policy
            or args.normalized_output or args.summary_output or args.fail_on_errors
            or args.require_evidence or args.fail_on_regression or args.event_kind
            or args.event_status != "all" or args.incident_status != "all" or gate_values
        )
        if conflicting:
            print("backtrace-agent: --scan cannot be combined with a trace, watch, focused analysis, exports, or quality-gate options", file=sys.stderr)
            return 2
        return _scan(args)
    try:
        trace = args.trace or newest_codex_session()
    except (OSError, ValueError) as exc:
        print(f"backtrace-agent: {exc}", file=sys.stderr)
        return 2
    if args.incident_status != "all" and not args.list_incidents:
        print("backtrace-agent: --incident-status requires --list-incidents", file=sys.stderr)
        return 2
    if args.list_incidents:
        conflicting = args.watch or args.incident or args.from_event or args.to_event or args.compare or args.find or args.audit_ingestion or args.doctor or args.event_kind or args.event_status != "all"
        if conflicting:
            print("backtrace-agent: --list-incidents cannot be combined with watch, comparison, or focused-output options", file=sys.stderr)
            return 2
        return _list_incidents(args, trace)
    if (args.event_kind or args.event_status != "all") and not args.find:
        print("backtrace-agent: --event-kind and --event-status require --find", file=sys.stderr)
        return 2
    if args.find:
        conflicting = args.watch or args.incident or args.from_event or args.to_event or args.compare or args.list_incidents or args.audit_ingestion or args.doctor
        if conflicting:
            print("backtrace-agent: --find cannot be combined with watch, comparison, incident catalog, or focused-output options", file=sys.stderr)
            return 2
        return _find_events(args, trace)
    if args.audit_ingestion:
        conflicting = args.watch or args.incident or args.from_event or args.to_event or args.compare or args.list_incidents or args.find or args.doctor or args.event_kind or args.event_status != "all"
        if conflicting:
            print("backtrace-agent: --audit-ingestion cannot be combined with watch, comparison, search, incident, or focused-output options", file=sys.stderr)
            return 2
        return _audit_ingestion(args, trace)
    if args.doctor:
        conflicting = args.watch or args.incident or args.from_event or args.to_event or args.compare or args.list_incidents or args.find or args.audit_ingestion or args.event_kind or args.event_status != "all"
        if conflicting:
            print("backtrace-agent: --doctor cannot be combined with watch, comparison, search, ingestion audit, incident, or focused-output options", file=sys.stderr)
            return 2
        return _doctor(args, trace)
    return _watch(args, trace) if args.watch else _process_once(args, trace)


if __name__ == "__main__":
    raise SystemExit(main())

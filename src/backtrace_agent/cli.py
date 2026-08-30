from __future__ import annotations

import argparse
import json
import os
import sys
import webbrowser
from pathlib import Path

from .analysis import analyze_run, render_markdown_summary
from .core import build_restart_brief, detect_signals, parse_trace
from .report import write_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="backtrace-agent", description="Turn raw AI-agent logs into evidence-backed diagnostics and restart context.")
    parser.add_argument("trace", type=Path, nargs="?", help="JSON/JSONL trace. Omit to use the newest local Codex session.")
    parser.add_argument("--output", "-o", type=Path, default=Path("backtrace-report.html"), help="HTML report path")
    parser.add_argument("--json", action="store_true", help="Print privacy-safe normalized data as JSON")
    parser.add_argument("--normalized-output", type=Path, help="Write privacy-safe normalized JSON")
    parser.add_argument("--summary-output", type=Path, help="Write an evidence-backed Markdown run summary")
    parser.add_argument("--restart-at", metavar="EVENT_ID", help="Also write a restart brief at an event ID")
    parser.add_argument("--brief-output", type=Path, default=Path("restart-brief.md"), help="Restart brief path")
    parser.add_argument("--open", action="store_true", help="Open the generated report in the default browser")
    parser.add_argument("--fail-on-errors", action="store_true", help="Exit 1 when the trace contains failed actions (useful in CI)")
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
    except (OSError, ValueError) as exc:
        print(f"backtrace-agent: {exc}", file=sys.stderr)
        return 2
    signals = detect_signals(run.events)
    analysis = analyze_run(run)
    if args.json:
        print(json.dumps({"run": run.as_dict(), "analysis": analysis}, indent=2, ensure_ascii=False))
    report = write_report(run, args.output)
    print(f"Report: {report.resolve()}")
    counts = analysis["counts"]
    print(f"Source: {trace.resolve()}")
    print(f"Turns: {counts['turns']} · Meaningful events: {counts['events']} · Actions: {counts['actions']} · Failed: {counts['failures']} · Signals: {len(signals)}")
    if analysis["privacy"]["total_findings"]:
        print(f"Privacy: redacted {analysis['privacy']['total_findings']} potential secret occurrence(s) from generated outputs")
    if args.normalized_output:
        args.normalized_output.write_text(json.dumps({"run": run.as_dict(), "analysis": analysis}, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Normalized JSON: {args.normalized_output.resolve()}")
    if args.summary_output:
        args.summary_output.write_text(render_markdown_summary(run), encoding="utf-8")
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
    return 1 if args.fail_on_errors and counts["failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

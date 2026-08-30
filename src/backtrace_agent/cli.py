from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import build_restart_brief, detect_signals, parse_trace
from .report import write_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="backtrace-agent", description="Turn raw AI-agent logs into a timeline, diagnostics, and restart brief.")
    parser.add_argument("trace", type=Path, help="Path to a JSON or JSONL trace")
    parser.add_argument("--output", "-o", type=Path, default=Path("backtrace-report.html"), help="HTML report path")
    parser.add_argument("--json", action="store_true", help="Print the normalized run and signals as JSON")
    parser.add_argument("--restart-at", metavar="EVENT_ID", help="Also write a restart brief at an event ID")
    parser.add_argument("--brief-output", type=Path, default=Path("restart-brief.md"), help="Restart brief path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        run = parse_trace(args.trace)
    except (OSError, ValueError) as exc:
        print(f"backtrace-agent: {exc}", file=sys.stderr)
        return 2
    signals = detect_signals(run.events)
    if args.json:
        print(json.dumps({"run": run.as_dict(), "signals": [signal.as_dict() for signal in signals]}, indent=2, ensure_ascii=False))
    report = write_report(run, args.output)
    print(f"Report: {report.resolve()}")
    print(f"Events: {len(run.events)} · Agents: {len(run.agents)} · Signals: {len(signals)}")
    if args.restart_at:
        try:
            brief = build_restart_brief(run, args.restart_at)
        except ValueError as exc:
            print(f"backtrace-agent: {exc}", file=sys.stderr)
            return 2
        args.brief_output.write_text(brief, encoding="utf-8")
        print(f"Restart brief: {args.brief_output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

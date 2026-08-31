"""Agent Backtrace: local trace parsing, diagnostics, and restart briefs."""

from .analysis import analyze_run, catalog_incidents, compare_runs, evaluate_policy, focus_incident, render_markdown_summary, search_events
from .bundle import verify_evidence_bundle, write_evidence_bundle
from .ci import render_junit_xml
from .core import Event, Run, Signal, Turn, build_restart_brief, detect_signals, parse_trace, slice_run, suppress_content

__all__ = ["Event", "Run", "Signal", "Turn", "analyze_run", "catalog_incidents", "compare_runs", "evaluate_policy", "focus_incident", "render_markdown_summary", "search_events", "render_junit_xml", "write_evidence_bundle", "verify_evidence_bundle", "build_restart_brief", "detect_signals", "parse_trace", "slice_run", "suppress_content"]
__version__ = "0.23.0"

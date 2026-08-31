"""Agent Backtrace: local trace parsing, diagnostics, and restart briefs."""

from .analysis import analyze_run, catalog_incidents, compare_runs, evaluate_policy, focus_incident, render_markdown_summary, search_events
from .bundle import verify_evidence_bundle, write_evidence_bundle
from .ci import render_fleet_junit_xml, render_junit_xml
from .core import Event, Run, Signal, Turn, build_restart_brief, detect_signals, inspect_source_health, parse_trace, slice_run, suppress_content
from .fleet import build_history_snapshot, compare_history_snapshots, discover_traces, evaluate_fleet_gate, render_fleet_html, scan_traces, update_fleet_history, write_fleet_report

__all__ = ["Event", "Run", "Signal", "Turn", "analyze_run", "catalog_incidents", "compare_runs", "evaluate_policy", "focus_incident", "render_markdown_summary", "search_events", "render_fleet_junit_xml", "render_junit_xml", "write_evidence_bundle", "verify_evidence_bundle", "build_restart_brief", "detect_signals", "inspect_source_health", "parse_trace", "slice_run", "suppress_content", "build_history_snapshot", "compare_history_snapshots", "discover_traces", "evaluate_fleet_gate", "render_fleet_html", "scan_traces", "update_fleet_history", "write_fleet_report"]
__version__ = "0.28.0"

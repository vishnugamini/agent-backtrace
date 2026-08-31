"""Agent Backtrace: local trace parsing, diagnostics, and restart briefs."""

from .analysis import analyze_run, compare_runs, evaluate_policy, render_markdown_summary
from .bundle import verify_evidence_bundle, write_evidence_bundle
from .ci import render_junit_xml
from .core import Event, Run, Signal, Turn, build_restart_brief, detect_signals, parse_trace, slice_run, suppress_content

__all__ = ["Event", "Run", "Signal", "Turn", "analyze_run", "compare_runs", "evaluate_policy", "render_markdown_summary", "render_junit_xml", "write_evidence_bundle", "verify_evidence_bundle", "build_restart_brief", "detect_signals", "parse_trace", "slice_run", "suppress_content"]
__version__ = "0.18.0"

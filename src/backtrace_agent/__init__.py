"""Agent Backtrace: local trace parsing, diagnostics, and restart briefs."""

from .analysis import analyze_run, compare_runs, evaluate_policy, render_markdown_summary
from .bundle import write_evidence_bundle
from .core import Event, Run, Signal, Turn, build_restart_brief, detect_signals, parse_trace, suppress_content

__all__ = ["Event", "Run", "Signal", "Turn", "analyze_run", "compare_runs", "evaluate_policy", "render_markdown_summary", "write_evidence_bundle", "build_restart_brief", "detect_signals", "parse_trace", "suppress_content"]
__version__ = "0.12.0"

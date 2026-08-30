"""Agent Backtrace: local trace parsing, diagnostics, and restart briefs."""

from .analysis import analyze_run, compare_runs, render_markdown_summary
from .core import Event, Run, Signal, Turn, build_restart_brief, detect_signals, parse_trace

__all__ = ["Event", "Run", "Signal", "Turn", "analyze_run", "compare_runs", "render_markdown_summary", "build_restart_brief", "detect_signals", "parse_trace"]
__version__ = "0.3.0"

"""Agent Backtrace: local trace parsing, diagnostics, and restart briefs."""

from .core import Event, Run, Signal, build_restart_brief, detect_signals, parse_trace

__all__ = ["Event", "Run", "Signal", "build_restart_brief", "detect_signals", "parse_trace"]
__version__ = "0.1.0"

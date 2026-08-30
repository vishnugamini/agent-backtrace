from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from typing import Any

from .core import Event, Run, detect_signals


@dataclass(slots=True)
class TurnSummary:
    id: str
    request: str
    duration_ms: int
    actions: int
    files_changed: int
    failures: int
    final_response: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _short(value: str, length: int = 180) -> str:
    value = " ".join(value.split())
    return value if len(value) <= length else value[:length] + "…"


def analyze_run(run: Run) -> dict[str, Any]:
    """Compute factual, explainable run-level diagnostics."""
    signals = detect_signals(run.events)
    tool_events = [event for event in run.events if event.kind in {"tool", "error"} and event.operation]
    file_events = [event for event in run.events if event.kind == "file"]
    failures = [event for event in run.events if event.status == "error"]
    successful = [event for event in tool_events if event.status == "ok"]
    changed_files: dict[str, dict[str, int]] = defaultdict(lambda: {"changes": 0, "additions": 0, "deletions": 0})
    referenced_files: Counter[str] = Counter()
    for event in file_events:
        for path in event.files:
            changed_files[path]["changes"] += 1
            # Codex reports aggregate diff counts on a multi-file change. Do not
            # pretend those totals belong to every file.
            if len(event.files) == 1:
                changed_files[path]["additions"] += int(event.metadata.get("additions", 0))
                changed_files[path]["deletions"] += int(event.metadata.get("deletions", 0))
    for event in run.events:
        if event.kind != "file":
            referenced_files.update(event.files)

    turn_summaries: list[TurnSummary] = []
    for turn in run.turns:
        events = [event for event in run.events if event.turn_id == turn.id]
        turn_summaries.append(TurnSummary(
            turn.id, _short(turn.user_request, 260), turn.duration_ms,
            sum(event.kind in {"tool", "file", "handoff", "error"} for event in events),
            len(set(path for event in events if event.kind == "file" for path in event.files)),
            sum(event.status == "error" for event in events), _short(turn.final_response, 320),
        ))

    milestones = [
        {"event_id": event.id, "at_ms": event.at_ms, "title": event.title, "detail": _short(event.detail, 260)}
        for event in run.events if event.kind == "message" and event.agent == "codex"
    ]
    slowest = sorted((event for event in tool_events if event.duration_ms), key=lambda event: event.duration_ms, reverse=True)[:8]
    operation_counts = Counter(event.operation for event in tool_events if event.operation)
    repeated_operations = [
        {"operation": operation, "count": count}
        for operation, count in operation_counts.most_common() if count > 1
    ]
    evidence = []
    for event in successful:
        operation = event.operation or ""
        deployment_succeeded = "deployment" in operation and "succeed" in (event.output + event.detail).lower()
        if operation in {"test", "build", "lint", "git.push", "site.package"} or deployment_succeeded:
            evidence.append({"event_id": event.id, "title": event.title, "at_ms": event.at_ms})

    total_tokens = run.tokens.get("total_tokens", 0)
    cached = run.tokens.get("cached_input_tokens", 0)
    cache_ratio = round(cached / total_tokens * 100, 1) if total_tokens else None
    active_ms = sum(event.duration_ms for event in tool_events)
    return {
        "counts": {
            "events": len(run.events), "turns": len(run.turns), "actions": len(tool_events) + len(file_events),
            "tools": len(tool_events), "successful_tools": len(successful), "failures": len(failures),
            "file_changes": len(file_events), "files_changed": len(changed_files),
            "files_referenced": len(referenced_files), "subagent_events": sum(event.kind == "handoff" for event in run.events),
            "signals": len(signals),
        },
        "event_kinds": dict(Counter(event.kind for event in run.events)),
        "operations": [{"operation": operation, "count": count} for operation, count in operation_counts.most_common()],
        "repeated_operations": repeated_operations,
        "files": [{"path": path, **stats} for path, stats in sorted(changed_files.items(), key=lambda item: (-item[1]["changes"], item[0]))],
        "referenced_files": [{"path": path, "references": count} for path, count in referenced_files.most_common()],
        "turns": [summary.as_dict() for summary in turn_summaries],
        "milestones": milestones,
        "signals": [signal.as_dict() for signal in signals],
        "slowest_actions": [{"event_id": event.id, "title": event.title, "duration_ms": event.duration_ms, "operation": event.operation} for event in slowest],
        "completion_evidence": evidence,
        "tokens": {**run.tokens, "cache_ratio_percent": cache_ratio},
        "timing": {"elapsed_ms": run.duration_ms, "measured_tool_ms": active_ms},
        "privacy": {"redactions": run.privacy_findings, "total_findings": sum(run.privacy_findings.values())},
        "goal": {"objective": run.goal, "claimed_status": run.goal_status, "evidence_count": len(evidence)},
    }


def render_markdown_summary(run: Run) -> str:
    analysis = analyze_run(run)
    counts = analysis["counts"]
    lines = [
        f"# Backtrace summary: {run.name}", "",
        f"- Source: {run.source}", f"- Session: {run.session_id or 'unknown'}", f"- Model: {run.model or 'unknown'}",
        f"- Duration: {round(run.duration_ms / 60_000, 1)} minutes", f"- Turns: {counts['turns']}",
        f"- Meaningful events: {counts['events']}", f"- Actions: {counts['actions']} ({counts['failures']} failed)",
        f"- Files changed: {counts['files_changed']}", f"- Diagnostic signals: {counts['signals']}", "",
        "## Objective", run.goal or "No persistent goal was recorded.", "", "## Turn-by-turn",
    ]
    for turn in analysis["turns"]:
        lines.extend([f"### {turn['request'] or 'Turn without recovered request'}", f"- Duration: {round(turn['duration_ms']/1000, 1)}s", f"- Actions: {turn['actions']}", f"- Files changed: {turn['files_changed']}", f"- Failures: {turn['failures']}", f"- Outcome: {turn['final_response'] or 'No final response recorded.'}", ""])
    lines.append("## Diagnostic signals")
    lines.extend([f"- **{signal['title']}** ({signal['severity']}): {signal['detail']}" for signal in analysis["signals"]] or ["- None detected."])
    lines.extend(["", "## Files changed"])
    lines.extend([f"- `{item['path']}` — {item['changes']} change event(s), +{item['additions']} −{item['deletions']}" for item in analysis["files"]] or ["- None detected."])
    lines.extend(["", "## Completion evidence"])
    lines.extend([f"- {item['title']}" for item in analysis["completion_evidence"]] or ["- No build, test, push, or deployment evidence was detected."])
    if analysis["privacy"]["total_findings"]:
        lines.extend(["", "## Privacy", f"Backtrace redacted {analysis['privacy']['total_findings']} potential secret occurrence(s) from generated output."])
    return "\n".join(lines)

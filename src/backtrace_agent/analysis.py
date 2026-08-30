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
    slowest = sorted((event for event in tool_events if event.duration_ms and not event.metadata.get("long_running")), key=lambda event: event.duration_ms, reverse=True)[:8]
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
    active_ms = sum(event.duration_ms for event in tool_events if not event.metadata.get("long_running"))
    attention_items = []
    for signal in signals:
        if signal.kind == "failure":
            attention_items.append({"priority": "high", "title": "Investigate failed action", "detail": signal.detail, "event_id": signal.event_id})
        elif signal.kind == "repetition":
            attention_items.append({"priority": "medium", "title": "Remove repeated work", "detail": signal.detail, "event_id": signal.event_id})
        elif signal.kind == "stall":
            attention_items.append({"priority": "medium", "title": "Explain idle time", "detail": signal.detail, "event_id": signal.event_id})
        elif signal.kind == "slow":
            attention_items.append({"priority": "low", "title": "Review slow action", "detail": signal.detail, "event_id": signal.event_id})
    if not evidence:
        attention_items.append({"priority": "high", "title": "Add completion evidence", "detail": "No successful build, test, push, package, or deployment proof was detected.", "event_id": None})
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
        "attention_items": attention_items[:12],
        "tokens": {**run.tokens, "cache_ratio_percent": cache_ratio},
        "timing": {"elapsed_ms": run.duration_ms, "measured_tool_ms": active_ms},
        "privacy": {
            "redactions": run.privacy_findings,
            "secret_findings": sum(value for key, value in run.privacy_findings.items() if key != "custom_suppression"),
            "custom_suppressions": run.privacy_findings.get("custom_suppression", 0),
            "total_findings": sum(run.privacy_findings.values()),
        },
        "goal": {"objective": run.goal, "claimed_status": run.goal_status, "evidence_count": len(evidence)},
    }


def compare_runs(current: Run, baseline: Run) -> dict[str, Any]:
    """Compare two runs using normalized metrics and explain every conclusion."""
    current_analysis = analyze_run(current)
    baseline_analysis = analyze_run(baseline)
    ca, ba = current_analysis["counts"], baseline_analysis["counts"]
    current_turns, baseline_turns = max(1, ca["turns"]), max(1, ba["turns"])
    current_actions, baseline_actions = max(1, ca["actions"]), max(1, ba["actions"])

    def metric(key: str, label: str, baseline_value: float, current_value: float, preference: str, unit: str = "") -> dict[str, Any]:
        delta = current_value - baseline_value
        meaningful_delta = max(abs(baseline_value) * 0.05, 0.01)
        if abs(delta) < meaningful_delta:
            outcome = "same"
        elif preference == "lower":
            outcome = "improved" if delta < 0 else "regressed"
        elif preference == "higher":
            outcome = "improved" if delta > 0 else "regressed"
        else:
            outcome = "changed"
        percent = None if baseline_value == 0 else round(delta / baseline_value * 100, 1)
        return {
            "key": key, "label": label, "baseline": round(baseline_value, 2), "current": round(current_value, 2),
            "delta": round(delta, 2), "delta_percent": percent, "preference": preference, "outcome": outcome, "unit": unit,
        }

    current_signal_counts = Counter(item["kind"] for item in current_analysis["signals"])
    baseline_signal_counts = Counter(item["kind"] for item in baseline_analysis["signals"])
    metrics = [
        metric("tool_seconds_per_turn", "Measured tool time per turn", baseline_analysis["timing"]["measured_tool_ms"] / baseline_turns / 1000, current_analysis["timing"]["measured_tool_ms"] / current_turns / 1000, "lower", "sec"),
        metric("actions_per_turn", "Actions per turn", ba["actions"] / baseline_turns, ca["actions"] / current_turns, "neutral"),
        metric("failures_per_100_actions", "Failures per 100 actions", ba["failures"] / baseline_actions * 100, ca["failures"] / current_actions * 100, "lower"),
        metric("repetitions_per_turn", "Repeated actions per turn", baseline_signal_counts["repetition"] / baseline_turns, current_signal_counts["repetition"] / current_turns, "lower"),
        metric("stalls_per_turn", "Stalls per turn", baseline_signal_counts["stall"] / baseline_turns, current_signal_counts["stall"] / current_turns, "lower"),
        metric("slow_actions_per_100", "Slow actions per 100 actions", baseline_signal_counts["slow"] / baseline_actions * 100, current_signal_counts["slow"] / current_actions * 100, "lower"),
        metric("verification_per_turn", "Verification evidence per turn", len(baseline_analysis["completion_evidence"]) / baseline_turns, len(current_analysis["completion_evidence"]) / current_turns, "higher"),
        metric("files_changed", "Unique files changed", ba["files_changed"], ca["files_changed"], "neutral"),
    ]

    def failed_operations(run: Run) -> set[str]:
        return {event.operation or event.title for event in run.events if event.status == "error"}

    current_failed, baseline_failed = failed_operations(current), failed_operations(baseline)
    current_files = {item["path"] for item in current_analysis["files"]}
    baseline_files = {item["path"] for item in baseline_analysis["files"]}
    current_operations = {item["operation"]: item["count"] for item in current_analysis["operations"]}
    baseline_operations = {item["operation"]: item["count"] for item in baseline_analysis["operations"]}
    operation_deltas = [
        {"operation": operation, "baseline": baseline_operations.get(operation, 0), "current": current_operations.get(operation, 0), "delta": current_operations.get(operation, 0) - baseline_operations.get(operation, 0)}
        for operation in sorted(current_operations.keys() | baseline_operations.keys())
        if current_operations.get(operation, 0) != baseline_operations.get(operation, 0)
    ]
    operation_deltas.sort(key=lambda item: (-abs(item["delta"]), item["operation"]))
    new_failures, resolved_failures = sorted(current_failed - baseline_failed), sorted(baseline_failed - current_failed)
    regressions = [item for item in metrics if item["outcome"] == "regressed"]
    improvements = [item for item in metrics if item["outcome"] == "improved"]
    findings = [
        *({"kind": "regression", "title": f"New failing operation: {operation}", "detail": "This operation failed in the current run but not in the baseline."} for operation in new_failures),
        *({"kind": "improvement", "title": f"Resolved failure: {operation}", "detail": "This operation failed in the baseline and did not fail in the current run."} for operation in resolved_failures),
        *({"kind": item["outcome"], "title": item["label"], "detail": f"{item['baseline']} → {item['current']} {item['unit']} ({item['delta']:+g})."} for item in metrics if item["outcome"] in {"regressed", "improved"}),
    ]
    if new_failures or len(regressions) > len(improvements):
        verdict = "regressed"
    elif resolved_failures or len(improvements) > len(regressions):
        verdict = "improved"
    elif not regressions and not improvements and not new_failures and not resolved_failures:
        verdict = "unchanged"
    else:
        verdict = "mixed"
    return {
        "baseline": {"name": baseline.name, "session_id": baseline.session_id, "model": baseline.model},
        "current": {"name": current.name, "session_id": current.session_id, "model": current.model},
        "verdict": verdict,
        "metrics": metrics,
        "findings": findings,
        "new_failing_operations": new_failures,
        "resolved_failing_operations": resolved_failures,
        "file_scope": {"added": sorted(current_files - baseline_files), "removed": sorted(baseline_files - current_files), "shared": sorted(current_files & baseline_files)},
        "operation_deltas": operation_deltas,
        "summary": {"regressions": len(regressions) + len(new_failures), "improvements": len(improvements) + len(resolved_failures)},
    }


def render_markdown_summary(run: Run, comparison: dict[str, Any] | None = None) -> str:
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
        lines.extend(["", "## Privacy", f"Backtrace applied {analysis['privacy']['total_findings']} privacy protection(s) to generated output ({analysis['privacy']['secret_findings']} recognized secret pattern(s), {analysis['privacy']['custom_suppressions']} custom suppression(s))."])
    if comparison:
        lines.extend(["", "## Baseline comparison", f"Verdict: **{comparison['verdict']}** against `{comparison['baseline']['name']}`."])
        lines.extend([f"- **{item['title']}** ({item['kind']}): {item['detail']}" for item in comparison["findings"]] or ["- No material normalized changes detected."])
    return "\n".join(lines)

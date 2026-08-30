from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
import re
from statistics import median
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


PHASE_ORDER = ["Understand", "Inspect", "Implement", "Verify", "Publish", "Coordinate", "Communicate", "Operate"]


def classify_phase(event: Event) -> str:
    """Map an event to an explainable workflow phase using only recorded evidence."""
    operation = (event.operation or "").casefold()
    evidence = f"{operation} {event.title}".casefold()
    if event.kind == "handoff":
        return "Coordinate"
    if "deployment_status" in evidence:
        return "Verify"
    if any(term in evidence for term in ("git.push", "git.commit", "deploy", "save_site_version", "create_source_repository", "site.package", "release", "publish")):
        return "Publish"
    if any(term in evidence for term in ("test", "lint", "build", "check", "verify", "validate")):
        return "Verify"
    if event.kind == "file" or any(term in evidence for term in ("edit", "write", "patch", "file.change", "mkdir", "init-site")):
        return "Implement"
    if any(term in evidence for term in ("inspect", "read", "search", "find", "list", "shell.ls", "get_site", "git.inspect")):
        return "Inspect"
    if event.kind == "reasoning" or event.agent == "user":
        return "Understand"
    if event.kind == "message":
        return "Communicate"
    return "Operate"


def classify_side_effect(event: Event) -> dict[str, Any] | None:
    """Identify consequential actions from explicit operations or shell commands."""
    if event.kind not in {"tool", "error"}:
        return None
    operation = (event.operation or "").casefold()
    command = event.input.casefold().strip()
    if "deployment_status" in operation:
        return None
    if any(term in operation for term in ("delete", "destroy", "remove")) or re.search(r"(?:^|[;&|]\s*)(?:rm|rmdir|unlink)\s", command):
        return {"category": "destructive", "label": "Deletion or destructive mutation", "severity": "high", "reversible": False}
    if any(term in operation for term in ("permission", "access_policy", "share")) or re.search(r"(?:^|[;&|]\s*)(?:chmod|chown)\s", command):
        return {"category": "access", "label": "Access or permission change", "severity": "high", "reversible": True}
    if any(term in operation for term in ("git.push", "deploy", "publish", "save_site_version", "release")):
        return {"category": "publish", "label": "External publish or deployment", "severity": "medium", "reversible": True}
    if operation == "git.commit" or "git.commit" in operation:
        return {"category": "repository", "label": "Repository history change", "severity": "low", "reversible": True}
    if any(term in operation for term in ("send", "comment", "create_issue", "update_issue", "upload", "external_write")):
        return {"category": "external_write", "label": "External write", "severity": "medium", "reversible": True}
    if "install" in operation or re.search(r"(?:^|[;&|]\s*)(?:pip|uv|npm|pnpm|yarn|brew)\s+(?:install|add)\b", command):
        return {"category": "install", "label": "Dependency or software installation", "severity": "medium", "reversible": True}
    return None


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

    phase_events: dict[str, list[Event]] = defaultdict(list)
    for event in run.events:
        phase_events[classify_phase(event)].append(event)
    workflow_phases = []
    for name in PHASE_ORDER:
        events = phase_events.get(name, [])
        if not events:
            continue
        action_events = [event for event in events if event.kind in {"tool", "file", "handoff", "error"}]
        phase_files = sorted({path for event in events for path in event.files})
        workflow_phases.append({
            "name": name,
            "events": len(events),
            "actions": len(action_events),
            "failures": sum(event.status == "error" for event in events),
            "measured_ms": sum(event.duration_ms for event in action_events if not event.metadata.get("long_running")),
            "files": phase_files,
            "first_at_ms": min(event.at_ms for event in events),
            "last_at_ms": max(event.at_ms + event.duration_ms for event in events),
            "first_event_id": events[0].id,
        })
    classified_actions = [(classify_phase(event), event) for event in run.events if event.kind in {"tool", "file", "handoff", "error"}]
    transition_counts: Counter[tuple[str, str]] = Counter()
    for (before, _), (after, _) in zip(classified_actions, classified_actions[1:]):
        if before != after:
            transition_counts[(before, after)] += 1
    dominant_phase = max(workflow_phases, key=lambda phase: (phase["measured_ms"], phase["actions"]), default=None)

    action_events = [event for event in run.events if event.kind in {"tool", "file", "handoff", "error"}]
    open_incidents: dict[str, dict[str, Any]] = {}
    incidents: list[dict[str, Any]] = []
    for index, event in enumerate(action_events):
        if event.metadata.get("long_running"):
            continue
        operation = event.operation or event.title
        if event.status == "error":
            incident = open_incidents.get(operation)
            if incident:
                incident["failure_event_ids"].append(event.id)
                incident["latest_failure_event_id"] = event.id
                incident["failure_details"].append(_short(event.detail, 220))
            else:
                open_incidents[operation] = {
                    "id": f"incident-{event.id}", "operation": operation, "status": "unresolved",
                    "first_failure_event_id": event.id, "latest_failure_event_id": event.id,
                    "failure_event_ids": [event.id], "failure_details": [_short(event.detail, 220)],
                    "recovery_event_id": None, "recovery_title": None, "started_at_ms": event.at_ms,
                    "time_to_recovery_ms": None, "intervening_actions": None, "files": [],
                    "phase": classify_phase(event), "turn_id": event.turn_id, "_start_index": index,
                }
        elif event.status == "ok" and operation in open_incidents:
            incident = open_incidents.pop(operation)
            incident["status"] = "recovered"
            incident["recovery_event_id"] = event.id
            incident["recovery_title"] = event.title
            incident["time_to_recovery_ms"] = max(0, event.at_ms - incident["started_at_ms"])
            incident["intervening_actions"] = max(0, index - incident["_start_index"] - 1)
            incident["files"] = sorted({path for item in action_events[incident["_start_index"]:index + 1] for path in item.files})
            incidents.append(incident)
    for incident in open_incidents.values():
        incident["intervening_actions"] = max(0, len(action_events) - incident["_start_index"] - 1)
        incident["files"] = sorted({path for item in action_events[incident["_start_index"]:] for path in item.files})
        incidents.append(incident)
    for incident in incidents:
        incident["failed_attempts"] = len(incident["failure_event_ids"])
        incident.pop("_start_index", None)
    incidents.sort(key=lambda incident: (incident["status"] == "recovered", incident["started_at_ms"]))
    recovery_times = [incident["time_to_recovery_ms"] for incident in incidents if incident["time_to_recovery_ms"] is not None]

    side_effect_items = []
    for event in run.events:
        classification = classify_side_effect(event)
        if not classification:
            continue
        side_effect_items.append({
            "event_id": event.id, "at_ms": event.at_ms, "operation": event.operation or event.title,
            "title": event.title, "detail": _short(event.detail, 240), "status": event.status,
            "files": event.files, **classification,
        })
    side_effect_categories = Counter(item["category"] for item in side_effect_items)

    total_tokens = run.tokens.get("total_tokens", 0)
    input_tokens = run.tokens.get("input_tokens", 0)
    cached = run.tokens.get("cached_input_tokens", 0)
    output_tokens = run.tokens.get("output_tokens", 0)
    reasoning_tokens = run.tokens.get("reasoning_output_tokens", 0)
    cache_ratio = round(cached / total_tokens * 100, 1) if total_tokens else None
    input_cache_ratio = round(cached / input_tokens * 100, 1) if input_tokens else None
    tokens_per_action = round(total_tokens / max(1, len(tool_events) + len(file_events)), 1) if total_tokens else None
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
        "workflow": {
            "phases": workflow_phases,
            "transitions": [
                {"from": before, "to": after, "count": count}
                for (before, after), count in transition_counts.most_common()
            ],
            "dominant_phase": dominant_phase["name"] if dominant_phase else None,
            "current_phase": classified_actions[-1][0] if classified_actions else None,
            "current_event_id": classified_actions[-1][1].id if classified_actions else None,
        },
        "incidents": {
            "items": incidents,
            "total": len(incidents),
            "recovered": sum(incident["status"] == "recovered" for incident in incidents),
            "unresolved": sum(incident["status"] == "unresolved" for incident in incidents),
            "median_recovery_ms": round(median(recovery_times)) if recovery_times else None,
        },
        "side_effects": {
            "items": side_effect_items,
            "total": len(side_effect_items),
            "successful": sum(item["status"] == "ok" for item in side_effect_items),
            "failed": sum(item["status"] == "error" for item in side_effect_items),
            "destructive_attempts": side_effect_categories["destructive"],
            "categories": [{"category": category, "count": count} for category, count in side_effect_categories.most_common()],
        },
        "tokens": {
            **run.tokens,
            "uncached_input_tokens": max(0, input_tokens - cached),
            "cache_ratio_percent": cache_ratio,
            "input_cache_ratio_percent": input_cache_ratio,
            "tokens_per_action": tokens_per_action,
            "output_share_percent": round(output_tokens / total_tokens * 100, 1) if total_tokens else None,
            "reasoning_share_percent": round(reasoning_tokens / output_tokens * 100, 1) if output_tokens else None,
            "counter_scope": "recorded cumulative session usage; not a billing estimate",
        },
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
        metric("unresolved_incidents_per_100_actions", "Unresolved failure incidents per 100 actions", baseline_analysis["incidents"]["unresolved"] / baseline_actions * 100, current_analysis["incidents"]["unresolved"] / current_actions * 100, "lower"),
        metric("repetitions_per_turn", "Repeated actions per turn", baseline_signal_counts["repetition"] / baseline_turns, current_signal_counts["repetition"] / current_turns, "lower"),
        metric("stalls_per_turn", "Stalls per turn", baseline_signal_counts["stall"] / baseline_turns, current_signal_counts["stall"] / current_turns, "lower"),
        metric("slow_actions_per_100", "Slow actions per 100 actions", baseline_signal_counts["slow"] / baseline_actions * 100, current_signal_counts["slow"] / current_actions * 100, "lower"),
        metric("verification_per_turn", "Verification evidence per turn", len(baseline_analysis["completion_evidence"]) / baseline_turns, len(current_analysis["completion_evidence"]) / current_turns, "higher"),
        metric("files_changed", "Unique files changed", ba["files_changed"], ca["files_changed"], "neutral"),
    ]
    baseline_token_stats, current_token_stats = baseline_analysis["tokens"], current_analysis["tokens"]
    if baseline_token_stats.get("tokens_per_action") is not None and current_token_stats.get("tokens_per_action") is not None:
        metrics.extend([
            metric("tokens_per_action", "Recorded tokens per action", baseline_token_stats["tokens_per_action"], current_token_stats["tokens_per_action"], "lower", "tokens"),
            metric("input_cache_ratio", "Input cache ratio", baseline_token_stats.get("input_cache_ratio_percent") or 0, current_token_stats.get("input_cache_ratio_percent") or 0, "higher", "%"),
        ])

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


def evaluate_policy(run: Run, policy: dict[str, Any], comparison: dict[str, Any] | None = None) -> dict[str, Any]:
    """Evaluate explicit, machine-enforceable quality checks for a run."""
    analysis = analyze_run(run)
    counts = analysis["counts"]
    signal_counts = Counter(item["kind"] for item in analysis["signals"])
    action_count = max(1, counts["actions"])
    failure_rate = counts["failures"] / action_count * 100
    checks: list[dict[str, Any]] = []

    def add(key: str, label: str, actual: Any, expected: str, passed: bool, detail: str) -> None:
        checks.append({"key": key, "label": label, "actual": actual, "expected": expected, "passed": passed, "detail": detail})

    if policy.get("max_failures") is not None:
        limit = int(policy["max_failures"])
        add("max_failures", "Failed actions", counts["failures"], f"≤ {limit}", counts["failures"] <= limit, f"Detected {counts['failures']} failed action(s).")
    if policy.get("max_unresolved_failures") is not None:
        limit = int(policy["max_unresolved_failures"])
        actual = analysis["incidents"]["unresolved"]
        add("max_unresolved_failures", "Unresolved failure incidents", actual, f"≤ {limit}", actual <= limit, f"Detected {actual} operation-level failure incident(s) without later successful recovery evidence.")
    if policy.get("max_destructive_actions") is not None:
        limit = int(policy["max_destructive_actions"])
        actual = analysis["side_effects"]["destructive_attempts"]
        add("max_destructive_actions", "Destructive action attempts", actual, f"≤ {limit}", actual <= limit, f"Detected {actual} explicit deletion or destructive-mutation attempt(s), including failed attempts.")
    if policy.get("max_repetitions") is not None:
        limit = int(policy["max_repetitions"])
        actual = signal_counts["repetition"]
        add("max_repetitions", "Repeated actions", actual, f"≤ {limit}", actual <= limit, f"Detected {actual} repeated-action signal(s).")
    if policy.get("max_stalls") is not None:
        limit = int(policy["max_stalls"])
        actual = signal_counts["stall"]
        add("max_stalls", "Unexplained stalls", actual, f"≤ {limit}", actual <= limit, f"Detected {actual} within-turn stall signal(s).")
    if policy.get("max_failure_rate") is not None:
        limit = float(policy["max_failure_rate"])
        add("max_failure_rate", "Failure rate", round(failure_rate, 2), f"≤ {limit:g}%", failure_rate <= limit, f"{counts['failures']} failures across {counts['actions']} actions.")
    if policy.get("require_evidence"):
        actual = len(analysis["completion_evidence"])
        add("require_evidence", "Completion evidence", actual, "≥ 1", actual >= 1, f"Detected {actual} successful verification, package, push, or deployment evidence item(s).")
    if policy.get("fail_on_regression"):
        verdict = comparison["verdict"] if comparison else "unavailable"
        passed = comparison is not None and verdict != "regressed"
        detail = "No comparison baseline was supplied." if comparison is None else f"Comparison verdict: {verdict}."
        add("fail_on_regression", "Baseline regression", verdict, "not regressed", passed, detail)
    token_stats = analysis["tokens"]
    if policy.get("max_total_tokens") is not None:
        limit = int(policy["max_total_tokens"])
        recorded_total = token_stats.get("total_tokens")
        actual = int(recorded_total) if recorded_total is not None else None
        add("max_total_tokens", "Recorded cumulative tokens", actual if actual is not None else "unavailable", f"≤ {limit}", actual is not None and actual <= limit, "Uses the trace's cumulative session counter; this is not a billing estimate.")
    if policy.get("max_tokens_per_action") is not None:
        limit = float(policy["max_tokens_per_action"])
        actual = token_stats.get("tokens_per_action")
        passed = actual is not None and actual <= limit
        add("max_tokens_per_action", "Recorded tokens per action", actual if actual is not None else "unavailable", f"≤ {limit:g}", passed, "Normalized cumulative tokens by meaningful tool and file actions.")
    if policy.get("min_cache_ratio") is not None:
        limit = float(policy["min_cache_ratio"])
        actual = token_stats.get("input_cache_ratio_percent")
        passed = actual is not None and actual >= limit
        add("min_cache_ratio", "Input cache ratio", actual if actual is not None else "unavailable", f"≥ {limit:g}%", passed, "Cached input tokens divided by recorded input tokens.")
    return {
        "configured": bool(checks),
        "passed": all(check["passed"] for check in checks),
        "checks": checks,
        "summary": {"passed": sum(check["passed"] for check in checks), "failed": sum(not check["passed"] for check in checks)},
    }


def render_markdown_summary(run: Run, comparison: dict[str, Any] | None = None, quality_gate: dict[str, Any] | None = None) -> str:
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
    workflow = analysis["workflow"]
    lines.extend(["## Reconstructed workflow", f"Largest measured phase: **{workflow['dominant_phase'] or 'unavailable'}**. Latest action phase: **{workflow['current_phase'] or 'unavailable'}**."])
    lines.extend([
        f"- **{phase['name']}** — {phase['actions']} actions, {round(phase['measured_ms']/1000, 1)}s measured, {phase['failures']} failed, {len(phase['files'])} files"
        for phase in workflow["phases"]
    ] or ["- No phase evidence recovered."])
    token_stats = analysis["tokens"]
    if token_stats.get("total_tokens"):
        lines.extend([
            "", "## Token economics",
            f"Recorded cumulative tokens: **{token_stats['total_tokens']:,}**; {token_stats['tokens_per_action']:,} per meaningful action; {token_stats['input_cache_ratio_percent']}% input-cache ratio.",
            "These are trace counters, not billing or price estimates.",
        ])
    incidents = analysis["incidents"]
    lines.extend(["", "## Failure incidents", f"Recovered: **{incidents['recovered']}**. Unresolved: **{incidents['unresolved']}**."])
    lines.extend([
        f"- **{incident['operation']}** — {incident['status']}; {incident['failed_attempts']} failed attempt(s); "
        + (f"recovered after {round(incident['time_to_recovery_ms']/1000, 1)}s" if incident["status"] == "recovered" else "no later successful operation recorded")
        for incident in incidents["items"]
    ] or ["- No failure incidents detected."])
    side_effects = analysis["side_effects"]
    lines.extend(["", "## Side-effect ledger", f"Consequential actions: **{side_effects['total']}** ({side_effects['successful']} successful, {side_effects['failed']} failed); destructive attempts: **{side_effects['destructive_attempts']}**."])
    lines.extend([
        f"- **{item['label']}** — `{item['operation']}` ({item['status']}): {item['detail']}"
        for item in side_effects["items"]
    ] or ["- No explicit side effects detected."])
    lines.extend(["", "## Diagnostic signals"])
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
    if quality_gate and quality_gate["configured"]:
        lines.extend(["", "## Quality gate", f"Result: **{'PASS' if quality_gate['passed'] else 'FAIL'}**."])
        lines.extend([f"- {'PASS' if check['passed'] else 'FAIL'} — **{check['label']}**: actual `{check['actual']}`, expected `{check['expected']}`. {check['detail']}" for check in quality_gate["checks"]])
    return "\n".join(lines)

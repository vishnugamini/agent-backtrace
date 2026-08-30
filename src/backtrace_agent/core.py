from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


FILE_RE = re.compile(r"(?:^|[\s\"'`(])((?:\.?\.?/|/)?(?:[\w@.-]+/)+[\w@.+-]+\.[A-Za-z0-9]{1,8})(?=$|[\s\"'`),:])")
SECRET_PATTERNS = (
    (re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"(?:api[_-]?key|token|secret|password)(\s*[=:]\s*)[\"']?(?!\[REDACTED)[^\s,\"']{8,}", re.I), r"\1[REDACTED]"),
)


@dataclass(slots=True)
class Event:
    id: str
    at_ms: int
    agent: str
    kind: str
    title: str
    detail: str
    files: list[str] = field(default_factory=list)
    status: str = "ok"
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Run:
    name: str
    source: str
    events: list[Event]

    @property
    def duration_ms(self) -> int:
        return max((event.at_ms for event in self.events), default=0)

    @property
    def agents(self) -> list[str]:
        return list(dict.fromkeys(event.agent for event in self.events))

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "source": self.source, "duration_ms": self.duration_ms, "agents": self.agents, "events": [e.as_dict() for e in self.events]}


@dataclass(slots=True)
class Signal:
    kind: str
    title: str
    detail: str
    event_id: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(filter(None, (_stringify(item) for item in value)))
    if isinstance(value, dict):
        for key in ("text", "output_text", "content"):
            if key in value:
                return _stringify(value[key])
        return json.dumps(value, ensure_ascii=False, indent=2, default=str)
    return str(value)


def _compact(value: str, length: int = 500) -> str:
    cleaned = re.sub(r"\s+", " ", value).strip()
    return cleaned if len(cleaned) <= length else cleaned[:length] + "…"


def _parse_time(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value * 1000 if value < 10_000_000_000 else value)
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp() * 1000
    except ValueError:
        return None


def _read_records(raw: str) -> list[dict[str, Any]]:
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            values = parsed
        elif isinstance(parsed, dict) and isinstance(parsed.get("events"), list):
            values = parsed["events"]
        else:
            values = [parsed]
    except json.JSONDecodeError:
        values = []
        for line_number, line in enumerate(raw.splitlines(), 1):
            if not line.strip():
                continue
            try:
                values.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return [value for value in values if isinstance(value, dict)]


def _classify(event_type: str, payload: dict[str, Any], detail: str) -> str:
    sample = f"{event_type} {payload.get('name', '')} {detail[:140]}".lower()
    if re.search(r"error|failed|failure|exception", sample):
        return "error"
    if re.search(r"handoff|delegate|subagent|spawn_agent", sample):
        return "handoff"
    if re.search(r"patch|edit|write_file|create_file|file_change", sample):
        return "file"
    if re.search(r"function_call_output|tool_result|command_output|result", sample):
        return "result"
    if re.search(r"tool|function_call|command|exec|search|browser|mcp", sample):
        return "tool"
    if re.search(r"reason|thinking|analysis", sample):
        return "reasoning"
    return "message"


def _title(event_type: str, payload: dict[str, Any], kind: str, detail: str) -> str:
    name = str(payload.get("name") or payload.get("tool_name") or payload.get("function") or "").removeprefix("mcp__")
    if kind == "error":
        return f"{name} failed" if name else "Error encountered"
    if kind == "handoff":
        return f"Delegated to {name}" if name else "Agent handoff"
    if kind == "file":
        return f"Changed via {name}" if name else "File changed"
    if kind == "tool":
        return f"Called {name}" if name else "Tool call"
    if kind == "result":
        return f"{name} returned" if name else "Tool result"
    if kind == "reasoning":
        return "Reasoned about next step"
    preview = _compact(detail, 62)
    return preview or f"{str(payload.get('role', 'agent')).title()} message"


def parse_trace(source: str | Path, *, name: str | None = None) -> Run:
    """Parse a JSON/JSONL path or raw string into a normalized Run.

    The parser intentionally accepts loose event shapes used by coding agents and
    OpenAI-style traces. Unknown fields remain available on ``Event.raw``.
    """
    path = Path(source) if isinstance(source, Path) or (isinstance(source, str) and "\n" not in source and Path(source).exists()) else None
    raw = path.read_text(encoding="utf-8", errors="replace") if path else str(source)
    records = _read_records(raw)
    if not records:
        raise ValueError("No readable JSON or JSONL event objects were found.")

    timestamps = [_parse_time(record.get("timestamp") or record.get("created_at") or record.get("time") or record.get("ts")) for record in records]
    first = next((timestamp for timestamp in timestamps if timestamp is not None), 0.0)
    events: list[Event] = []
    for index, record in enumerate(records):
        payload = record.get("payload") if isinstance(record.get("payload"), dict) else record
        event_type = str(payload.get("type") or record.get("type") or "message")
        content = next((payload.get(key) for key in ("arguments", "output", "content", "message", "text", "data") if payload.get(key) is not None), payload)
        full_detail = _stringify(content)
        detail = _compact(full_detail) or "No payload was recorded for this event."
        kind = _classify(event_type, payload, detail)
        agent = str(payload.get("agent_name") or payload.get("agent") or record.get("agent") or payload.get("role") or "primary")
        if agent.lower() in {"assistant", "model"}:
            agent = "primary"
        timestamp = timestamps[index]
        at_ms = max(0, round(timestamp - first)) if timestamp is not None and first else index * 14_000
        files = list(dict.fromkeys(FILE_RE.findall(full_detail)))[:12]
        status = "error" if kind == "error" else "warning" if re.search(r"warn|retry|timeout", detail, re.I) else "ok"
        events.append(Event(f"evt-{index + 1:04d}", at_ms, agent, kind, _title(event_type, payload, kind, detail), detail, files, status, record))

    return Run(name or (path.stem if path else "imported-trace"), "local", events)


def detect_signals(events: Iterable[Event], *, loop_threshold: int = 3, stall_ms: int = 180_000) -> list[Signal]:
    ordered = list(events)
    signals: list[Signal] = []
    recent: dict[str, list[Event]] = {}
    for event in ordered:
        if event.kind == "error":
            signals.append(Signal("failure", "Failed step", event.title, event.id))
        key = f"{event.agent}:{re.sub(r'\d+', '#', event.title.lower())}"
        group = [*recent.get(key, []), event]
        group = [candidate for candidate in group if event.at_ms - candidate.at_ms < stall_ms]
        recent[key] = group
        if len(group) == loop_threshold:
            signals.append(Signal("loop", "Possible tool loop", f"{event.agent} repeated “{event.title}” {loop_threshold} times", event.id))
    for previous, current in zip(ordered, ordered[1:]):
        gap = current.at_ms - previous.at_ms
        if gap > stall_ms:
            signals.append(Signal("stall", "Long idle gap", f"{round(gap / 60_000)} minutes without an event", current.id))
    return signals


def redact_secrets(value: str) -> str:
    for pattern, replacement in SECRET_PATTERNS:
        value = pattern.sub(replacement, value)
    return value


def build_restart_brief(run: Run, checkpoint: int | str = -1) -> str:
    if not run.events:
        raise ValueError("Cannot build a restart brief for an empty run.")
    if isinstance(checkpoint, str):
        index = next((i for i, event in enumerate(run.events) if event.id == checkpoint), None)
        if index is None:
            raise ValueError(f"Unknown checkpoint: {checkpoint}")
    else:
        index = checkpoint if checkpoint >= 0 else len(run.events) + checkpoint
    index = max(0, min(index, len(run.events) - 1))
    history = run.events[: index + 1]
    user_goal = next((event for event in history if event.kind == "message" and "user" in event.agent.lower()), None)
    if user_goal is None:
        user_goal = next((event for event in history if event.kind == "message"), None)
    completed = [event for event in history if event.kind in {"tool", "file", "result", "handoff"}][-6:]
    files = list(dict.fromkeys(file for event in history for file in event.files))[-10:]
    selected = history[-1]
    sections = [
        f"# Restart brief: {run.name}", "", "## Original objective", user_goal.detail if user_goal else "Continue the agent run represented by this trace.", "",
        "## Progress before this checkpoint",
        *([f"- [{event.agent}] {event.title}: {event.detail}" for event in completed] or ["- No completed tool steps were recorded."]), "",
        "## Files observed", *([f"- {file}" for file in files] or ["- No file paths were detected."]), "",
        "## Resume from here", f"Checkpoint: {selected.id} — {selected.title}", f"Last recorded state: {selected.detail}",
        "Inspect the current workspace state, verify prior work before changing it, then continue with the next incomplete step.",
    ]
    return redact_secrets("\n".join(sections))

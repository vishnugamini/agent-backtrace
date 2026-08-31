from __future__ import annotations

import hashlib
import json
import re
import shlex
from collections import Counter
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


FILE_RE = re.compile(r"(?:^|[\s\"'`(])((?:\.?\.?/|/)?(?:[\w@.-]+/)+[\w@.+-]+\.[A-Za-z0-9]{1,10})(?=$|[\s\"'`),:])")
SUPPORTED_CODEX_ITEM_TYPES = {
    "UserMessage", "AgentMessage", "Reasoning", "CommandExecution", "FileChange",
    "Extension", "McpToolCall", "DynamicToolCall", "SubAgentActivity", "ContextCompaction",
}
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("openai_api_key", re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"), "[REDACTED_OPENAI_KEY]"),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    ("site_credential", re.compile(r"\bart_v\d+_[A-Za-z0-9_-]{16,}\b"), "[REDACTED_SITE_CREDENTIAL]"),
    ("sites_access_token", re.compile(r"\bla_[A-Za-z0-9_-]{24,}\b"), "[REDACTED_SITES_ACCESS_TOKEN]"),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "[REDACTED_AWS_KEY]"),
    ("bearer_token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}"), "Bearer [REDACTED]"),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    ("named_secret", re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|password|secret)(\s*[=:]\s*)[\"']?(?!\[REDACTED)[^\s,;\"']{8,}"), r"\1\2[REDACTED]"),
)


@dataclass(slots=True)
class Event:
    id: str
    at_ms: int
    agent: str
    kind: str
    title: str
    detail: str
    status: str = "ok"
    duration_ms: int = 0
    turn_id: str | None = None
    operation: str | None = None
    input: str = ""
    output: str = ""
    files: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def fingerprint(self) -> str:
        basis = f"{self.agent}\0{self.operation or self.title}\0{self.input}".lower()
        return hashlib.sha1(basis.encode("utf-8", errors="replace")).hexdigest()[:12]

    def as_dict(self) -> dict[str, Any]:
        # Raw provider payloads are intentionally excluded: they can contain
        # credentials, system prompts, and private source code.
        return {key: value for key, value in asdict(self).items() if key != "raw"}


@dataclass(slots=True)
class Turn:
    id: str
    started_at_ms: int
    completed_at_ms: int | None = None
    user_request: str = ""
    final_response: str = ""
    status: str = "running"

    @property
    def duration_ms(self) -> int:
        return max(0, (self.completed_at_ms or self.started_at_ms) - self.started_at_ms)

    def as_dict(self) -> dict[str, Any]:
        return {**asdict(self), "duration_ms": self.duration_ms}


@dataclass(slots=True)
class Run:
    name: str
    source: str
    events: list[Event]
    session_id: str | None = None
    goal: str = ""
    goal_status: str | None = None
    model: str | None = None
    cwd: str | None = None
    originator: str | None = None
    cli_version: str | None = None
    started_at: str | None = None
    turns: list[Turn] = field(default_factory=list)
    tokens: dict[str, int] = field(default_factory=dict)
    privacy_findings: dict[str, int] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_ms(self) -> int:
        return max((event.at_ms + event.duration_ms for event in self.events), default=0)

    @property
    def agents(self) -> list[str]:
        return list(dict.fromkeys(event.agent for event in self.events))

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "source": self.source, "session_id": self.session_id,
            "goal": self.goal, "goal_status": self.goal_status, "model": self.model,
            "cwd": self.cwd, "originator": self.originator, "cli_version": self.cli_version,
            "started_at": self.started_at, "duration_ms": self.duration_ms,
            "agents": self.agents, "tokens": self.tokens, "privacy_findings": self.privacy_findings,
            "metadata": self.metadata, "turns": [turn.as_dict() for turn in self.turns],
            "events": [event.as_dict() for event in self.events],
        }


@dataclass(slots=True)
class Signal:
    kind: str
    severity: str
    title: str
    detail: str
    event_id: str
    related_event_ids: list[str] = field(default_factory=list)
    evidence: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(filter(None, (_stringify(item) for item in value)))
    if isinstance(value, dict):
        for key in ("text", "output_text", "content", "message"):
            if key in value and value[key] is not value:
                result = _stringify(value[key])
                if result:
                    return result
        return json.dumps(value, ensure_ascii=False, indent=2, default=str)
    return str(value)


def _compact(value: str, length: int = 700) -> str:
    cleaned = re.sub(r"\s+", " ", value).strip()
    return cleaned if len(cleaned) <= length else cleaned[:length] + "…"


def _limit(value: str, length: int = 6000) -> str:
    return value if len(value) <= length else value[:length] + f"\n… [{len(value) - length:,} characters omitted]"


def scan_secrets(value: str) -> dict[str, int]:
    return {name: len(pattern.findall(value)) for name, pattern, _ in SECRET_PATTERNS if pattern.search(value)}


def redact_secrets(value: str) -> str:
    for _, pattern, replacement in SECRET_PATTERNS:
        value = pattern.sub(replacement, value)
    return value


def suppress_content(run: Run, terms: Iterable[str]) -> Run:
    """Return a copy with matching lines and paths removed from every exportable field.

    This is for ordinary sensitive content that pattern-based credential
    redaction cannot infer, such as client names, internal codenames, or a
    historical comment. The source Run and trace are never modified.
    """
    normalized = list(dict.fromkeys(term.strip() for term in terms if term.strip()))
    if not normalized:
        return deepcopy(run)
    result = deepcopy(run)
    removed = 0
    patterns = [re.compile(rf"(?<!\w){re.escape(term)}(?!\w)", re.I) for term in normalized]

    def matches(value: str) -> bool:
        return any(pattern.search(value) for pattern in patterns)

    def clean_text(value: str) -> str:
        nonlocal removed
        kept = []
        for line in value.splitlines():
            if matches(line):
                removed += 1
            else:
                kept.append(line)
        return "\n".join(kept).strip()

    def clean_value(value: Any) -> Any:
        nonlocal removed
        if isinstance(value, str):
            return clean_text(value)
        if isinstance(value, list):
            cleaned_list = []
            for item in value:
                if isinstance(item, str) and matches(item):
                    removed += 1
                else:
                    cleaned_list.append(clean_value(item))
            return cleaned_list
        if isinstance(value, dict):
            cleaned = {}
            for key, item in value.items():
                if matches(str(key)):
                    removed += 1
                    continue
                cleaned[key] = clean_value(item)
            return cleaned
        return value

    result.name = clean_text(result.name) or "suppressed-run"
    result.source = clean_text(result.source) or "Suppressed source"
    result.goal = clean_text(result.goal)
    result.cwd = clean_text(result.cwd or "") or None
    for turn in result.turns:
        turn.user_request = clean_text(turn.user_request)
        turn.final_response = clean_text(turn.final_response)
    for event in result.events:
        event.title = clean_text(event.title) or "Suppressed event"
        event.detail = clean_text(event.detail)
        event.input = clean_text(event.input)
        event.output = clean_text(event.output)
        event.operation = clean_text(event.operation or "") or None
        event.agent = clean_text(event.agent) or "suppressed"
        kept_files = []
        for path in event.files:
            if matches(path):
                removed += 1
            else:
                kept_files.append(path)
        event.files = kept_files
        event.metadata = clean_value(event.metadata)
        event.raw = {}
    result.metadata = clean_value(result.metadata)
    result.metadata["custom_suppression"] = {"term_count": len(normalized), "removed_items": removed}
    result.privacy_findings["custom_suppression"] = removed
    return result


def slice_run(
    run: Run,
    *,
    from_event: str | None = None,
    to_event: str | None = None,
    agents: Iterable[str] = (),
) -> Run:
    """Return an explicit, time-rebased subset without inventing full-run metrics."""
    if not run.events:
        raise ValueError("Cannot focus a run with no events.")

    event_indexes = {event.id: index for index, event in enumerate(run.events)}
    if from_event and from_event not in event_indexes:
        raise ValueError(f"Unknown --from-event ID: {from_event}")
    if to_event and to_event not in event_indexes:
        raise ValueError(f"Unknown --to-event ID: {to_event}")
    start_index = event_indexes[from_event] if from_event else 0
    end_index = event_indexes[to_event] if to_event else len(run.events) - 1
    if start_index > end_index:
        raise ValueError("--from-event occurs after --to-event in the normalized timeline.")

    requested_agents = list(dict.fromkeys(agent.strip() for agent in agents if agent.strip()))
    available_agents = {agent.casefold(): agent for agent in run.agents}
    unknown_agents = [agent for agent in requested_agents if agent.casefold() not in available_agents]
    if unknown_agents:
        raise ValueError(
            f"Unknown --agent value(s): {', '.join(unknown_agents)}. "
            f"Available agents: {', '.join(run.agents)}"
        )
    selected_agent_names = [available_agents[agent.casefold()] for agent in requested_agents]
    selected_agent_keys = {agent.casefold() for agent in selected_agent_names}

    range_events = run.events[start_index:end_index + 1]
    selected_source_events = [
        event for event in range_events
        if not selected_agent_keys or event.agent.casefold() in selected_agent_keys
    ]
    if not selected_source_events:
        raise ValueError("The requested event range and agent filters select no events.")

    result = deepcopy(run)
    result.events = deepcopy(selected_source_events)
    selected_raw = json.dumps([event.raw for event in selected_source_events], ensure_ascii=False, default=str)
    result.privacy_findings = scan_secrets(selected_raw)
    offset_ms = result.events[0].at_ms
    for event in result.events:
        event.at_ms = max(0, event.at_ms - offset_ms)

    source_turn_counts: dict[str, int] = {}
    selected_turn_counts: dict[str, int] = {}
    selected_turn_ids = {event.turn_id for event in result.events if event.turn_id}
    for event in run.events:
        if event.turn_id:
            source_turn_counts[event.turn_id] = source_turn_counts.get(event.turn_id, 0) + 1
    for event in result.events:
        if event.turn_id:
            selected_turn_counts[event.turn_id] = selected_turn_counts.get(event.turn_id, 0) + 1
    result.turns = [deepcopy(turn) for turn in run.turns if turn.id in selected_turn_ids]
    for turn in result.turns:
        turn_events = [event for event in result.events if event.turn_id == turn.id]
        turn.started_at_ms = min(event.at_ms for event in turn_events)
        turn.completed_at_ms = max(event.at_ms + event.duration_ms for event in turn_events)
        if selected_turn_counts.get(turn.id, 0) < source_turn_counts.get(turn.id, 0):
            turn.status = "partial"
            if not any(event.kind == "message" and event.metadata.get("phase") == "final" for event in turn_events):
                turn.final_response = ""

    had_token_counters = bool(result.tokens)
    result.tokens = {}
    result.metadata["scope"] = {
        "active": True,
        "from_event": range_events[0].id,
        "to_event": range_events[-1].id,
        "agents": selected_agent_names,
        "source_event_count": len(run.events),
        "selected_event_count": len(result.events),
        "selected_first_event": selected_source_events[0].id,
        "selected_last_event": selected_source_events[-1].id,
        "original_start_ms": selected_source_events[0].at_ms,
        "original_end_ms": max(event.at_ms + event.duration_ms for event in selected_source_events),
        "timeline_rebased": True,
        "cumulative_token_counters_removed": had_token_counters,
    }
    return result


def _safe(value: Any, length: int = 6000) -> str:
    return _limit(redact_secrets(_stringify(value)), length)


def _extract_files(value: Any) -> list[str]:
    return list(dict.fromkeys(FILE_RE.findall(_stringify(value))))[:40]


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
        values = parsed if isinstance(parsed, list) else parsed.get("events", [parsed]) if isinstance(parsed, dict) else []
    except json.JSONDecodeError:
        values = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            try:
                values.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return [value for value in values if isinstance(value, dict)]


def _content_text(content: Any) -> str:
    if isinstance(content, list):
        return "\n".join(filter(None, (_content_text(item) for item in content)))
    if isinstance(content, dict):
        return _stringify(content.get("text") or content.get("output_text") or content.get("content") or "")
    return _stringify(content)


def _clean_user_request(value: str) -> str:
    """Remove app-supplied context wrappers while preserving the actual request."""
    value = re.sub(
        r"\s*<in-app-browser-context\b[^>]*>[\s\S]*?</in-app-browser-context>\s*",
        "\n",
        value,
        flags=re.I,
    )
    value = re.sub(r"^\s*##\s*My request:\s*", "", value, flags=re.I)
    return value.strip()


def _display_path(path: str, cwd: str | None) -> str:
    if cwd and path.startswith(cwd.rstrip("/") + "/"):
        return path[len(cwd.rstrip("/")) + 1:]
    return path


def _human_tool_name(name: str) -> str:
    special = {
        "sites.create_site": "Created Site", "sites.save_site_version": "Saved Site version",
        "sites.deploy_private_site_version": "Published private Site", "sites.get_deployment_status": "Checked deployment",
        "github.get_repo": "Verified GitHub repository", "codex_app.open_in_codex": "Opened preview",
        "node_repl.js": "Controlled browser", "web.search": "Searched the web",
    }
    if name in special:
        return special[name]
    label = name.split(".")[-1].replace("__", "_").replace("_", " ").strip()
    return label[:1].upper() + label[1:]


def _shell_command(item: dict[str, Any]) -> str:
    command = item.get("command") or []
    if isinstance(command, list) and len(command) >= 3 and command[1] in {"-lc", "-c"}:
        return str(command[2])
    if isinstance(command, list):
        return " ".join(shlex.quote(str(part)) for part in command)
    return str(command)


def _command_title(item: dict[str, Any], command: str) -> tuple[str, str]:
    parsed = item.get("parsed_cmd") or []
    primary = parsed[0] if parsed and isinstance(parsed[0], dict) else {}
    parsed_type = str(primary.get("type") or "")
    name = str(primary.get("name") or "")
    lower = command.lower()
    if re.search(r"\b(npm|pnpm|yarn) (run )?(dev|start|serve)\b|\b(uvicorn|gunicorn|flask run)\b", lower):
        return "Ran development service", "service.dev"
    if parsed_type == "read":
        return f"Read {name or 'file'}", "file.read"
    if "pytest" in lower or re.search(r"\bnpm (run )?test\b", lower):
        return "Ran test suite", "test"
    if re.search(r"\bnpm run (build|lint)\b", lower):
        action = "Built project" if "build" in lower else "Ran linter"
        return action, "build" if "build" in lower else "lint"
    if re.search(r"\bgit push\b", lower):
        return "Pushed changes", "git.push"
    if re.search(r"\bgit commit\b", lower):
        return "Committed changes", "git.commit"
    if re.search(r"\bgit (status|diff|log|rev-parse|ls-remote)\b", lower):
        return "Inspected repository state", "git.inspect"
    if "package-site.sh" in lower:
        return "Packaged Site", "site.package"
    if re.search(r"\b(pip|npm) install\b", lower) or "-m venv" in lower:
        return "Prepared dependencies", "dependencies"
    if re.search(r"\b(curl|wget)\b", lower):
        return "Checked endpoint", "http.check"
    if re.match(r"\s*(rg|jq|sed|find|wc)\b", lower):
        return "Inspected project data", "inspect"
    try:
        executable = Path(shlex.split(command)[0]).name
    except (ValueError, IndexError):
        executable = "command"
    return f"Ran {executable}", f"shell.{executable}"


def _status(item: dict[str, Any]) -> str:
    status = str(item.get("status") or "completed").lower()
    exit_code = item.get("exit_code")
    if status in {"failed", "error", "cancelled"} or (isinstance(exit_code, int) and exit_code != 0):
        return "error"
    if status in {"pending", "running", "in_progress"}:
        return "warning"
    return "ok"


def _duration(payload: dict[str, Any], item: dict[str, Any]) -> int:
    started = payload.get("started_at_ms")
    completed = payload.get("completed_at_ms")
    if isinstance(started, (int, float)) and isinstance(completed, (int, float)):
        return max(0, round(completed - started))
    duration = item.get("duration")
    if isinstance(duration, dict):
        return int(duration.get("secs", 0) * 1000 + duration.get("nanos", 0) / 1_000_000)
    return 0


def _parse_codex(records: list[dict[str, Any]], name: str, raw: str) -> Run:
    meta_record = next((r for r in records if r.get("type") == "session_meta"), {})
    meta = meta_record.get("payload") if isinstance(meta_record.get("payload"), dict) else {}
    task_starts: dict[str, int] = {}
    task_ends: dict[str, int] = {}
    turns_by_id: dict[str, Turn] = {}
    goal = ""
    goal_status: str | None = None
    tokens: dict[str, int] = {}
    turn_context = next(
        (r.get("payload") for r in records if r.get("type") == "turn_context" and isinstance(r.get("payload"), dict)),
        {},
    )
    for record in records:
        payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
        if record.get("type") == "event_msg" and payload.get("type") == "task_started":
            turn_id = str(payload.get("turn_id"))
            started = int(float(payload.get("started_at", 0)) * 1000)
            task_starts[turn_id] = started
            turns_by_id[turn_id] = Turn(turn_id, started)
        elif record.get("type") == "event_msg" and payload.get("type") == "task_complete":
            turn_id = str(payload.get("turn_id"))
            completed = int(float(payload.get("completed_at", 0)) * 1000)
            task_ends[turn_id] = completed
            turn = turns_by_id.setdefault(turn_id, Turn(turn_id, completed))
            turn.completed_at_ms = completed
            turn.final_response = redact_secrets(str(payload.get("last_agent_message") or ""))
            turn.status = "completed"
        elif record.get("type") == "event_msg" and payload.get("type") == "thread_goal_updated":
            goal_data = payload.get("goal") if isinstance(payload.get("goal"), dict) else {}
            goal = str(goal_data.get("objective") or goal)
            goal_status = str(goal_data.get("status") or goal_status or "") or None
        elif record.get("type") == "event_msg" and payload.get("type") == "token_count":
            usage = ((payload.get("info") or {}).get("total_token_usage") or {}) if isinstance(payload.get("info"), dict) else {}
            tokens = {str(k): int(v) for k, v in usage.items() if isinstance(v, (int, float))}

    first_ms = min(task_starts.values(), default=int(_parse_time(meta.get("timestamp")) or 0))
    events: list[Event] = []
    normalized_item_types: Counter[str] = Counter()
    for record in records:
        if record.get("type") != "event_msg":
            continue
        payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
        if payload.get("type") != "item_completed" or not isinstance(payload.get("item"), dict):
            continue
        item = payload["item"]
        item_type = str(item.get("type") or "")
        turn_id = str(payload.get("turn_id") or "") or None
        at_ms = max(0, int(payload.get("started_at_ms") or first_ms) - first_ms)
        duration_ms = _duration(payload, item)
        event_id = str(item.get("id") or f"evt-{len(events)+1:04d}")
        status = _status(item)
        event: Event | None = None

        if item_type == "UserMessage":
            detail = _safe(_clean_user_request(_content_text(item.get("content"))), 8000)
            if turn_id and turn_id in turns_by_id:
                previous = turns_by_id[turn_id].user_request
                turns_by_id[turn_id].user_request = "\n\n".join(filter(None, (previous, detail)))
            event = Event(event_id, at_ms, "user", "message", _compact(detail, 90) or "User request", detail, turn_id=turn_id, duration_ms=duration_ms, raw=item)
        elif item_type == "AgentMessage":
            detail = _safe(_content_text(item.get("content")), 8000)
            phase = str(item.get("phase") or "commentary")
            title = "Final response" if phase == "final" else "Progress update"
            event = Event(event_id, at_ms, "codex", "message", title, detail, turn_id=turn_id, duration_ms=duration_ms, metadata={"phase": phase}, raw=item)
        elif item_type == "Reasoning":
            summaries = item.get("summary_text") or []
            detail = _safe("\n".join(str(value) for value in summaries)).replace("**", "")
            if detail:
                event = Event(event_id, at_ms, "codex", "reasoning", _compact(detail, 100), detail, turn_id=turn_id, duration_ms=duration_ms, raw=item)
        elif item_type == "CommandExecution":
            command = _shell_command(item)
            title, operation = _command_title(item, command)
            stdout = str(item.get("stdout") or "")
            stderr = str(item.get("stderr") or "")
            output = _safe("\n".join(filter(None, (stdout, stderr))), 8000)
            detail = f"{_compact(redact_secrets(command), 420)}"
            if output:
                detail += f"\n{_compact(output, 320)}"
            paths = []
            for parsed in item.get("parsed_cmd") or []:
                if isinstance(parsed, dict) and parsed.get("path"):
                    paths.append(_display_path(str(parsed["path"]), meta.get("cwd")))
            paths.extend(_display_path(path, meta.get("cwd")) for path in _extract_files(command))
            long_running = bool(re.search(r"\b(npm|pnpm|yarn) (run )?(dev|start|serve)\b|\b(uvicorn|gunicorn|flask run)\b", command, re.I))
            event = Event(event_id, at_ms, "codex", "error" if status == "error" else "tool", title, detail, status, duration_ms, turn_id, operation, _safe(command, 5000), output, list(dict.fromkeys(paths)), {"exit_code": item.get("exit_code"), "cwd": item.get("cwd"), "long_running": long_running}, item)
        elif item_type == "FileChange":
            changes = item.get("changes") if isinstance(item.get("changes"), dict) else {}
            files = [_display_path(str(path), meta.get("cwd")) for path in changes]
            additions = deletions = 0
            rows = []
            for path, change in changes.items():
                change = change if isinstance(change, dict) else {}
                diff = str(change.get("unified_diff") or change.get("content") or "")
                additions += sum(line.startswith("+") and not line.startswith("+++") for line in diff.splitlines())
                deletions += sum(line.startswith("-") and not line.startswith("---") for line in diff.splitlines())
                rows.append(f"{change.get('type', 'changed')}: {_display_path(str(path), meta.get('cwd'))}")
            title = f"Changed {len(files)} file{'s' if len(files) != 1 else ''} (+{additions} −{deletions})"
            event = Event(event_id, at_ms, "codex", "file", title, "\n".join(rows), status, duration_ms, turn_id, "file.change", files=files, metadata={"additions": additions, "deletions": deletions, "change_count": len(files)}, raw=item)
        elif item_type == "Extension":
            operation = str(item.get("kind") or "extension")
            query = str(item.get("query") or "")
            results = item.get("results") if isinstance(item.get("results"), list) else []
            title = f"Searched web: {_compact(query, 70)}" if operation == "web.search" else _human_tool_name(operation)
            output = "\n".join(f"- {r.get('title')}: {r.get('url')}" for r in results[:20] if isinstance(r, dict))
            event = Event(event_id, at_ms, "codex", "tool", title, _compact(output or query, 700), status, duration_ms, turn_id, operation, _safe(item.get("action") or query), _safe(output), _extract_files(item), {"result_count": len(results), "domains": list(dict.fromkeys(str(r.get("domain")) for r in results if isinstance(r, dict) and r.get("domain")))}, item)
        elif item_type in {"McpToolCall", "DynamicToolCall"}:
            server = str(item.get("server") or item.get("namespace") or "tool")
            tool = str(item.get("tool") or "call")
            operation = f"{server}.{tool}"
            result = item.get("result") or item.get("content_items") or ""
            output = _safe(result, 8000)
            detail = _compact(output, 550) or _compact(_safe(item.get("arguments")), 550)
            event = Event(event_id, at_ms, "codex", "error" if status == "error" else "tool", _human_tool_name(operation), detail, status, duration_ms, turn_id, operation, _safe(item.get("arguments"), 5000), output, _extract_files({"arguments": item.get("arguments"), "result": result}), {"server": server, "tool": tool, "read_only": item.get("readOnlyHint")}, item)
        elif item_type == "SubAgentActivity":
            path = str(item.get("agent_path") or "subagent")
            action = str(item.get("kind") or "activity")
            title = f"{action.title()} subagent {path.split('/')[-1]}"
            event = Event(event_id, at_ms, "codex", "handoff", title, f"Agent path: {path}\nThread: {item.get('agent_thread_id', 'unknown')}", status, duration_ms, turn_id, f"subagent.{action}", metadata={"agent_path": path, "agent_thread_id": item.get("agent_thread_id")}, raw=item)
        elif item_type == "ContextCompaction":
            event = Event(
                event_id, at_ms, "codex", "reasoning", "Compacted conversation context",
                "The agent condensed earlier conversation state to continue within its context window.",
                status, duration_ms, turn_id, "context.compact", raw=item,
            )

        if event:
            events.append(event)
            normalized_item_types[item_type] += 1

    events.sort(key=lambda event: (event.at_ms, event.id))
    turns = sorted(turns_by_id.values(), key=lambda turn: turn.started_at_ms)
    for turn in turns:
        turn.started_at_ms = max(0, turn.started_at_ms - first_ms)
        if turn.completed_at_ms is not None:
            turn.completed_at_ms = max(turn.started_at_ms, turn.completed_at_ms - first_ms)
    completed_item_types = Counter(
        str(record["payload"]["item"].get("type") or "unknown")
        for record in records
        if record.get("type") == "event_msg"
        and isinstance(record.get("payload"), dict)
        and record["payload"].get("type") == "item_completed"
        and isinstance(record["payload"].get("item"), dict)
    )
    semantic_candidates = sum(completed_item_types.values())
    unsupported_types = completed_item_types.keys() - SUPPORTED_CODEX_ITEM_TYPES
    unsupported = Counter({item_type: completed_item_types[item_type] for item_type in unsupported_types})
    supported_candidates = semantic_candidates - sum(unsupported.values())
    omitted_supported = Counter({
        item_type: completed_item_types[item_type] - normalized_item_types[item_type]
        for item_type in SUPPORTED_CODEX_ITEM_TYPES
        if completed_item_types[item_type] > normalized_item_types[item_type]
    })
    ingestion = {
        "adapter": "codex",
        "total_records": len(records),
        "bookkeeping_records": len(records) - semantic_candidates,
        "semantic_candidates": semantic_candidates,
        "normalized_events": len(events),
        "semantic_coverage_percent": round(len(events) / semantic_candidates * 100, 1) if semantic_candidates else 100.0,
        "adapter_coverage_percent": round(supported_candidates / semantic_candidates * 100, 1) if semantic_candidates else 100.0,
        "unsupported_completed_items": sum(unsupported.values()),
        "unsupported_item_types": [{"type": item_type, "count": count} for item_type, count in sorted(unsupported.items())],
        "omitted_supported_items": max(0, supported_candidates - len(events)),
        "omitted_supported_item_types": [{"type": item_type, "count": count} for item_type, count in sorted(omitted_supported.items())],
        "item_type_coverage": [
            {
                "type": item_type,
                "completed": count,
                "normalized": normalized_item_types[item_type],
                "omitted": max(0, count - normalized_item_types[item_type]),
                "supported": item_type in SUPPORTED_CODEX_ITEM_TYPES,
            }
            for item_type, count in sorted(completed_item_types.items())
        ],
    }
    return Run(
        name=name, source="Codex session", events=events, session_id=str(meta.get("session_id") or meta.get("id") or "") or None,
        goal=redact_secrets(goal), goal_status=goal_status, model=str(meta.get("model") or turn_context.get("model") or "") or None,
        cwd=str(meta.get("cwd") or turn_context.get("cwd") or "") or None, originator=str(meta.get("originator") or "") or None,
        cli_version=str(meta.get("cli_version") or "") or None, started_at=str(meta.get("timestamp") or "") or None,
        turns=turns, tokens=tokens, privacy_findings=scan_secrets(raw),
        metadata={"record_count": len(records), "adapter": "codex", "ignored_record_count": len(records) - len(events), "ingestion": ingestion},
    )


def _classify_generic(event_type: str, payload: dict[str, Any], detail: str) -> str:
    sample = f"{event_type} {payload.get('name', '')} {detail[:140]}".lower()
    if re.search(r"error|failed|failure|exception", sample): return "error"
    if re.search(r"handoff|delegate|subagent|spawn_agent", sample): return "handoff"
    if re.search(r"patch|edit|write_file|create_file|file_change", sample): return "file"
    if re.search(r"function_call_output|tool_result|command_output|result", sample): return "result"
    if re.search(r"tool|function_call|command|exec|search|browser|mcp", sample): return "tool"
    if re.search(r"reason|thinking|analysis", sample): return "reasoning"
    return "message"


def _parse_generic(records: list[dict[str, Any]], name: str, raw: str) -> Run:
    timestamps = [_parse_time(r.get("timestamp") or r.get("created_at") or r.get("time") or r.get("ts")) for r in records]
    first = next((value for value in timestamps if value is not None), 0.0)
    events: list[Event] = []
    for index, record in enumerate(records):
        payload = record.get("payload") if isinstance(record.get("payload"), dict) else record
        event_type = str(payload.get("type") or record.get("type") or "message")
        content = next((payload.get(key) for key in ("arguments", "output", "content", "message", "text", "data") if payload.get(key) is not None), payload)
        detail = _safe(content)
        kind = _classify_generic(event_type, payload, detail)
        name_value = str(payload.get("name") or payload.get("tool_name") or "")
        title = _human_tool_name(name_value) if name_value else _compact(detail, 90) or event_type.replace("_", " ").title()
        agent = str(payload.get("agent_name") or payload.get("agent") or payload.get("role") or "agent")
        timestamp = timestamps[index]
        at_ms = max(0, round(timestamp - first)) if timestamp is not None and first else index * 1000
        status = "error" if kind == "error" else "warning" if re.search(r"warn|retry|timeout", detail, re.I) else "ok"
        events.append(Event(f"evt-{index+1:04d}", at_ms, agent, kind, title, _compact(detail, 700), status, operation=name_value or event_type, input=detail if kind == "tool" else "", files=_extract_files(content), raw=record))
    ingestion = {
        "adapter": "generic",
        "total_records": len(records),
        "bookkeeping_records": 0,
        "semantic_candidates": len(records),
        "normalized_events": len(events),
        "semantic_coverage_percent": 100.0,
        "adapter_coverage_percent": 100.0,
        "unsupported_completed_items": 0,
        "unsupported_item_types": [],
        "omitted_supported_items": 0,
        "omitted_supported_item_types": [],
        "item_type_coverage": [{"type": "generic", "completed": len(records), "normalized": len(events), "omitted": 0, "supported": True}],
    }
    return Run(name, "Generic trace", events, privacy_findings=scan_secrets(raw), metadata={"record_count": len(records), "adapter": "generic", "ignored_record_count": 0, "ingestion": ingestion})


def parse_trace(source: str | Path, *, name: str | None = None) -> Run:
    """Parse Codex or loose JSON/JSONL into a compact, privacy-safe run model."""
    path: Path | None = None
    if isinstance(source, Path):
        path = source
    elif isinstance(source, str) and "\n" not in source:
        candidate = Path(source).expanduser()
        if candidate.exists():
            path = candidate
    source_bytes = path.read_bytes() if path else str(source).encode("utf-8")
    raw = source_bytes.decode("utf-8", errors="replace")
    records = _read_records(raw)
    if not records:
        raise ValueError("No readable JSON or JSONL event objects were found.")
    run_name = name or (path.stem if path else "imported-trace")
    is_codex = any(record.get("type") == "event_msg" and isinstance(record.get("payload"), dict) and record["payload"].get("type") == "item_completed" for record in records)
    run = _parse_codex(records, run_name, raw) if is_codex else _parse_generic(records, run_name, raw)
    run.metadata["source_fingerprint"] = f"sha256:{hashlib.sha256(source_bytes).hexdigest()}"
    run.metadata["source_bytes"] = len(source_bytes)
    return run


def detect_signals(events: Iterable[Event], *, loop_threshold: int = 3, stall_ms: int = 180_000) -> list[Signal]:
    ordered = list(events)
    signals: list[Signal] = []
    groups: dict[str, list[Event]] = {}
    for event in ordered:
        if event.status == "error" or event.kind == "error":
            signals.append(Signal("failure", "error", "Failed action", event.title, event.id, evidence=_compact(event.output or event.detail, 260)))
        if event.kind == "tool":
            groups.setdefault(event.fingerprint, []).append(event)

    for group in groups.values():
        for index in range(loop_threshold - 1, len(group)):
            window = group[index - loop_threshold + 1:index + 1]
            if window[-1].at_ms - window[0].at_ms <= 10 * 60_000:
                signals.append(Signal("repetition", "warning", "Repeated identical action", f"{window[-1].title} ran {loop_threshold} times with the same input.", window[-1].id, [event.id for event in window], _compact(window[-1].input, 220)))
                break

    failures = [event for event in ordered if event.status == "error"]
    for failed in failures:
        recovered = next((event for event in ordered if event.at_ms > failed.at_ms and event.status == "ok" and event.operation == failed.operation), None)
        if recovered:
            signals.append(Signal("recovery", "info", "Failure recovered", f"{failed.title} later succeeded after {round((recovered.at_ms-failed.at_ms)/1000)}s.", recovered.id, [failed.id, recovered.id]))

    for previous, current in zip(ordered, ordered[1:]):
        gap = current.at_ms - (previous.at_ms + previous.duration_ms)
        if gap > stall_ms and current.turn_id == previous.turn_id:
            signals.append(Signal("stall", "warning", "Unexplained idle gap", f"{round(gap / 60_000, 1)} minutes between “{previous.title}” and “{current.title}”.", current.id, [previous.id, current.id]))

    for event in ordered:
        if event.duration_ms >= 60_000 and event.kind in {"tool", "error"} and not event.metadata.get("long_running"):
            signals.append(Signal("slow", "info", "Slow action", f"{event.title} took {round(event.duration_ms/1000, 1)} seconds.", event.id))
    return sorted(signals, key=lambda signal: (ordered.index(next(event for event in ordered if event.id == signal.event_id)), {"error": 0, "warning": 1, "info": 2}.get(signal.severity, 3)))


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
    selected = history[-1]
    turn = next((turn for turn in run.turns if turn.id == selected.turn_id), None)
    successful = [event for event in history if event.status == "ok" and event.kind in {"tool", "file", "handoff"}][-10:]
    failures = [event for event in history if event.status == "error"][-5:]
    decisions = [event for event in history if event.kind in {"reasoning", "message"} and event.agent != "user"][-6:]
    files = list(dict.fromkeys(file for event in history for file in event.files))[-20:]
    scope = run.metadata.get("scope") or {}
    scope_notice = []
    if scope.get("active"):
        scope_notice = [
            "## Scope warning",
            f"This brief uses a focused slice containing {scope['selected_event_count']} of {scope['source_event_count']} normalized events. Events outside `{scope['from_event']}` through `{scope['to_event']}` are not represented.",
            "",
        ]
        incident = scope.get("incident") or {}
        if incident:
            scope_notice[2:2] = [
                f"Automatic incident focus: {incident['operation']} ({incident['status']}), with {incident['context_events']} surrounding event(s) on each side.",
            ]
    lines = [
        f"# Restart brief: {run.name}", "", *scope_notice, "## Objective", run.goal or (turn.user_request if turn else "Continue the recorded agent task."), "",
        "## Current turn", (turn.user_request if turn and turn.user_request else "No user request was recovered for this turn."), "",
        "## Decisions and progress", *([f"- {event.title}: {event.detail}" for event in decisions] or ["- No explicit decision summaries were recorded."]), "",
        "## Completed actions", *([f"- [{event.agent}] {event.title}" + (f" — {event.detail}" if event.detail else "") for event in successful] or ["- No successful actions were recorded."]), "",
        "## Failures still worth checking", *([f"- {event.title}: {_compact(event.output or event.detail, 300)}" for event in failures] or ["- No failed actions occurred before this checkpoint."]), "",
        "## Files involved", *([f"- {file}" for file in files] or ["- No file paths were detected."]), "",
        "## Resume exactly here", f"Checkpoint: {selected.id} — {selected.title}", f"Last recorded state: {selected.detail}",
        "Verify the workspace and external state before repeating any side effect. Continue with the next incomplete step; do not redo successful work without evidence it is stale.", "",
        "## Environment", f"- Model: {run.model or 'unknown'}", f"- Working directory: {run.cwd or 'unknown'}", f"- Source session: {run.session_id or 'unknown'}",
    ]
    return redact_secrets("\n".join(lines))

import json
from pathlib import Path

import pytest

from backtrace_agent.analysis import analyze_run, compare_runs, render_markdown_summary
from backtrace_agent.core import build_restart_brief, detect_signals, parse_trace, suppress_content
from backtrace_agent.report import render_html


def write_jsonl(tmp_path: Path, records: list[dict], name: str = "sample.jsonl") -> Path:
    path = tmp_path / name
    path.write_text("\n".join(json.dumps(record) for record in records), encoding="utf-8")
    return path


def generic_trace(tmp_path: Path) -> Path:
    return write_jsonl(tmp_path, [
        {"timestamp": "2026-08-29T12:00:00Z", "type": "message", "payload": {"role": "user", "content": "Fix app/main.py"}},
        {"timestamp": "2026-08-29T12:00:01Z", "type": "response_item", "payload": {"type": "function_call", "name": "exec_command", "arguments": "pytest"}},
        {"timestamp": "2026-08-29T12:00:02Z", "type": "response_item", "payload": {"type": "function_call", "name": "exec_command", "arguments": "pytest"}},
        {"timestamp": "2026-08-29T12:00:03Z", "type": "response_item", "payload": {"type": "function_call", "name": "exec_command", "arguments": "pytest"}},
        {"timestamp": "2026-08-29T12:00:04Z", "type": "error", "payload": {"agent": "builder", "message": "test failed"}},
    ])


def codex_trace(tmp_path: Path) -> Path:
    turn = "turn-1"

    def item(kind: str, item_value: dict, started: int) -> dict:
        return {"type": "event_msg", "payload": {"type": "item_completed", "turn_id": turn, "started_at_ms": started, "completed_at_ms": started + 500, "item": {"type": kind, "id": f"e-{started}", **item_value}}}

    return write_jsonl(tmp_path, [
        {"type": "session_meta", "payload": {"id": "session-1", "timestamp": "2026-08-29T12:00:00Z", "cwd": "/repo"}},
        {"type": "turn_context", "payload": {"turn_id": turn, "model": "gpt-test", "cwd": "/repo"}},
        {"type": "event_msg", "payload": {"type": "task_started", "turn_id": turn, "started_at": 2_000}},
        item("UserMessage", {"content": [{"text": "<in-app-browser-context>ignore me</in-app-browser-context>\n## My request:\nBuild the analyzer"}]}, 2_000_000),
        item("CommandExecution", {"command": ["zsh", "-lc", "pytest -q"], "status": "failed", "exit_code": 1, "stderr": "1 failed token=ghp_abcdefghijklmnopqrstuvwxyz123456 access=la_abcdefghijklmnopqrstuvwxyz123456"}, 2_001_000),
        item("FileChange", {"changes": {"/repo/src/app.py": {"type": "update", "unified_diff": "--- a\n+++ b\n-old\n+new\n+more"}}}, 2_002_000),
        item("CommandExecution", {"command": ["zsh", "-lc", "pytest -q"], "status": "completed", "exit_code": 0, "stdout": "3 passed"}, 2_003_000),
        item("McpToolCall", {"server": "sites", "tool": "get_deployment_status", "status": "completed", "result": {"status": "succeeded"}}, 2_004_000),
        {"type": "response_item", "payload": {"type": "function_call", "arguments": "ignored low-level duplicate"}},
        {"type": "event_msg", "payload": {"type": "token_count", "info": {"total_token_usage": {"total_tokens": 100, "cached_input_tokens": 40}}}},
        {"type": "event_msg", "payload": {"type": "task_complete", "turn_id": turn, "completed_at": 2_006, "last_agent_message": "Built and verified."}},
    ], "codex.jsonl")


def test_generic_trace_and_repetition_signal(tmp_path):
    run = parse_trace(generic_trace(tmp_path))
    assert len(run.events) == 5
    assert run.events[0].files == ["app/main.py"]
    assert run.duration_ms == 4000
    assert {signal.kind for signal in detect_signals(run.events)} == {"repetition", "failure"}


def test_codex_adapter_uses_semantic_events_and_redacts(tmp_path):
    run = parse_trace(codex_trace(tmp_path))
    assert run.model == "gpt-test"
    assert run.session_id == "session-1"
    assert len(run.events) == 5
    assert run.turns[0].user_request == "Build the analyzer"
    assert run.turns[0].final_response == "Built and verified."
    assert run.events[1].status == "error"
    assert run.events[2].files == ["src/app.py"]
    assert run.events[2].metadata["additions"] == 2
    exported = json.dumps(run.as_dict())
    assert "ghp_" not in exported
    assert "la_abcdefghijklmnopqrstuvwxyz" not in exported
    assert "raw" not in run.events[0].as_dict()


def test_analysis_separates_changed_and_referenced_files(tmp_path):
    analysis = analyze_run(parse_trace(codex_trace(tmp_path)))
    assert analysis["counts"]["files_changed"] == 1
    assert analysis["files"][0]["path"] == "src/app.py"
    assert {item["title"] for item in analysis["completion_evidence"]} == {"Ran test suite", "Checked deployment"}
    assert "Files changed: 1" in render_markdown_summary(parse_trace(codex_trace(tmp_path)))


def test_compare_runs_finds_normalized_improvement(tmp_path):
    baseline = parse_trace(codex_trace(tmp_path))
    current = parse_trace(codex_trace(tmp_path))
    failed = next(event for event in current.events if event.status == "error")
    failed.status = "ok"
    failed.kind = "tool"
    comparison = compare_runs(current, baseline)
    assert comparison["verdict"] == "improved"
    assert comparison["resolved_failing_operations"] == ["test"]
    failure_rate = next(item for item in comparison["metrics"] if item["key"] == "failures_per_100_actions")
    assert failure_rate["outcome"] == "improved"
    assert comparison["summary"]["improvements"] >= 2
    assert compare_runs(baseline, baseline)["verdict"] == "unchanged"


def test_comparison_appears_in_report_and_markdown(tmp_path):
    baseline = parse_trace(codex_trace(tmp_path))
    current = parse_trace(codex_trace(tmp_path))
    current.events[1].status = "ok"
    current.events[1].kind = "tool"
    comparison = compare_runs(current, baseline)
    report = render_html(current, comparison)
    assert 'data-view="compare"' in report
    assert "BASELINE COMPARISON" in report
    assert "LARGEST OPERATION COUNT CHANGES" in report
    assert '"comparison": {' in report
    assert "## Baseline comparison" in render_markdown_summary(current, comparison)


def test_custom_suppression_is_non_destructive_and_covers_exports(tmp_path):
    original = parse_trace(codex_trace(tmp_path))
    protected = suppress_content(original, ["analyzer", "src/app.py", "3 passed"])
    exported = json.dumps(protected.as_dict()).casefold()
    assert "analyzer" not in exported
    assert "src/app.py" not in exported
    assert "3 passed" not in exported
    assert original.turns[0].user_request == "Build the analyzer"
    assert original.events[2].files == ["src/app.py"]
    assert protected.metadata["custom_suppression"]["term_count"] == 3
    assert protected.privacy_findings["custom_suppression"] >= 3
    assert "analyzer" not in render_html(protected).casefold()


def test_restart_brief_is_checkpointed_and_redacted(tmp_path):
    run = parse_trace(codex_trace(tmp_path))
    brief = build_restart_brief(run, run.events[-1].id)
    assert "Build the analyzer" in brief
    assert "src/app.py" in brief
    assert "ghp_" not in brief
    with pytest.raises(ValueError, match="Unknown checkpoint"):
        build_restart_brief(run, "missing")


def test_report_is_self_contained_and_useful(tmp_path):
    report = render_html(parse_trace(codex_trace(tmp_path)))
    assert "<!doctype html>" in report.lower()
    assert "Failure recovered" in report
    assert "Restart brief" in report
    assert "RUN JOURNEY" in report
    assert "FILES CHANGED" in report
    assert "WHAT NEEDS ATTENTION" in report
    assert r"<\/script>" in render_html(parse_trace('\n'.join([
        json.dumps({"timestamp": "2026-01-01T00:00:00Z", "type": "message", "payload": {"content": "</script><script>alert(1)</script>"}}),
    ])))
    assert "https://" not in report

import json
from pathlib import Path

import pytest

from backtrace_agent.core import build_restart_brief, detect_signals, parse_trace, redact_secrets
from backtrace_agent.report import render_html


def make_trace(tmp_path: Path) -> Path:
    records = [
        {"timestamp": "2026-08-29T12:00:00Z", "type": "message", "payload": {"role": "user", "content": "Fix app/main.py"}},
        {"timestamp": "2026-08-29T12:00:01Z", "type": "response_item", "payload": {"type": "function_call", "name": "exec_command", "arguments": "pytest"}},
        {"timestamp": "2026-08-29T12:00:02Z", "type": "response_item", "payload": {"type": "function_call", "name": "exec_command", "arguments": "pytest"}},
        {"timestamp": "2026-08-29T12:00:03Z", "type": "response_item", "payload": {"type": "function_call", "name": "exec_command", "arguments": "pytest"}},
        {"timestamp": "2026-08-29T12:00:04Z", "type": "error", "payload": {"agent": "builder", "message": "test failed"}},
    ]
    path = tmp_path / "sample.jsonl"
    path.write_text("\n".join(json.dumps(record) for record in records), encoding="utf-8")
    return path


def test_parse_jsonl_and_extract_files(tmp_path):
    run = parse_trace(make_trace(tmp_path))
    assert len(run.events) == 5
    assert run.events[0].files == ["app/main.py"]
    assert run.duration_ms == 4000
    assert "builder" in run.agents


def test_detects_loop_and_failure(tmp_path):
    signals = detect_signals(parse_trace(make_trace(tmp_path)).events)
    assert {signal.kind for signal in signals} == {"loop", "failure"}


def test_restart_brief_redacts_secrets(tmp_path):
    run = parse_trace(make_trace(tmp_path))
    run.events[0].detail += " token=ghp_abcdefghijklmnopqrstuvwxyz123456"
    brief = build_restart_brief(run, "evt-0005")
    assert "[REDACTED_GITHUB_TOKEN]" in brief
    assert "app/main.py" in brief


def test_unknown_checkpoint_raises(tmp_path):
    with pytest.raises(ValueError, match="Unknown checkpoint"):
        build_restart_brief(parse_trace(make_trace(tmp_path)), "missing")


def test_report_is_self_contained(tmp_path):
    report = render_html(parse_trace(make_trace(tmp_path)))
    assert "<!doctype html>" in report.lower()
    assert "Possible tool loop" in report
    assert "Restart brief" in report
    assert "https://" not in report

import json
import hashlib
from pathlib import Path
from zipfile import ZipFile
from xml.etree import ElementTree as ET

import pytest

from backtrace_agent.analysis import analyze_run, catalog_incidents, classify_side_effect, compare_runs, evaluate_policy, focus_incident, render_markdown_summary, search_events
from backtrace_agent.cli import _watch, build_parser, build_policy_spec, load_policy, main
from backtrace_agent.ci import render_junit_xml
from backtrace_agent.bundle import verify_evidence_bundle, write_evidence_bundle
from backtrace_agent.core import Event, Run, build_restart_brief, detect_signals, parse_trace, slice_run, suppress_content
from backtrace_agent.fleet import discover_traces, render_fleet_html, scan_traces
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
        {"type": "event_msg", "payload": {"type": "token_count", "info": {"total_token_usage": {"total_tokens": 100, "input_tokens": 80, "cached_input_tokens": 40, "output_tokens": 20, "reasoning_output_tokens": 10}}}},
        {"type": "event_msg", "payload": {"type": "task_complete", "turn_id": turn, "completed_at": 2_006, "last_agent_message": "Built and verified."}},
    ], "codex.jsonl")


def test_generic_trace_and_repetition_signal(tmp_path):
    run = parse_trace(generic_trace(tmp_path))
    assert len(run.events) == 5
    assert run.events[0].files == ["app/main.py"]
    assert run.duration_ms == 4000
    assert {signal.kind for signal in detect_signals(run.events)} == {"repetition", "failure"}
    assert analyze_run(run)["ingestion"] == {
        "adapter": "generic",
        "total_records": 5,
        "bookkeeping_records": 0,
        "semantic_candidates": 5,
        "normalized_events": 5,
        "semantic_coverage_percent": 100.0,
        "adapter_coverage_percent": 100.0,
        "unsupported_completed_items": 0,
        "unsupported_item_types": [],
        "omitted_supported_items": 0,
        "omitted_supported_item_types": [],
        "item_type_coverage": [{"type": "generic", "completed": 5, "normalized": 5, "omitted": 0, "supported": True}],
    }


def test_codex_adapter_uses_semantic_events_and_redacts(tmp_path):
    trace = codex_trace(tmp_path)
    run = parse_trace(trace)
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
    assert run.metadata["source_fingerprint"] == f"sha256:{hashlib.sha256(trace.read_bytes()).hexdigest()}"
    assert run.metadata["source_bytes"] == len(trace.read_bytes())
    assert run.metadata["ingestion"] == {
        "adapter": "codex",
        "total_records": 11,
        "bookkeeping_records": 6,
        "semantic_candidates": 5,
        "normalized_events": 5,
        "semantic_coverage_percent": 100.0,
        "adapter_coverage_percent": 100.0,
        "unsupported_completed_items": 0,
        "unsupported_item_types": [],
        "omitted_supported_items": 0,
        "omitted_supported_item_types": [],
        "item_type_coverage": [
            {"type": "CommandExecution", "completed": 2, "normalized": 2, "omitted": 0, "supported": True},
            {"type": "FileChange", "completed": 1, "normalized": 1, "omitted": 0, "supported": True},
            {"type": "McpToolCall", "completed": 1, "normalized": 1, "omitted": 0, "supported": True},
            {"type": "UserMessage", "completed": 1, "normalized": 1, "omitted": 0, "supported": True},
        ],
    }


def test_ingestion_audit_exposes_schema_drift_empty_items_cli_and_gate(tmp_path, capsys):
    trace = codex_trace(tmp_path)
    records = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    records.extend([
        {
            "type": "event_msg",
            "payload": {
                "type": "item_completed",
                "turn_id": "turn-1",
                "item": {"type": "PlanMutation", "id": "unknown-1", "steps": ["inspect", "patch"]},
            },
        },
        {
            "type": "event_msg",
            "payload": {
                "type": "item_completed",
                "turn_id": "turn-1",
                "item": {"type": "Reasoning", "id": "empty-reasoning", "summary": []},
            },
        },
        {
            "type": "event_msg",
            "payload": {
                "type": "item_completed",
                "turn_id": "turn-1",
                "item": {"type": "ContextCompaction", "id": "compaction-1"},
            },
        },
    ])
    drift_trace = write_jsonl(tmp_path, records, "schema-drift.jsonl")
    run = parse_trace(drift_trace)
    ingestion = analyze_run(run)["ingestion"]
    assert ingestion["semantic_candidates"] == 8
    assert ingestion["normalized_events"] == 6
    assert ingestion["semantic_coverage_percent"] == 75.0
    assert ingestion["adapter_coverage_percent"] == 87.5
    assert ingestion["unsupported_completed_items"] == 1
    assert ingestion["unsupported_item_types"] == [{"type": "PlanMutation", "count": 1}]
    assert ingestion["omitted_supported_items"] == 1
    assert ingestion["omitted_supported_item_types"] == [{"type": "Reasoning", "count": 1}]
    assert ingestion["bookkeeping_records"] == 6

    no_report = tmp_path / "must-not-exist.html"
    assert main([str(drift_trace), "--audit-ingestion", "--output", str(no_report)]) == 0
    audit_text = capsys.readouterr().out
    assert "materialized: 75.0% · adapter coverage: 87.5%" in audit_text
    assert "PlanMutation: 1" in audit_text
    assert not no_report.exists()
    assert main([str(drift_trace), "--audit-ingestion", "--json"]) == 0
    audit_json = json.loads(capsys.readouterr().out)
    assert audit_json["source_wide"] is True
    assert audit_json["unsupported_completed_items"] == 1
    assert main([str(drift_trace), "--audit-ingestion", "--watch"]) == 2
    capsys.readouterr()

    gate = evaluate_policy(run, {"max_unsupported_items": 0})
    assert gate["passed"] is False
    assert gate["checks"][0]["key"] == "max_unsupported_items"
    assert main([str(trace), "--max-unsupported-items", "0", "-o", str(tmp_path / "clean.html")]) == 0
    assert main([str(drift_trace), "--max-unsupported-items", "0", "-o", str(tmp_path / "drift.html")]) == 1
    capsys.readouterr()
    report = render_html(run, quality_gate=gate)
    assert 'data-view="ingestion"' in report
    assert "SOURCE-WIDE PARSER COVERAGE" in report
    assert "PARSER DRIFT · 1 UNSUPPORTED" in report
    assert "PlanMutation" in report
    assert "PROVIDER TYPE MATRIX" in report
    assert "Reasoning" in report
    assert "including events outside the focused slice" not in report
    focused = slice_run(run, from_event=run.events[0].id, to_event=run.events[1].id)
    assert "including events outside the focused slice" in render_html(focused)
    markdown = render_markdown_summary(run)
    assert "## Ingestion coverage" in markdown
    assert "`PlanMutation` — 1 item(s)" in markdown


def test_trace_doctor_reports_damage_truncation_duplicate_ids_order_and_gates(tmp_path, capsys):
    source = codex_trace(tmp_path)
    records = source.read_text(encoding="utf-8").splitlines()
    duplicate_out_of_order = {
        "type": "event_msg",
        "payload": {
            "type": "item_completed",
            "turn_id": "turn-1",
            "started_at_ms": 1_999_000,
            "completed_at_ms": 1_999_100,
            "item": {
                "type": "CommandExecution",
                "id": "e-2003000",
                "command": ["zsh", "-lc", "echo duplicate"],
                "status": "completed",
                "exit_code": 0,
            },
        },
    }
    damaged = tmp_path / "damaged.jsonl"
    damaged.write_text("\n".join([*records[:4], "{broken", *records[4:], json.dumps(duplicate_out_of_order), '{"unfinished":']), encoding="utf-8")
    run = parse_trace(damaged)
    health = analyze_run(run)["input_health"]
    assert health["format"] == "jsonl"
    assert health["malformed_records"] == 2
    assert health["malformed_line_numbers"] == [5, 14]
    assert health["trailing_partial_record"] is True
    assert health["duplicate_event_ids"] == 1
    assert health["duplicate_event_id_samples"] == ["e-2003000"]
    assert health["timestamp_regressions"] == 1
    assert health["issue_count"] == 3
    assert health["warning_count"] == 1
    assert health["healthy"] is False

    no_report = tmp_path / "doctor-must-not-write.html"
    assert main([str(damaged), "--doctor", "-o", str(no_report)]) == 0
    doctor_text = capsys.readouterr().out
    assert "Trace doctor: ISSUES DETECTED" in doctor_text
    assert "Malformed lines: 5, 14" in doctor_text
    assert "Trailing partial record: yes" in doctor_text
    assert "Duplicate ID samples: e-2003000" in doctor_text
    assert not no_report.exists()
    assert main([str(damaged), "--doctor", "--json"]) == 0
    doctor_json = json.loads(capsys.readouterr().out)
    assert doctor_json["issue_count"] == 3
    assert doctor_json["warning_count"] == 1
    assert doctor_json["trailing_partial_record"] is True
    assert main([str(damaged), "--doctor", "--audit-ingestion"]) == 2
    capsys.readouterr()

    gate = evaluate_policy(run, {"max_malformed_records": 0, "max_duplicate_event_ids": 0})
    assert gate["passed"] is False
    assert {check["key"] for check in gate["checks"]} == {"max_malformed_records", "max_duplicate_event_ids"}
    assert main([str(damaged), "--max-malformed-records", "0", "--max-duplicate-event-ids", "0", "-o", str(tmp_path / "doctor-gate.html")]) == 1
    capsys.readouterr()
    report = render_html(run, quality_gate=gate)
    assert 'data-view="health"' in report
    assert "TRACE DOCTOR · SOURCE-WIDE" in report
    assert "SOURCE HEALTH · 3 ISSUES" in report
    assert "e-2003000" in report
    markdown = render_markdown_summary(run, quality_gate=gate)
    assert "## Input health" in markdown
    assert "Malformed source lines: 5, 14" in markdown

    healthy = analyze_run(parse_trace(codex_trace(tmp_path)))["input_health"]
    assert healthy["healthy"] is True
    assert healthy["issue_count"] == 0
    assert healthy["warning_count"] == 0

    unreadable = tmp_path / "only-broken.jsonl"
    unreadable.write_text('{"unfinished":', encoding="utf-8")
    assert main([str(unreadable), "--doctor", "--json"]) == 0
    unreadable_health = json.loads(capsys.readouterr().out)
    assert unreadable_health["malformed_records"] == 1
    assert unreadable_health["trailing_partial_record"] is True
    assert unreadable_health["normalization_available"] is False
    assert unreadable_health["healthy"] is False

    encoding_damaged = tmp_path / "encoding-damaged.jsonl"
    valid_record = json.dumps({"timestamp": "2026-08-29T12:00:00Z", "type": "message", "payload": {"content": "valid"}}).encode()
    encoding_damaged.write_bytes(valid_record + b"\n\xff")
    encoding_health = analyze_run(parse_trace(encoding_damaged))["input_health"]
    assert encoding_health["encoding_replacement_characters"] == 1
    assert encoding_health["malformed_records"] == 1
    assert encoding_health["healthy"] is False


def test_fleet_scan_ranks_runs_handles_errors_suppression_html_and_cli(tmp_path, capsys):
    root = tmp_path / "sessions with spaces"
    root.mkdir()
    write_jsonl(root, [{"timestamp": "2026-08-29T12:00:00Z", "type": "message", "payload": {"content": "quiet run"}}], "client-alpha.jsonl")
    write_jsonl(root, [{"timestamp": "2026-08-29T12:00:00Z", "type": "error", "payload": {"message": "deployment failed"}}], "failed.jsonl")
    (root / "broken.jsonl").write_text('{"unfinished":', encoding="utf-8")
    (root / "package.json").write_text("{}", encoding="utf-8")
    ignored = root / "node_modules"
    ignored.mkdir()
    write_jsonl(ignored, [{"type": "error", "payload": {"message": "ignore me"}}], "ignored.jsonl")

    discovered = discover_traces(root, limit=10)
    assert {path.name for path in discovered} == {"client-alpha.jsonl", "failed.jsonl", "broken.jsonl"}
    fleet = scan_traces(root, limit=10, suppress=["client-alpha"])
    assert fleet["summary"]["runs"] == 3
    assert fleet["parse_errors"] == 1
    assert fleet["status_counts"] == {"critical": 1, "attention": 0, "clean": 1, "unreadable": 1}
    assert fleet["summary"]["needs_attention"] == 2
    assert fleet["runs"][0]["status"] == "unreadable"
    assert any(item["path"] == "[suppressed]" for item in fleet["runs"])
    assert len({item["id"] for item in fleet["runs"]}) == 3
    assert "client-alpha" not in json.dumps(fleet).casefold()
    failed = next(item for item in fleet["runs"] if item["path"] == "failed.jsonl")
    assert failed["status"] == "critical"
    assert failed["unresolved_incidents"] == 1
    assert failed["source_argument"].startswith("'")
    html = render_fleet_html(fleet)
    assert "Session fleet" in html
    assert "MULTI-RUN SUPERVISION" in html
    assert "Highest risk" in html
    assert "Copy command" in html
    assert "Set as baseline" in html
    assert "Copy comparison command" in html
    assert "--compare ${baseline.source_argument}" in html
    assert "https://" not in html

    report = tmp_path / "fleet.html"
    assert main(["--scan", str(root), "--scan-limit", "10", "--suppress", "client-alpha", "-o", str(report)]) == 0
    text_output = capsys.readouterr().out
    assert "Session fleet: 3 run(s) · 2 need attention" in text_output
    assert f"Fleet report: {report.resolve()}" in text_output
    assert report.exists()
    json_report = tmp_path / "fleet-json.html"
    assert main(["--scan", str(root), "--scan-limit", "2", "--json", "-o", str(json_report)]) == 0
    json_output = json.loads(capsys.readouterr().out)
    assert json_output["summary"]["runs"] == 2
    assert json_report.exists()
    assert main(["--scan", str(root), str(root / "failed.jsonl"), "-o", str(tmp_path / "conflict.html")]) == 2
    capsys.readouterr()


def test_analysis_separates_changed_and_referenced_files(tmp_path):
    analysis = analyze_run(parse_trace(codex_trace(tmp_path)))
    assert analysis["counts"]["files_changed"] == 1
    assert analysis["files"][0]["path"] == "src/app.py"
    assert {item["title"] for item in analysis["completion_evidence"]} == {"Ran test suite", "Checked deployment"}
    assert "Files changed: 1" in render_markdown_summary(parse_trace(codex_trace(tmp_path)))
    assert analysis["tokens"]["uncached_input_tokens"] == 40
    assert analysis["tokens"]["input_cache_ratio_percent"] == 50.0
    assert analysis["tokens"]["tokens_per_action"] == 25.0
    assert analysis["tokens"]["reasoning_share_percent"] == 50.0
    phases = {phase["name"]: phase for phase in analysis["workflow"]["phases"]}
    assert phases["Implement"]["actions"] == 1
    assert phases["Verify"]["actions"] == 3
    assert analysis["workflow"]["current_phase"] == "Verify"
    assert analysis["incidents"]["total"] == 1
    assert analysis["incidents"]["recovered"] == 1
    assert analysis["incidents"]["unresolved"] == 0
    assert analysis["incidents"]["median_recovery_ms"] == 2000
    assert analysis["incidents"]["items"][0]["files"] == ["src/app.py"]
    agents = {item["agent"]: item for item in analysis["agents"]}
    assert set(agents) == {"user", "codex"}
    assert agents["codex"]["actions"] == 4
    assert agents["codex"]["failures"] == 1
    markdown = render_markdown_summary(parse_trace(codex_trace(tmp_path)))
    assert "## Reconstructed workflow" in markdown
    assert "## Agent activity" in markdown
    assert "## Token economics" in markdown
    assert "## Failure incidents" in markdown


def test_focused_slice_rebases_events_marks_partial_turns_and_omits_cumulative_tokens(tmp_path):
    trace = codex_trace(tmp_path)
    run = parse_trace(trace)
    focused = slice_run(run, from_event="e-2001000", to_event="e-2003000", agents=["CODEX"])
    assert [event.id for event in focused.events] == ["e-2001000", "e-2002000", "e-2003000"]
    assert [event.at_ms for event in focused.events] == [0, 1000, 2000]
    assert focused.tokens == {}
    assert focused.metadata["source_fingerprint"] == run.metadata["source_fingerprint"]
    assert focused.metadata["scope"] == {
        "active": True,
        "from_event": "e-2001000",
        "to_event": "e-2003000",
        "agents": ["codex"],
        "source_event_count": 5,
        "selected_event_count": 3,
        "selected_first_event": "e-2001000",
        "selected_last_event": "e-2003000",
        "original_start_ms": 1000,
        "original_end_ms": 3500,
        "timeline_rebased": True,
        "cumulative_token_counters_removed": True,
    }
    assert focused.turns[0].status == "partial"
    assert focused.turns[0].final_response == ""
    assert analyze_run(focused)["turns"][0]["status"] == "partial"
    assert "Focused slice: **3 of 5 events**" in render_markdown_summary(focused)
    assert "FOCUSED 3/5" in render_html(focused)
    assert "partial turn" in render_html(focused)
    assert "id=\"tokens\"" not in render_html(focused)
    assert "## Scope warning" in build_restart_brief(focused)
    with pytest.raises(ValueError, match="Unknown --agent"):
        slice_run(run, agents=["reviewer"])
    with pytest.raises(ValueError, match="occurs after"):
        slice_run(run, from_event="e-2003000", to_event="e-2001000")
    normalized = tmp_path / "focused.json"
    report = tmp_path / "focused.html"
    bundle = tmp_path / "focused.zip"
    assert main([
        str(trace), "--from-event", "e-2001000", "--to-event", "e-2003000", "--agent", "codex",
        "--normalized-output", str(normalized), "--bundle", str(bundle), "-o", str(report),
    ]) == 0
    cli_payload = json.loads(normalized.read_text())
    assert cli_payload["run"]["metadata"]["scope"]["selected_event_count"] == 3
    assert verify_evidence_bundle(bundle, source_trace=trace)["source_verified"] is True
    assert main([str(trace), "--from-event", "e-2001000", "--compare", str(trace), "-o", str(report)]) == 2


def test_automatic_incident_focus_expands_recovery_and_handles_unresolved_runs(tmp_path):
    trace = codex_trace(tmp_path)
    run = parse_trace(trace)
    recovered = focus_incident(run, "e-2001000", context_events=0, agents=["CODEX"])
    assert [event.id for event in recovered.events] == ["e-2001000", "e-2002000", "e-2003000"]
    incident = recovered.metadata["scope"]["incident"]
    assert incident["operation"] == "test"
    assert incident["status"] == "recovered"
    assert incident["failure_event_ids"] == ["e-2001000"]
    assert incident["recovery_event_id"] == "e-2003000"
    assert focus_incident(run, "e-2003000", context_events=0).metadata["scope"]["incident"]["id"] == incident["id"]
    assert "Automatic incident focus: **test** (recovered)" in render_markdown_summary(recovered)
    assert "Automatic incident focus selected <strong>test</strong>" in render_html(recovered)
    with pytest.raises(ValueError, match="No failure incident"):
        focus_incident(run, "missing-event")
    with pytest.raises(ValueError, match="removes incident evidence"):
        focus_incident(run, "e-2001000", agents=["user"])

    unresolved_run = Run("unresolved", "test", [
        Event("before", 0, "codex", "message", "Starting", ""),
        Event("failed", 1000, "codex", "error", "Tests failed", "1 failed", "error", operation="test"),
        Event("after", 2000, "codex", "message", "Investigating", ""),
    ])
    unresolved = focus_incident(unresolved_run, "failed", context_events=1)
    assert [event.id for event in unresolved.events] == ["before", "failed", "after"]
    assert unresolved.metadata["scope"]["incident"]["status"] == "unresolved"
    assert unresolved.metadata["scope"]["incident"]["recovery_event_id"] is None

    normalized = tmp_path / "incident.json"
    report = tmp_path / "incident.html"
    assert main([
        str(trace), "--incident", "e-2001000", "--context-events", "0", "--agent", "codex",
        "--normalized-output", str(normalized), "-o", str(report),
    ]) == 0
    assert json.loads(normalized.read_text())["run"]["metadata"]["scope"]["incident"]["status"] == "recovered"
    assert main([str(trace), "--context-events", "1", "-o", str(report)]) == 2
    assert main([str(trace), "--incident", "e-2001000", "--from-event", "e-2001000", "-o", str(report)]) == 2


def test_incident_catalog_supports_text_json_and_filters_without_writing_report(tmp_path, capsys):
    trace = codex_trace(tmp_path)
    run = parse_trace(trace)
    catalog = catalog_incidents(run)
    assert catalog["summary"] == {"total": 1, "recovered": 1, "unresolved": 0}
    assert catalog["incidents"][0]["focus_reference"] == "e-2001000"
    assert catalog["incidents"][0]["agents"] == ["codex"]
    assert catalog_incidents(run, status="unresolved")["incidents"] == []
    assert catalog_incidents(run, agents=["user"])["incidents"] == []
    with pytest.raises(ValueError, match="Unknown --agent"):
        catalog_incidents(run, agents=["reviewer"])
    assert catalog_incidents(Run("clean", "test", [Event("ok", 0, "codex", "tool", "Passed", "", operation="test")]))["summary"]["total"] == 0

    assert main([str(trace), "--list-incidents"]) == 0
    text_output = capsys.readouterr().out
    assert "1 · 0 unresolved · 1 recovered" in text_output
    assert "--incident e-2001000" in text_output
    assert not (tmp_path / "backtrace-report.html").exists()

    assert main([str(trace), "--list-incidents", "--json", "--incident-status", "recovered"]) == 0
    json_output = json.loads(capsys.readouterr().out)
    assert json_output["summary"]["recovered"] == 1
    assert json_output["incidents"][0]["recovery_event_id"] == "e-2003000"

    assert main([str(trace), "--list-incidents", "--agent", "user"]) == 0
    assert "No matching failure incidents detected." in capsys.readouterr().out
    assert main([str(trace), "--incident-status", "unresolved"]) == 2
    capsys.readouterr()

    html = render_html(run)
    assert 'data-copy-incident="e-2001000"' in html
    assert "backtrace-agent TRACE --incident" in html
    assert "Copy command template" in html
    assert "Template copied" in html


def test_ranked_event_search_supports_filters_json_limits_and_slice_templates(tmp_path, capsys):
    trace = codex_trace(tmp_path)
    run = parse_trace(trace)
    results = search_events(run, "pytest")
    assert results["summary"] == {"total_matches": 2, "returned": 2, "truncated": False}
    assert [event["id"] for event in results["events"]] == ["e-2001000", "e-2003000"]
    assert search_events(run, "pytest", status="error")["events"][0]["id"] == "e-2001000"
    exact = search_events(run, "e-2003000")
    assert exact["events"][0]["rank"] == 0
    assert exact["events"][0]["id"] == "e-2003000"
    file_results = search_events(run, "src/app.py", agents=["CODEX"], kinds=["file"])
    assert [event["id"] for event in file_results["events"]] == ["e-2002000"]
    limited = search_events(run, "test", limit=1)
    assert limited["summary"]["returned"] == 1 and limited["summary"]["truncated"] is True
    assert search_events(run, "not present")["events"] == []
    assert search_events(run, "ghp_abcdefghijklmnopqrstuvwxyz123456")["events"] == []
    with pytest.raises(ValueError, match="must not be empty"):
        search_events(run, "   ")
    with pytest.raises(ValueError, match="Unknown --agent"):
        search_events(run, "test", agents=["reviewer"])
    with pytest.raises(ValueError, match="Unknown --event-kind"):
        search_events(run, "test", kinds=["network"])

    assert main([str(trace), "--find", "pytest", "--event-status", "error"]) == 0
    text_output = capsys.readouterr().out
    assert "Matches: 1 of 1" in text_output
    assert "--from-event e-2001000 --to-event e-2001000" in text_output

    assert main([str(trace), "--find", "pytest", "--event-kind", "tool", "--json"]) == 0
    json_output = json.loads(capsys.readouterr().out)
    assert json_output["filters"]["kinds"] == ["tool"]
    assert [event["id"] for event in json_output["events"]] == ["e-2003000"]
    assert main([str(trace), "--event-kind", "tool"]) == 2
    capsys.readouterr()
    assert main([str(trace), "--find", "test", "--list-incidents"]) == 2
    capsys.readouterr()

    html = render_html(run)
    assert 'id="copy-slice"' in html
    assert "--from-event ${selected.id} --to-event ${selected.id}" in html


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


def test_quality_gate_is_explainable_and_rendered(tmp_path):
    run = parse_trace(codex_trace(tmp_path))
    gate = evaluate_policy(run, {"max_failures": 0, "max_repetitions": 1, "require_evidence": True})
    assert gate["configured"] is True
    assert gate["passed"] is False
    assert gate["summary"] == {"passed": 2, "failed": 1}
    failed = next(check for check in gate["checks"] if not check["passed"])
    assert failed["key"] == "max_failures"
    report = render_html(run, quality_gate=gate)
    assert "QUALITY GATE FAIL" in report
    assert "ENFORCEABLE QUALITY GATE · FAIL" in report
    assert "## Quality gate" in render_markdown_summary(run, quality_gate=gate)
    token_gate = evaluate_policy(run, {"max_total_tokens": 99, "max_tokens_per_action": 30, "min_cache_ratio": 50})
    assert token_gate["passed"] is False
    assert token_gate["summary"] == {"passed": 2, "failed": 1}
    token_report = render_html(run)
    assert 'data-view="tokens"' in token_report
    assert "TOKEN ECONOMICS" in token_report
    assert 'data-view="incidents"' in token_report
    assert "FAILURE → RECOVERY CHAINS" in token_report
    incident_gate = evaluate_policy(run, {"max_unresolved_failures": 0})
    assert incident_gate["passed"] is True


def test_missing_token_counters_are_explicit_and_do_not_create_empty_view(tmp_path):
    run = parse_trace(generic_trace(tmp_path))
    gate = evaluate_policy(run, {"max_total_tokens": 100, "max_tokens_per_action": 100, "min_cache_ratio": 50})
    assert gate["passed"] is False
    assert gate["summary"] == {"passed": 0, "failed": 3}
    assert {check["actual"] for check in gate["checks"]} == {"unavailable"}
    assert 'data-view="tokens"' not in render_html(run)


def test_side_effect_ledger_and_destructive_gate_are_explicit():
    destructive = Event("remove-1", 0, "builder", "tool", "Remove cache", "rm cache.db", operation="shell.rm", input="rm cache.db")
    publish = Event("push-1", 1000, "builder", "tool", "Push branch", "origin/main", operation="git.push")
    harmless = Event("read-1", 2000, "builder", "tool", "Read file", "README", operation="file.read", input="echo rm cache.db")
    status_check = Event("status-1", 3000, "builder", "tool", "Check deployment", "succeeded", operation="sites.get_deployment_status")
    assert classify_side_effect(destructive)["category"] == "destructive"
    assert classify_side_effect(publish)["category"] == "publish"
    assert classify_side_effect(harmless) is None
    assert classify_side_effect(status_check) is None
    run = Run("effects", "test", [destructive, publish, harmless])
    analysis = analyze_run(run)
    assert analysis["side_effects"]["total"] == 2
    assert analysis["side_effects"]["destructive_attempts"] == 1
    assert evaluate_policy(run, {"max_destructive_actions": 0})["passed"] is False
    report = render_html(run)
    assert 'data-view="effects"' in report
    assert "CONSEQUENTIAL ACTION LEDGER" in report


def test_evidence_bundle_is_sanitized_complete_and_hash_verified(tmp_path):
    trace = codex_trace(tmp_path)
    run = parse_trace(trace)
    destination = write_evidence_bundle(run, tmp_path / "evidence.zip")
    duplicate = write_evidence_bundle(run, tmp_path / "evidence-copy.zip")
    assert destination.read_bytes() == duplicate.read_bytes()
    with ZipFile(destination) as archive:
        assert set(archive.namelist()) == {"report.html", "normalized.json", "summary.md", "manifest.json"}
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["format"] == "backtrace-evidence-bundle-v2"
        assert manifest["raw_trace_included"] is False
        assert manifest["source_trace"] == {"sha256": run.metadata["source_fingerprint"], "bytes": len(trace.read_bytes()), "included": False}
        for name, evidence in manifest["files"].items():
            content = archive.read(name)
            assert evidence["sha256"] == hashlib.sha256(content).hexdigest()
            assert evidence["bytes"] == len(content)
        combined = b"\n".join(archive.read(name) for name in archive.namelist())
        assert b"ghp_abcdefghijklmnopqrstuvwxyz" not in combined
    assert verify_evidence_bundle(destination) == {"valid": True, "files_verified": 3, "source_verified": None, "errors": []}
    assert verify_evidence_bundle(destination, source_trace=trace)["source_verified"] is True
    malformed = tmp_path / "malformed-provenance.zip"
    with ZipFile(destination) as source, ZipFile(malformed, "w") as target:
        for name in source.namelist():
            content = source.read(name)
            if name == "manifest.json":
                broken_manifest = json.loads(content)
                broken_manifest["source_trace"].pop("bytes")
                content = json.dumps(broken_manifest).encode()
            target.writestr(name, content)
    assert verify_evidence_bundle(malformed)["errors"] == ["Source-trace provenance is missing or incomplete."]
    tampered = tmp_path / "tampered.zip"
    with ZipFile(destination) as source, ZipFile(tampered, "w") as target:
        for name in source.namelist():
            content = source.read(name) + (b"changed" if name == "report.html" else b"")
            target.writestr(name, content)
    verification = verify_evidence_bundle(tampered)
    assert verification["valid"] is False
    assert verification["files_verified"] == 2
    assert verification["source_verified"] is None
    assert verification["errors"] == ["SHA-256 mismatch for report.html."]
    assert main(["--verify-bundle", str(destination)]) == 0
    assert main(["--verify-bundle", str(destination), "--verify-source", str(trace)]) == 0
    assert main(["--verify-source", str(trace)]) == 2
    assert main(["--verify-bundle", str(tampered)]) == 1
    wrong_source = tmp_path / "wrong.jsonl"
    wrong_source.write_text("{}")
    mismatch = verify_evidence_bundle(destination, source_trace=wrong_source)
    assert mismatch["valid"] is False
    assert mismatch["source_verified"] is False
    assert mismatch["errors"] == ["Supplied source trace does not match the bundle provenance."]
    legacy = tmp_path / "legacy-v1.zip"
    with ZipFile(destination) as source, ZipFile(legacy, "w") as target:
        for name in source.namelist():
            content = source.read(name)
            if name == "manifest.json":
                old_manifest = json.loads(content)
                old_manifest["format"] = "backtrace-evidence-bundle-v1"
                old_manifest.pop("source_trace")
                content = json.dumps(old_manifest).encode()
            target.writestr(name, content)
    assert verify_evidence_bundle(legacy)["valid"] is True
    legacy_source_check = verify_evidence_bundle(legacy, source_trace=trace)
    assert legacy_source_check["valid"] is False
    assert legacy_source_check["errors"] == ["Bundle does not contain source-trace provenance."]


def test_watch_mode_regenerates_all_outputs_atomically(tmp_path):
    trace = write_jsonl(tmp_path, [{"timestamp": "2026-08-29T12:00:00Z", "type": "message", "payload": {"role": "user", "content": "First event"}}], "watch.jsonl")
    report = tmp_path / "watch-report.html"
    normalized = tmp_path / "watch.json"
    summary = tmp_path / "watch.md"
    bundle = tmp_path / "watch.zip"
    args = build_parser().parse_args([str(trace), "--watch", "-o", str(report), "--normalized-output", str(normalized), "--summary-output", str(summary), "--bundle", str(bundle)])

    def append_event(_interval):
        second = json.dumps({"timestamp": "2026-08-29T12:00:01Z", "type": "message", "payload": {"role": "assistant", "content": "Second event"}})
        trace.write_text(trace.read_text(encoding="utf-8") + "\n" + second, encoding="utf-8")

    assert _watch(args, trace, _sleep=append_event, _max_cycles=2) == 0
    watched = json.loads(normalized.read_text())
    assert watched["analysis"]["counts"]["events"] == 2
    assert watched["run"]["metadata"]["source_fingerprint"] == f"sha256:{hashlib.sha256(trace.read_bytes()).hexdigest()}"
    assert "Second event" in report.read_text()
    assert "## Agent activity" in summary.read_text()
    assert verify_evidence_bundle(bundle)["valid"] is True
    assert not list(tmp_path.glob(".watch-*"))


def test_policy_file_is_strict_validated_overridable_and_embedded(tmp_path):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps({"max_failures": 1, "max_unresolved_failures": 0, "require_evidence": True}))
    assert load_policy(policy_path)["max_failures"] == 1
    args = build_parser().parse_args(["trace.jsonl", "--policy", str(policy_path), "--max-failures", "3"])
    assert build_policy_spec(args)["max_failures"] == 3
    trace = codex_trace(tmp_path)
    report = tmp_path / "policy-report.html"
    normalized = tmp_path / "policy.json.out"
    assert main([str(trace), "--policy", str(policy_path), "-o", str(report), "--normalized-output", str(normalized)]) == 0
    exported = json.loads(normalized.read_text())
    assert exported["quality_gate"]["policy_source"] == "policy.json"
    assert "POLICY policy.json" in report.read_text()
    invalid = tmp_path / "invalid-policy.json"
    invalid.write_text(json.dumps({"max_failures": -1, "invented_gate": 2}))
    assert main([str(trace), "--policy", str(invalid), "-o", str(tmp_path / "invalid.html")]) == 2
    assert not (tmp_path / "invalid.html").exists()


def test_junit_export_maps_gate_results_and_empty_policy(tmp_path):
    run = parse_trace(codex_trace(tmp_path))
    failed_gate = evaluate_policy(run, {"max_failures": 0, "require_evidence": True})
    failed_gate["policy_source"] = "strict.json"
    suite = ET.fromstring(render_junit_xml(run, failed_gate))
    assert suite.attrib["tests"] == "2"
    assert suite.attrib["failures"] == "1"
    assert suite.find("./properties/property[@name='policy']").attrib["value"] == "strict.json"
    assert suite.find("./testcase/failure").attrib["type"] == "max_failures"
    empty = ET.fromstring(render_junit_xml(run, evaluate_policy(run, {})))
    assert empty.attrib["skipped"] == "1"
    junit_path = tmp_path / "quality.xml"
    assert main([str(codex_trace(tmp_path)), "--max-failures", "1", "--junit-output", str(junit_path), "-o", str(tmp_path / "junit-report.html")]) == 0
    assert ET.parse(junit_path).getroot().attrib["failures"] == "0"


def test_cli_quality_gate_controls_exit_status(tmp_path):
    trace = generic_trace(tmp_path)
    assert main([str(trace), "--output", str(tmp_path / "failed.html"), "--max-failures", "0"]) == 1
    assert main([str(trace), "--output", str(tmp_path / "passed.html"), "--max-failures", "1"]) == 0
    assert main([str(trace), "--output", str(tmp_path / "unresolved.html"), "--max-unresolved-failures", "0"]) == 1
    destructive = write_jsonl(tmp_path, [{"timestamp": "2026-08-29T12:00:00Z", "type": "response_item", "payload": {"type": "function_call", "name": "exec_command", "arguments": "rm cache.db"}}], "destructive.jsonl")
    assert main([str(destructive), "--output", str(tmp_path / "destructive.html"), "--max-destructive-actions", "0"]) == 1


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
    assert 'data-view="workflow"' in report
    assert "RECONSTRUCTED WORKFLOW" in report
    assert "MOST COMMON PHASE TRANSITIONS" in report
    assert 'id="bookmark-event"' in report
    assert 'id="copy-event-link"' in report
    assert 'data-view="review"' in report
    assert "backtrace-review:" in report
    assert "#event=" in report
    assert 'data-view="map"' in report
    assert "TIME-SCALED AGENT MOVEMENT" in report
    assert "AGENT WORKLOAD" in report
    assert "FILES CHANGED" in report
    assert "WHAT NEEDS ATTENTION" in report
    assert r"<\/script>" in render_html(parse_trace('\n'.join([
        json.dumps({"timestamp": "2026-01-01T00:00:00Z", "type": "message", "payload": {"content": "</script><script>alert(1)</script>"}}),
    ])))
    assert "https://" not in report

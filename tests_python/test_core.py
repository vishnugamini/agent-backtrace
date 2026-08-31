import json
import hashlib
from pathlib import Path
from zipfile import ZipFile
from xml.etree import ElementTree as ET

import pytest

from backtrace_agent.analysis import analyze_run, catalog_incidents, classify_side_effect, compare_runs, evaluate_policy, focus_incident, render_markdown_summary
from backtrace_agent.cli import _watch, build_parser, build_policy_spec, load_policy, main
from backtrace_agent.ci import render_junit_xml
from backtrace_agent.bundle import verify_evidence_bundle, write_evidence_bundle
from backtrace_agent.core import Event, Run, build_restart_brief, detect_signals, parse_trace, slice_run, suppress_content
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

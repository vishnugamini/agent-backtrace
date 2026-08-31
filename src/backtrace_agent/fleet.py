from __future__ import annotations

import html
import hashlib
import json
import os
import shlex
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .analysis import analyze_run
from .core import parse_trace, suppress_content


TRACE_SUFFIXES = {".jsonl", ".json"}
IGNORED_DIRECTORIES = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__"}
IGNORED_JSON_FILES = {"package.json", "package-lock.json", "tsconfig.json", "hosting.json"}


def discover_traces(root: str | Path, *, limit: int = 50) -> list[Path]:
    """Return the newest likely trace files below a directory."""
    root = Path(root).expanduser()
    if not root.exists():
        raise ValueError(f"Scan directory does not exist: {root}")
    if not root.is_dir():
        raise ValueError(f"--scan expects a directory, not a file: {root}")
    candidates: list[tuple[int, Path]] = []
    for directory, subdirectories, filenames in os.walk(root):
        subdirectories[:] = [name for name in subdirectories if name not in IGNORED_DIRECTORIES]
        for filename in filenames:
            path = Path(directory) / filename
            if path.suffix.casefold() not in TRACE_SUFFIXES or filename in IGNORED_JSON_FILES:
                continue
            try:
                candidates.append((path.stat().st_mtime_ns, path))
            except OSError:
                continue
    candidates.sort(key=lambda item: (-item[0], str(item[1])))
    return [path for _, path in candidates[:limit]]


def _short(value: str, length: int = 180) -> str:
    value = " ".join(value.split())
    return value if len(value) <= length else value[:length] + "…"


def _display_value(value: str, terms: Iterable[str]) -> str:
    folded = value.casefold()
    return "[suppressed]" if any(term.casefold() in folded for term in terms if term) else value


def scan_traces(root: str | Path, *, limit: int = 50, suppress: Iterable[str] = ()) -> dict[str, Any]:
    """Parse recent traces and return privacy-safe, risk-ranked run summaries."""
    root = Path(root).expanduser().resolve()
    suppression_terms = list(dict.fromkeys(term.strip() for term in suppress if term.strip()))
    paths = discover_traces(root, limit=limit)
    runs: list[dict[str, Any]] = []
    parse_errors = 0
    for path in paths:
        path_identity = "sha256:" + hashlib.sha256(f"source:{path}".encode("utf-8")).hexdigest()
        relative_path = _display_value(str(path.relative_to(root)), suppression_terms)
        safe_absolute_path = _display_value(str(path), suppression_terms)
        report_command = (
            f"backtrace-agent {shlex.quote(safe_absolute_path)} -o run-report.html"
            if safe_absolute_path != "[suppressed]"
            else "Source path suppressed in this dashboard."
        )
        modified = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
        try:
            run = parse_trace(path)
            if suppression_terms:
                run = suppress_content(run, suppression_terms)
            analysis = analyze_run(run)
            counts = analysis["counts"]
            health = analysis["input_health"]
            ingestion = analysis["ingestion"]
            incidents = analysis["incidents"]
            side_effects = analysis["side_effects"]
            signal_counts: dict[str, int] = {}
            for signal in analysis["signals"]:
                signal_counts[signal["kind"]] = signal_counts.get(signal["kind"], 0) + 1
            risk_score = min(100, (
                health["issue_count"] * 12
                + ingestion["unsupported_completed_items"] * 10
                + incidents["unresolved"] * 10
                + side_effects["destructive_attempts"] * 8
                + counts["failures"] * 2
                + signal_counts.get("repetition", 0) * 3
                + signal_counts.get("stall", 0) * 2
            ))
            if health["issue_count"] or ingestion["unsupported_completed_items"] or incidents["unresolved"] or side_effects["destructive_attempts"]:
                status = "critical"
            elif counts["failures"] or signal_counts.get("repetition", 0) or signal_counts.get("stall", 0):
                status = "attention"
            else:
                status = "clean"
            objective = run.goal or next((turn.user_request for turn in run.turns if turn.user_request), "")
            runs.append({
                "path": relative_path,
                "name": run.name,
                "modified_at": modified,
                "session_id": run.session_id,
                "model": run.model,
                "objective": _short(objective) or "No objective recovered.",
                "status": status,
                "risk_score": risk_score,
                "events": counts["events"],
                "actions": counts["actions"],
                "failures": counts["failures"],
                "unresolved_incidents": incidents["unresolved"],
                "destructive_attempts": side_effects["destructive_attempts"],
                "repetitions": signal_counts.get("repetition", 0),
                "stalls": signal_counts.get("stall", 0),
                "source_issues": health["issue_count"],
                "ordering_notes": health["warning_count"],
                "unsupported_items": ingestion["unsupported_completed_items"],
                "duration_ms": run.duration_ms,
                "source_fingerprint": run.metadata.get("source_fingerprint"),
                "history_identity_sha256": (
                    "sha256:" + hashlib.sha256(f"session:{run.session_id}".encode("utf-8")).hexdigest()
                    if run.session_id else path_identity
                ),
                "source_argument": shlex.quote(safe_absolute_path) if safe_absolute_path != "[suppressed]" else None,
                "report_command": report_command,
                "error": None,
            })
        except (OSError, ValueError) as exc:
            parse_errors += 1
            runs.append({
                "path": relative_path,
                "name": path.stem,
                "modified_at": modified,
                "session_id": None,
                "model": None,
                "objective": "No run could be recovered from this source.",
                "status": "unreadable",
                "risk_score": 100,
                "events": 0,
                "actions": 0,
                "failures": 0,
                "unresolved_incidents": 0,
                "destructive_attempts": 0,
                "repetitions": 0,
                "stalls": 0,
                "source_issues": 1,
                "ordering_notes": 0,
                "unsupported_items": 0,
                "duration_ms": 0,
                "source_fingerprint": None,
                "history_identity_sha256": path_identity,
                "source_argument": None,
                "report_command": report_command.replace(" -o run-report.html", " --doctor"),
                "error": _display_value(_short(str(exc), 240), suppression_terms),
            })
    runs.sort(key=lambda item: (-item["risk_score"], item["modified_at"], item["path"]), reverse=False)
    for index, item in enumerate(runs, 1):
        item["id"] = f"fleet-run-{index:04d}"
    status_counts = {status: sum(item["status"] == status for item in runs) for status in ("critical", "attention", "clean", "unreadable")}
    return {
        "root": _display_value(str(root), suppression_terms),
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "limit": limit,
        "files_discovered": len(paths),
        "parse_errors": parse_errors,
        "status_counts": status_counts,
        "summary": {
            "runs": len(runs),
            "needs_attention": status_counts["critical"] + status_counts["attention"] + status_counts["unreadable"],
            "failures": sum(item["failures"] for item in runs),
            "unresolved_incidents": sum(item["unresolved_incidents"] for item in runs),
            "source_issues": sum(item["source_issues"] for item in runs),
            "unsupported_items": sum(item["unsupported_items"] for item in runs),
        },
        "runs": runs,
    }


HISTORY_SCHEMA_VERSION = 1
HISTORY_SUMMARY_KEYS = ("runs", "needs_attention", "failures", "unresolved_incidents", "source_issues", "unsupported_items")
HISTORY_RUN_KEYS = (
    "status", "risk_score", "failures", "unresolved_incidents", "destructive_attempts",
    "repetitions", "stalls", "source_issues", "unsupported_items",
)
FLEET_GATE_LABELS = {
    "max_fleet_needs_attention": "Runs needing attention",
    "max_fleet_unresolved": "Unresolved incidents",
    "max_fleet_source_issues": "Source-integrity issues",
    "max_new_attention": "New runs needing attention",
    "fail_on_fleet_regression": "Run status regressions",
}


def _history_identity(run: dict[str, Any]) -> str:
    """Return a stable, irreversible run identity without persisting its source value."""
    if run.get("history_identity_sha256"):
        return str(run["history_identity_sha256"])
    if run.get("session_id"):
        source = f"session:{run['session_id']}"
    elif run.get("source_fingerprint"):
        source = f"fingerprint:{run['source_fingerprint']}"
    else:
        source = f"source:{run.get('path', '')}"
    return "sha256:" + hashlib.sha256(source.encode("utf-8")).hexdigest()


def build_history_snapshot(fleet: dict[str, Any]) -> dict[str, Any]:
    """Reduce a fleet scan to bounded trend data that contains no source text or paths."""
    return {
        "recorded_at": fleet["generated_at"],
        "summary": {key: int(fleet["summary"].get(key, 0)) for key in HISTORY_SUMMARY_KEYS},
        "status_counts": {key: int(fleet["status_counts"].get(key, 0)) for key in ("critical", "attention", "clean", "unreadable")},
        "runs": [
            {
                "identity_sha256": _history_identity(run),
                **{key: (str(run.get(key) or "clean") if key == "status" else int(run.get(key, 0))) for key in HISTORY_RUN_KEYS},
            }
            for run in fleet["runs"]
        ],
    }


def compare_history_snapshots(previous: dict[str, Any] | None, current: dict[str, Any]) -> dict[str, Any]:
    """Compare two fleet snapshots without claiming that absent runs recovered."""
    empty_deltas = {key: 0 for key in HISTORY_SUMMARY_KEYS}
    if previous is None:
        return {
            "has_baseline": False,
            "previous_recorded_at": None,
            "new_runs": len(current["runs"]),
            "new_runs_needing_attention": sum(run["status"] != "clean" for run in current["runs"]),
            "regressed_runs": 0,
            "improved_runs": 0,
            "left_scan_window": 0,
            "deltas": empty_deltas,
        }
    previous_runs = {run["identity_sha256"]: run for run in previous["runs"]}
    current_runs = {run["identity_sha256"]: run for run in current["runs"]}
    new_ids = current_runs.keys() - previous_runs.keys()
    left_ids = previous_runs.keys() - current_runs.keys()
    shared_ids = previous_runs.keys() & current_runs.keys()
    severity = {"clean": 0, "attention": 1, "critical": 2, "unreadable": 3}
    regressed = sum(severity.get(current_runs[key]["status"], 3) > severity.get(previous_runs[key]["status"], 3) for key in shared_ids)
    improved = sum(severity.get(current_runs[key]["status"], 3) < severity.get(previous_runs[key]["status"], 3) for key in shared_ids)
    return {
        "has_baseline": True,
        "previous_recorded_at": previous["recorded_at"],
        "new_runs": len(new_ids),
        "new_runs_needing_attention": sum(current_runs[key]["status"] != "clean" for key in new_ids),
        "regressed_runs": regressed,
        "improved_runs": improved,
        "left_scan_window": len(left_ids),
        "deltas": {key: current["summary"][key] - previous["summary"][key] for key in HISTORY_SUMMARY_KEYS},
    }


def _load_history(destination: Path) -> dict[str, Any]:
    if not destination.exists():
        return {"schema_version": HISTORY_SCHEMA_VERSION, "snapshots": []}
    try:
        history = json.loads(destination.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Fleet history is not valid JSON and was left unchanged: {destination}") from exc
    if not isinstance(history, dict) or history.get("schema_version") != HISTORY_SCHEMA_VERSION or not isinstance(history.get("snapshots"), list):
        raise ValueError(f"Unsupported fleet history schema and file was left unchanged: {destination}")
    valid_statuses = {"critical", "attention", "clean", "unreadable"}
    for snapshot in history["snapshots"]:
        valid_snapshot = (
            isinstance(snapshot, dict)
            and isinstance(snapshot.get("recorded_at"), str)
            and isinstance(snapshot.get("runs"), list)
            and isinstance(snapshot.get("summary"), dict)
            and isinstance(snapshot.get("status_counts"), dict)
            and all(isinstance(snapshot["summary"].get(key), int) for key in HISTORY_SUMMARY_KEYS)
            and all(isinstance(snapshot["status_counts"].get(key), int) for key in valid_statuses)
        )
        if not valid_snapshot:
            raise ValueError(f"Malformed fleet history snapshot and file was left unchanged: {destination}")
        for run in snapshot["runs"]:
            identity = run.get("identity_sha256") if isinstance(run, dict) else None
            valid_identity = (
                isinstance(identity, str) and identity.startswith("sha256:") and len(identity) == 71
                and all(character in "0123456789abcdef" for character in identity[7:])
            )
            if not valid_identity or run.get("status") not in valid_statuses or not all(isinstance(run.get(key), int) for key in HISTORY_RUN_KEYS if key != "status"):
                raise ValueError(f"Malformed fleet history run and file was left unchanged: {destination}")
    return history


def update_fleet_history(fleet: dict[str, Any], destination: str | Path, *, limit: int = 50) -> dict[str, Any]:
    """Atomically append a privacy-minimized fleet snapshot and return report-ready trend data."""
    destination = Path(destination).expanduser()
    history = _load_history(destination)
    current = build_history_snapshot(fleet)
    previous = history["snapshots"][-1] if history["snapshots"] else None
    trend = compare_history_snapshots(previous, current)
    history["snapshots"] = [*history["snapshots"], current][-limit:]
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    os.close(descriptor)
    try:
        Path(temporary).write_text(json.dumps(history, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return {
        "schema_version": HISTORY_SCHEMA_VERSION,
        "snapshot_count": len(history["snapshots"]),
        "trend": trend,
        "recent_snapshots": [
            {"recorded_at": item["recorded_at"], "summary": item["summary"], "status_counts": item["status_counts"]}
            for item in history["snapshots"][-12:]
        ],
    }


def evaluate_fleet_gate(fleet: dict[str, Any], spec: dict[str, Any]) -> dict[str, Any]:
    """Evaluate current-fleet and previous-snapshot thresholds with explicit skips."""
    checks: list[dict[str, Any]] = []
    current_metrics = {
        "max_fleet_needs_attention": fleet["summary"]["needs_attention"],
        "max_fleet_unresolved": fleet["summary"]["unresolved_incidents"],
        "max_fleet_source_issues": fleet["summary"]["source_issues"],
    }
    for key, actual in current_metrics.items():
        expected = spec.get(key)
        if expected is None:
            continue
        checks.append({
            "key": key,
            "label": FLEET_GATE_LABELS[key],
            "actual": actual,
            "expected": f"at most {expected}",
            "passed": actual <= expected,
            "skipped": False,
            "detail": f"Fleet recorded {actual}; configured maximum is {expected}.",
        })
    history = fleet.get("history") or {}
    trend = history.get("trend") or {}
    trend_metrics = []
    if spec.get("max_new_attention") is not None:
        trend_metrics.append(("max_new_attention", trend.get("new_runs_needing_attention"), f"at most {spec['max_new_attention']}"))
    if spec.get("fail_on_fleet_regression"):
        trend_metrics.append(("fail_on_fleet_regression", trend.get("regressed_runs"), "exactly 0"))
    for key, actual, expected_text in trend_metrics:
        skipped = not trend.get("has_baseline", False)
        threshold = 0 if key == "fail_on_fleet_regression" else spec[key]
        checks.append({
            "key": key,
            "label": FLEET_GATE_LABELS[key],
            "actual": "baseline unavailable" if skipped else actual,
            "expected": expected_text,
            "passed": skipped or int(actual) <= threshold,
            "skipped": skipped,
            "detail": (
                "No previous fleet snapshot exists; this trend check will evaluate on the next scan."
                if skipped else f"Previous-to-current comparison recorded {actual}; configured maximum is {threshold}."
            ),
        })
    failed = sum(not check["passed"] and not check["skipped"] for check in checks)
    skipped = sum(check["skipped"] for check in checks)
    return {
        "configured": bool(checks),
        "passed": failed == 0,
        "checks": checks,
        "summary": {"passed": len(checks) - failed - skipped, "failed": failed, "skipped": skipped},
    }


def render_fleet_html(fleet: dict[str, Any]) -> str:
    payload = json.dumps(fleet, ensure_ascii=False).replace("</", "<\\/")
    template = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Backtrace · Session fleet</title><style>
:root{--ink:#17211c;--paper:#f2efe6;--surface:#fffdf7;--green:#174c3b;--line:#cfcec4;--muted:#69726d;--red:#b94f3d;--amber:#a56720;--blue:#49779a}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:14px/1.45 Arial,sans-serif}.shell{max-width:1500px;margin:auto;padding:34px 30px 80px}.brand,.kicker{font:800 10px monospace;letter-spacing:.13em;color:var(--green)}h1{font:700 clamp(38px,6vw,70px)/.95 Georgia,serif;letter-spacing:-.04em;margin:16px 0}.lede{max-width:760px;color:#44524b;font:19px/1.5 Georgia,serif}.metrics{display:grid;grid-template-columns:repeat(6,1fr);border:1px solid var(--line);background:var(--surface);margin:28px 0}.metric{padding:18px;border-right:1px solid var(--line)}.metric:last-child{border:0}.metric strong,.metric span{display:block}.metric strong{font:28px Georgia,serif}.metric span{font:9px monospace;color:var(--muted);letter-spacing:.09em}.trend{margin:0 0 30px;border:1px solid var(--line);background:var(--surface);padding:22px}.trend-head{display:flex;justify-content:space-between;gap:20px;align-items:start}.trend-head h2{font:28px Georgia,serif;margin:4px 0}.trend-head p{margin:4px 0;color:var(--muted);max-width:680px}.trend-cards{display:grid;grid-template-columns:repeat(6,1fr);margin-top:17px;border:1px solid var(--line)}.trend-card{padding:14px;border-right:1px solid var(--line)}.trend-card:last-child{border:0}.trend-card strong,.trend-card span{display:block}.trend-card strong{font:24px Georgia,serif}.trend-card span{font:9px monospace;color:var(--muted);letter-spacing:.07em}.trend-card.bad strong{color:var(--red)}.trend-card.good strong{color:var(--green)}.chart-wrap{overflow:auto;margin-top:18px}.trend-chart{height:170px;min-width:540px;display:flex;align-items:flex-end;gap:9px;border-left:1px solid var(--line);border-bottom:1px solid var(--line);padding:15px 12px 0}.scan-column{height:100%;min-width:32px;flex:1;display:flex;gap:3px;align-items:flex-end;position:relative}.scan-column i{display:block;min-height:2px;flex:1;background:var(--amber);border-radius:2px 2px 0 0}.scan-column i.unresolved{background:var(--red)}.scan-column time{position:absolute;left:50%;bottom:-30px;transform:translateX(-50%) rotate(-32deg);font:8px monospace;color:var(--muted);white-space:nowrap}.chart-legend{display:flex;gap:18px;margin:32px 0 0;font:10px monospace;color:var(--muted)}.chart-legend span:before{content:"";display:inline-block;width:8px;height:8px;background:var(--amber);margin-right:5px}.chart-legend span:last-child:before{background:var(--red)}.toolbar{display:grid;grid-template-columns:minmax(240px,1fr) 170px 170px;gap:9px;margin:18px 0 8px}.toolbar input,.toolbar select{border:1px solid var(--line);background:var(--surface);padding:11px;border-radius:5px;font:inherit}.baseline-note{min-height:31px;padding:7px 10px;margin-bottom:10px;background:#e6ece4;border-left:3px solid var(--green);font:11px monospace;color:#385248}.table-wrap{overflow:auto;border:1px solid var(--line);background:var(--surface)}table{width:100%;border-collapse:collapse;min-width:1120px}th,td{text-align:left;padding:12px;border-bottom:1px solid #e1e0d7;vertical-align:top}th{font:800 9px monospace;letter-spacing:.09em;color:var(--muted);position:sticky;top:0;background:#f8f5ed}tr{cursor:pointer}tbody tr:hover,tbody tr.selected{background:#edf2e9}.status{font:800 9px monospace;text-transform:uppercase;border-radius:999px;padding:5px 7px;display:inline-block}.status.clean{background:#dfebdf;color:var(--green)}.status.attention{background:#f5e7d2;color:#835719}.status.critical,.status.unreadable{background:#f6ded8;color:#8b3225}.risk{font:700 21px Georgia,serif}.path{font:11px monospace;word-break:break-all}.objective{max-width:390px;color:#4e5b55}.detail{margin-top:18px;border:1px solid var(--line);border-left:5px solid var(--green);background:var(--surface);padding:22px;display:none}.detail.open{display:block}.detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}.facts,.compare-actions{display:flex;gap:8px;flex-wrap:wrap}.compare-actions{margin-top:16px}.pill{border:1px solid var(--line);border-radius:999px;padding:5px 8px;font:10px monospace}.command{display:flex;gap:8px;background:#e9ece5;padding:12px;margin-top:14px;align-items:center}.command code{flex:1;word-break:break-all}.button{border:1px solid var(--green);background:var(--green);color:white;padding:8px 11px;border-radius:4px;cursor:pointer;font-weight:700}.button.secondary{background:transparent;color:var(--green)}.button:disabled{opacity:.45;cursor:not-allowed}.empty{text-align:center;color:var(--muted);padding:40px}.footer{margin-top:22px;color:var(--muted);font-size:11px}@media(max-width:850px){.metrics,.trend-cards{grid-template-columns:repeat(3,1fr)}.trend-card:nth-child(3){border-right:0}.trend-card:nth-child(-n+3){border-bottom:1px solid var(--line)}.toolbar{grid-template-columns:1fr}.detail-grid{grid-template-columns:1fr}}@media(max-width:520px){.shell{padding-inline:14px}.metrics,.trend-cards{grid-template-columns:repeat(2,1fr)}.trend-card{border-bottom:1px solid var(--line)}.trend-card:nth-child(2n){border-right:0}.trend-head{display:block}.command{display:block}.command .button{margin-top:8px;width:100%}}
</style></head><body><div class="shell"><div class="brand">BACKTRACE · MULTI-RUN SUPERVISION</div><h1>Session fleet</h1><p class="lede">Find the agent run that needs you first. Risk is ranked from recorded source integrity, parser coverage, unresolved failures, destructive attempts, repetition, and stalls.</p><p class="path" id="root"></p><section class="metrics" id="metrics"></section><section class="trend" id="trend" hidden><div class="trend-head"><div><div class="kicker">FLEET HISTORY</div><h2>Is supervision improving?</h2><p id="trend-summary"></p></div><span class="pill" id="snapshot-count"></span></div><div class="trend-cards" id="trend-cards"></div><div class="chart-wrap"><div class="trend-chart" id="trend-chart" aria-label="Recent scan trends"></div></div><div class="chart-legend"><span>Runs needing attention</span><span>Unresolved incidents</span></div><p class="footer"><strong>Important:</strong> a run leaving the scan window is not counted as recovered. It may simply be older than the current scan limit.</p></section><section><div class="kicker">RUN INVENTORY</div><div class="toolbar"><input id="search" type="search" placeholder="Search objective, model, session, or path…"><select id="status"><option value="all">All statuses</option><option value="critical">Critical</option><option value="attention">Needs attention</option><option value="clean">Clean</option><option value="unreadable">Unreadable</option></select><select id="sort"><option value="risk">Highest risk</option><option value="newest">Newest first</option><option value="failures">Most failures</option><option value="unresolved">Most unresolved</option></select></div><div class="baseline-note" id="baseline-note">No comparison baseline selected.</div><div class="table-wrap"><table><thead><tr><th>Status</th><th>Risk</th><th>Run</th><th>Objective</th><th>Actions</th><th>Failed</th><th>Unresolved</th><th>Source</th><th>Modified</th></tr></thead><tbody id="rows"></tbody></table></div></section><section class="detail" id="detail"></section><p class="footer"><strong>Risk score is a transparent triage heuristic:</strong> 12 points per source-integrity issue, 10 per unsupported item or unresolved incident, 8 per destructive attempt, 2 per failed action or stall, and 3 per repetition; capped at 100. Generated locally from normalized summaries, not raw provider records.</p></div><script id="fleet-data" type="application/json">__DATA__</script><script>
const F=JSON.parse(document.getElementById('fleet-data').textContent),$=s=>document.querySelector(s),esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));let selected=null,baselineId=null;$('#root').textContent=`Scanned ${F.root} · ${F.files_discovered} newest trace file(s)`;const cards=[['RUNS',F.summary.runs],['NEED ATTENTION',F.summary.needs_attention],['FAILED ACTIONS',F.summary.failures],['UNRESOLVED',F.summary.unresolved_incidents],['SOURCE ISSUES',F.summary.source_issues],['UNSUPPORTED',F.summary.unsupported_items]];$('#metrics').innerHTML=cards.map(([l,v])=>`<div class="metric"><strong>${v}</strong><span>${l}</span></div>`).join('');if(F.history){const H=F.history,T=H.trend,signed=n=>`${n>0?'+':''}${n}`;$('#trend').hidden=false;$('#snapshot-count').textContent=`${H.snapshot_count} snapshot${H.snapshot_count===1?'':'s'}`;$('#trend-summary').textContent=T.has_baseline?`Compared with ${new Date(T.previous_recorded_at).toLocaleString()}. Status changes require the same hashed run identity in both scans.`:'First snapshot recorded. Run this command again later to establish a previous-scan baseline.';const tc=[['REGRESSED',T.regressed_runs,'bad'],['IMPROVED',T.improved_runs,'good'],['NEW RUNS',T.new_runs,''],['LEFT WINDOW',T.left_scan_window,''],['ATTENTION Δ',signed(T.deltas.needs_attention),T.deltas.needs_attention>0?'bad':T.deltas.needs_attention<0?'good':''],['UNRESOLVED Δ',signed(T.deltas.unresolved_incidents),T.deltas.unresolved_incidents>0?'bad':T.deltas.unresolved_incidents<0?'good':'']];$('#trend-cards').innerHTML=tc.map(([l,v,c])=>`<div class="trend-card ${c}"><strong>${v}</strong><span>${l}</span></div>`).join('');const snapshots=H.recent_snapshots,max=Math.max(1,...snapshots.flatMap(s=>[s.summary.needs_attention,s.summary.unresolved_incidents]));$('#trend-chart').innerHTML=snapshots.map(s=>`<div class="scan-column" title="${esc(new Date(s.recorded_at).toLocaleString())}: ${s.summary.needs_attention} need attention, ${s.summary.unresolved_incidents} unresolved"><i style="height:${s.summary.needs_attention/max*100}%"></i><i class="unresolved" style="height:${s.summary.unresolved_incidents/max*100}%"></i><time>${esc(new Date(s.recorded_at).toLocaleDateString())}</time></div>`).join('')}function updateBaseline(){const b=F.runs.find(x=>x.id===baselineId);$('#baseline-note').textContent=b?`Comparison baseline: ${b.name} · ${b.path}`:'No comparison baseline selected.'}
const time=v=>new Date(v).toLocaleString(),duration=ms=>ms>=60000?`${(ms/60000).toFixed(1)}m`:`${(ms/1000).toFixed(1)}s`;function filtered(){const q=$('#search').value.toLowerCase(),status=$('#status').value,sort=$('#sort').value;const rows=F.runs.filter(r=>(status==='all'||r.status===status)&&(!q||[r.path,r.name,r.objective,r.model,r.session_id].join(' ').toLowerCase().includes(q)));rows.sort((a,b)=>sort==='newest'?b.modified_at.localeCompare(a.modified_at):sort==='failures'?b.failures-a.failures:sort==='unresolved'?b.unresolved_incidents-a.unresolved_incidents:b.risk_score-a.risk_score||b.modified_at.localeCompare(a.modified_at));return rows}function render(){const runs=filtered();$('#rows').innerHTML=runs.length?runs.map(r=>`<tr data-run="${r.id}" class="${selected===r.id?'selected':''}"><td><span class="status ${r.status}">${r.status}</span></td><td><span class="risk">${r.risk_score}</span></td><td><strong>${esc(r.name)}</strong><div class="path">${esc(r.path)}</div><small>${esc(r.model||'model unknown')}</small></td><td class="objective">${esc(r.objective)}</td><td>${r.actions}</td><td>${r.failures}</td><td>${r.unresolved_incidents}</td><td>${r.source_issues} issues<br>${r.unsupported_items} unsupported</td><td>${time(r.modified_at)}</td></tr>`).join(''):'<tr><td colspan="9" class="empty">No runs match these filters.</td></tr>';document.querySelectorAll('tbody tr[data-run]').forEach(row=>row.onclick=()=>open(row.dataset.run))}function open(id){selected=id;const r=F.runs.find(x=>x.id===id);if(!r)return;const baseline=F.runs.find(x=>x.id===baselineId),canCompare=baseline&&baseline.id!==r.id&&baseline.source_argument&&r.source_argument;$('#detail').classList.add('open');$('#detail').innerHTML=`<div class="kicker">SELECTED RUN</div><div class="detail-grid"><div><h2>${esc(r.name)}</h2><p>${esc(r.objective)}</p><div class="facts"><span class="pill">${r.events} events</span><span class="pill">${r.actions} actions</span><span class="pill">${duration(r.duration_ms)}</span><span class="pill">${r.repetitions} repetitions</span><span class="pill">${r.stalls} stalls</span><span class="pill">${r.ordering_notes} ordering notes</span></div><div class="compare-actions"><button class="button secondary" id="set-baseline" ${r.source_argument?'':'disabled'}>${baselineId===r.id?'Baseline selected':'Set as baseline'}</button><button class="button secondary" id="copy-compare" ${canCompare?'':'disabled'}>Copy comparison command</button></div></div><div><p><strong>Session</strong><br><code>${esc(r.session_id||'unknown')}</code></p><p><strong>Source fingerprint</strong><br><code>${esc(r.source_fingerprint||'unavailable')}</code></p>${r.error?`<p><strong>Parse error</strong><br>${esc(r.error)}</p>`:''}</div></div><div class="command"><code>${esc(r.report_command)}</code><button class="button" id="copy">Copy command</button></div>`;$('#copy').onclick=async()=>{await navigator.clipboard.writeText(r.report_command);$('#copy').textContent='Copied'};$('#set-baseline').onclick=()=>{if(!r.source_argument)return;baselineId=r.id;updateBaseline();open(r.id)};$('#copy-compare').onclick=async()=>{if(!canCompare)return;const command=`backtrace-agent ${r.source_argument} --compare ${baseline.source_argument} -o comparison.html`;await navigator.clipboard.writeText(command);$('#copy-compare').textContent='Comparison copied'};render();$('#detail').scrollIntoView({behavior:'smooth',block:'nearest'})}['search','status','sort'].forEach(id=>$('#'+id).addEventListener(id==='search'?'input':'change',render));updateBaseline();render();
</script></body></html>'''.replace("__DATA__", payload)
    gate_css = '.fleet-gate{margin:0 0 28px;padding:20px;border:1px solid #9ab8a7;border-left:6px solid var(--green);background:#eef5ef}.fleet-gate.fail{border-color:#d39b8f;border-left-color:var(--red);background:#fbefec}.gate-head{display:flex;justify-content:space-between;gap:18px;align-items:start}.gate-head h2{font:27px Georgia,serif;margin:4px 0}.gate-result{font:800 12px monospace;border:1px solid currentColor;border-radius:999px;padding:7px 10px;color:var(--green)}.fleet-gate.fail .gate-result{color:var(--red)}.gate-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:15px}.gate-check{padding:12px;background:var(--surface);border:1px solid var(--line)}.gate-check.fail{border-color:#d39b8f}.gate-check.skip{border-style:dashed}.gate-check strong,.gate-check span,.gate-check small{display:block}.gate-check span{font:9px monospace;color:var(--muted);margin-top:5px}.gate-check small{margin-top:5px;color:#52605a}.delivery{margin:14px 0 0;padding:9px 11px;background:#fffdf799;border-left:3px solid var(--blue);font:11px monospace}.delivery.failed{border-left-color:var(--red)}.delivery.skipped{border-left-color:var(--amber)}'
    gate_html = '<section class="fleet-gate" id="fleet-gate" hidden><div class="gate-head"><div><div class="kicker">AUTOMATION DECISION</div><h2 id="gate-title"></h2><p id="gate-summary"></p></div><span class="gate-result" id="gate-result"></span></div><div class="gate-grid" id="gate-checks"></div><p class="delivery" id="notification-status" hidden></p></section>'
    gate_js = '''const G=F.quality_gate,N=F.notification;if(G?.configured){const gate=$('#fleet-gate');gate.hidden=false;gate.classList.toggle('fail',!G.passed);$('#gate-title').textContent=G.passed?'Fleet gate passed':'Fleet gate failed';$('#gate-result').textContent=G.passed?'PASS':'FAIL';$('#gate-summary').textContent=`${G.summary.passed} passed · ${G.summary.failed} failed · ${G.summary.skipped} skipped. Failed configured checks return exit code 1.`;$('#gate-checks').innerHTML=G.checks.map(c=>`<article class="gate-check ${c.skipped?'skip':c.passed?'':'fail'}"><strong>${esc(c.label)}</strong><span>Actual ${esc(c.actual)} · expected ${esc(c.expected)}</span><small>${esc(c.detail)}</small></article>`).join('');if(N?.configured){const delivery=$('#notification-status'),written=N.payload_written?' · exact payload written':'';delivery.hidden=false;delivery.classList.add(N.status);delivery.textContent=N.status==='delivered'?`${N.format} webhook delivered in ${N.attempts} attempt(s) · HTTP ${N.status_code} · ${N.event_id}${written}`:N.status==='skipped'?`${N.format} webhook skipped · ${N.error}${written}`:N.status==='previewed'?`${N.format} webhook previewed without a network request · ${N.event_id}${written}`:`${N.format} webhook delivery failed after ${N.attempts} attempt(s) · ${N.error}${written}`}}'''
    template = template.replace('.trend{', gate_css + '.trend{', 1)
    template = template.replace('<section class="trend" id="trend" hidden>', gate_html + '<section class="trend" id="trend" hidden>', 1)
    template = template.replace("if(F.history){", gate_js + "if(F.history){", 1)
    template = template.replace('@media(max-width:850px){.metrics,.trend-cards', '@media(max-width:850px){.gate-grid{grid-template-columns:1fr 1fr}.metrics,.trend-cards', 1)
    template = template.replace('@media(max-width:520px){.shell', '@media(max-width:520px){.gate-head{display:block}.gate-result{display:inline-block;margin-top:8px}.gate-grid{grid-template-columns:1fr}.shell', 1)
    return template


def write_fleet_report(fleet: dict[str, Any], destination: str | Path) -> Path:
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    os.close(descriptor)
    try:
        Path(temporary).write_text(render_fleet_html(fleet), encoding="utf-8")
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return destination

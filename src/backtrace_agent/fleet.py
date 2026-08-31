from __future__ import annotations

import html
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


def render_fleet_html(fleet: dict[str, Any]) -> str:
    payload = json.dumps(fleet, ensure_ascii=False).replace("</", "<\\/")
    return r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Backtrace · Session fleet</title><style>
:root{--ink:#17211c;--paper:#f2efe6;--surface:#fffdf7;--green:#174c3b;--line:#cfcec4;--muted:#69726d;--red:#b94f3d;--amber:#a56720;--blue:#49779a}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:14px/1.45 Arial,sans-serif}.shell{max-width:1500px;margin:auto;padding:34px 30px 80px}.brand,.kicker{font:800 10px monospace;letter-spacing:.13em;color:var(--green)}h1{font:700 clamp(38px,6vw,70px)/.95 Georgia,serif;letter-spacing:-.04em;margin:16px 0}.lede{max-width:760px;color:#44524b;font:19px/1.5 Georgia,serif}.metrics{display:grid;grid-template-columns:repeat(6,1fr);border:1px solid var(--line);background:var(--surface);margin:28px 0}.metric{padding:18px;border-right:1px solid var(--line)}.metric:last-child{border:0}.metric strong,.metric span{display:block}.metric strong{font:28px Georgia,serif}.metric span{font:9px monospace;color:var(--muted);letter-spacing:.09em}.toolbar{display:grid;grid-template-columns:minmax(240px,1fr) 170px 170px;gap:9px;margin:18px 0 8px}.toolbar input,.toolbar select{border:1px solid var(--line);background:var(--surface);padding:11px;border-radius:5px;font:inherit}.baseline-note{min-height:31px;padding:7px 10px;margin-bottom:10px;background:#e6ece4;border-left:3px solid var(--green);font:11px monospace;color:#385248}.table-wrap{overflow:auto;border:1px solid var(--line);background:var(--surface)}table{width:100%;border-collapse:collapse;min-width:1120px}th,td{text-align:left;padding:12px;border-bottom:1px solid #e1e0d7;vertical-align:top}th{font:800 9px monospace;letter-spacing:.09em;color:var(--muted);position:sticky;top:0;background:#f8f5ed}tr{cursor:pointer}tbody tr:hover,tbody tr.selected{background:#edf2e9}.status{font:800 9px monospace;text-transform:uppercase;border-radius:999px;padding:5px 7px;display:inline-block}.status.clean{background:#dfebdf;color:var(--green)}.status.attention{background:#f5e7d2;color:#835719}.status.critical,.status.unreadable{background:#f6ded8;color:#8b3225}.risk{font:700 21px Georgia,serif}.path{font:11px monospace;word-break:break-all}.objective{max-width:390px;color:#4e5b55}.detail{margin-top:18px;border:1px solid var(--line);border-left:5px solid var(--green);background:var(--surface);padding:22px;display:none}.detail.open{display:block}.detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}.facts,.compare-actions{display:flex;gap:8px;flex-wrap:wrap}.compare-actions{margin-top:16px}.pill{border:1px solid var(--line);border-radius:999px;padding:5px 8px;font:10px monospace}.command{display:flex;gap:8px;background:#e9ece5;padding:12px;margin-top:14px;align-items:center}.command code{flex:1;word-break:break-all}.button{border:1px solid var(--green);background:var(--green);color:white;padding:8px 11px;border-radius:4px;cursor:pointer;font-weight:700}.button.secondary{background:transparent;color:var(--green)}.button:disabled{opacity:.45;cursor:not-allowed}.empty{text-align:center;color:var(--muted);padding:40px}.footer{margin-top:22px;color:var(--muted);font-size:11px}@media(max-width:850px){.metrics{grid-template-columns:repeat(3,1fr)}.toolbar{grid-template-columns:1fr}.detail-grid{grid-template-columns:1fr}}@media(max-width:520px){.shell{padding-inline:14px}.metrics{grid-template-columns:repeat(2,1fr)}.command{display:block}.command .button{margin-top:8px;width:100%}}
</style></head><body><div class="shell"><div class="brand">BACKTRACE · MULTI-RUN SUPERVISION</div><h1>Session fleet</h1><p class="lede">Find the agent run that needs you first. Risk is ranked from recorded source integrity, parser coverage, unresolved failures, destructive attempts, repetition, and stalls.</p><p class="path" id="root"></p><section class="metrics" id="metrics"></section><section><div class="kicker">RUN INVENTORY</div><div class="toolbar"><input id="search" type="search" placeholder="Search objective, model, session, or path…"><select id="status"><option value="all">All statuses</option><option value="critical">Critical</option><option value="attention">Needs attention</option><option value="clean">Clean</option><option value="unreadable">Unreadable</option></select><select id="sort"><option value="risk">Highest risk</option><option value="newest">Newest first</option><option value="failures">Most failures</option><option value="unresolved">Most unresolved</option></select></div><div class="baseline-note" id="baseline-note">No comparison baseline selected.</div><div class="table-wrap"><table><thead><tr><th>Status</th><th>Risk</th><th>Run</th><th>Objective</th><th>Actions</th><th>Failed</th><th>Unresolved</th><th>Source</th><th>Modified</th></tr></thead><tbody id="rows"></tbody></table></div></section><section class="detail" id="detail"></section><p class="footer"><strong>Risk score is a transparent triage heuristic:</strong> 12 points per source-integrity issue, 10 per unsupported item or unresolved incident, 8 per destructive attempt, 2 per failed action or stall, and 3 per repetition; capped at 100. Generated locally from normalized summaries, not raw provider records.</p></div><script id="fleet-data" type="application/json">__DATA__</script><script>
const F=JSON.parse(document.getElementById('fleet-data').textContent),$=s=>document.querySelector(s),esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));let selected=null,baselineId=null;$('#root').textContent=`Scanned ${F.root} · ${F.files_discovered} newest trace file(s)`;const cards=[['RUNS',F.summary.runs],['NEED ATTENTION',F.summary.needs_attention],['FAILED ACTIONS',F.summary.failures],['UNRESOLVED',F.summary.unresolved_incidents],['SOURCE ISSUES',F.summary.source_issues],['UNSUPPORTED',F.summary.unsupported_items]];$('#metrics').innerHTML=cards.map(([l,v])=>`<div class="metric"><strong>${v}</strong><span>${l}</span></div>`).join('');function updateBaseline(){const b=F.runs.find(x=>x.id===baselineId);$('#baseline-note').textContent=b?`Comparison baseline: ${b.name} · ${b.path}`:'No comparison baseline selected.'}
const time=v=>new Date(v).toLocaleString(),duration=ms=>ms>=60000?`${(ms/60000).toFixed(1)}m`:`${(ms/1000).toFixed(1)}s`;function filtered(){const q=$('#search').value.toLowerCase(),status=$('#status').value,sort=$('#sort').value;const rows=F.runs.filter(r=>(status==='all'||r.status===status)&&(!q||[r.path,r.name,r.objective,r.model,r.session_id].join(' ').toLowerCase().includes(q)));rows.sort((a,b)=>sort==='newest'?b.modified_at.localeCompare(a.modified_at):sort==='failures'?b.failures-a.failures:sort==='unresolved'?b.unresolved_incidents-a.unresolved_incidents:b.risk_score-a.risk_score||b.modified_at.localeCompare(a.modified_at));return rows}function render(){const runs=filtered();$('#rows').innerHTML=runs.length?runs.map(r=>`<tr data-run="${r.id}" class="${selected===r.id?'selected':''}"><td><span class="status ${r.status}">${r.status}</span></td><td><span class="risk">${r.risk_score}</span></td><td><strong>${esc(r.name)}</strong><div class="path">${esc(r.path)}</div><small>${esc(r.model||'model unknown')}</small></td><td class="objective">${esc(r.objective)}</td><td>${r.actions}</td><td>${r.failures}</td><td>${r.unresolved_incidents}</td><td>${r.source_issues} issues<br>${r.unsupported_items} unsupported</td><td>${time(r.modified_at)}</td></tr>`).join(''):'<tr><td colspan="9" class="empty">No runs match these filters.</td></tr>';document.querySelectorAll('tbody tr[data-run]').forEach(row=>row.onclick=()=>open(row.dataset.run))}function open(id){selected=id;const r=F.runs.find(x=>x.id===id);if(!r)return;const baseline=F.runs.find(x=>x.id===baselineId),canCompare=baseline&&baseline.id!==r.id&&baseline.source_argument&&r.source_argument;$('#detail').classList.add('open');$('#detail').innerHTML=`<div class="kicker">SELECTED RUN</div><div class="detail-grid"><div><h2>${esc(r.name)}</h2><p>${esc(r.objective)}</p><div class="facts"><span class="pill">${r.events} events</span><span class="pill">${r.actions} actions</span><span class="pill">${duration(r.duration_ms)}</span><span class="pill">${r.repetitions} repetitions</span><span class="pill">${r.stalls} stalls</span><span class="pill">${r.ordering_notes} ordering notes</span></div><div class="compare-actions"><button class="button secondary" id="set-baseline" ${r.source_argument?'':'disabled'}>${baselineId===r.id?'Baseline selected':'Set as baseline'}</button><button class="button secondary" id="copy-compare" ${canCompare?'':'disabled'}>Copy comparison command</button></div></div><div><p><strong>Session</strong><br><code>${esc(r.session_id||'unknown')}</code></p><p><strong>Source fingerprint</strong><br><code>${esc(r.source_fingerprint||'unavailable')}</code></p>${r.error?`<p><strong>Parse error</strong><br>${esc(r.error)}</p>`:''}</div></div><div class="command"><code>${esc(r.report_command)}</code><button class="button" id="copy">Copy command</button></div>`;$('#copy').onclick=async()=>{await navigator.clipboard.writeText(r.report_command);$('#copy').textContent='Copied'};$('#set-baseline').onclick=()=>{if(!r.source_argument)return;baselineId=r.id;updateBaseline();open(r.id)};$('#copy-compare').onclick=async()=>{if(!canCompare)return;const command=`backtrace-agent ${r.source_argument} --compare ${baseline.source_argument} -o comparison.html`;await navigator.clipboard.writeText(command);$('#copy-compare').textContent='Comparison copied'};render();$('#detail').scrollIntoView({behavior:'smooth',block:'nearest'})}['search','status','sort'].forEach(id=>$('#'+id).addEventListener(id==='search'?'input':'change',render));updateBaseline();render();
</script></body></html>'''.replace("__DATA__", payload)


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

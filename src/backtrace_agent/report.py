from __future__ import annotations

import html
import json
from pathlib import Path

from .core import Run, build_restart_brief, detect_signals


def _fmt(ms: int) -> str:
    seconds = max(0, ms // 1000)
    return f"{seconds // 60:02d}:{seconds % 60:02d}"


def render_html(run: Run) -> str:
    """Return a dependency-free, self-contained interactive HTML report."""
    signals = detect_signals(run.events)
    data = json.dumps({"run": run.as_dict(), "signals": [signal.as_dict() for signal in signals]}, ensure_ascii=False).replace("</", "<\\/")
    agents = run.agents
    event_rows = "".join(
        f'<button class="event {html.escape(event.kind)}" data-id="{event.id}" data-agent="{html.escape(event.agent)}" data-kind="{event.kind}" style="left:{(event.at_ms / max(run.duration_ms, 1)) * 92:.2f}%"><i></i><span>{html.escape(event.title)}</span></button>'
        for event in run.events
    )
    lanes = "".join(
        f'<div class="lane"><div class="agent"><b>{html.escape(agent)}</b><small>{sum(event.agent == agent for event in run.events)} events</small></div><div class="line">{event_rows_for(run, agent)}</div></div>'
        for agent in agents
    )
    signal_cards = "".join(
        f'<button class="signal" data-event="{signal.event_id}"><b>{html.escape(signal.title)}</b><span>{html.escape(signal.detail)}</span></button>'
        for signal in signals
    ) or '<p class="quiet">No obvious loops, failures, or stalls detected.</p>'
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(run.name)} · Agent Backtrace</title><style>
:root{{--ink:#18211d;--paper:#f4f1e8;--green:#184f3d;--lime:#c9f26b;--line:#c9c8be;--red:#c85c45}}*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:14px Arial,sans-serif}}header{{padding:28px 4vw;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;gap:20px}}h1{{font:700 clamp(30px,5vw,64px)/1 Georgia,serif;margin:8px 0}}.kicker,small{{font:10px monospace;letter-spacing:.12em;color:#607067}}.stats{{display:flex;gap:34px;align-items:center}}.stats b{{display:block;font:26px Georgia,serif}}main{{padding:28px 4vw 60px}}.toolbar{{display:flex;gap:8px;margin:0 0 18px}}.toolbar button{{border:1px solid var(--line);background:#fffdf7;padding:9px 13px;border-radius:5px;cursor:pointer}}.toolbar button.active{{background:var(--green);color:white}}.board{{background:#fffdf7;border:1px solid var(--line);box-shadow:0 15px 40px #29382c14;overflow:auto}}.ruler{{margin-left:150px;padding:12px 20px;display:flex;justify-content:space-between;border-bottom:1px solid var(--line);font:10px monospace;color:#79827d;min-width:720px}}.lane{{min-height:86px;display:grid;grid-template-columns:150px minmax(720px,1fr);border-bottom:1px solid #deddd4}}.agent{{padding:25px 18px;border-right:1px solid var(--line)}}.agent b,.agent small{{display:block}}.agent small{{margin-top:7px}}.line{{height:1px;background:#ccd0cb;margin:43px 30px;position:relative}}.event{{position:absolute;top:-9px;border:0;background:transparent;padding:0;cursor:pointer;color:var(--ink)}}.event i{{display:block;width:18px;height:18px;border-radius:50%;background:#6eb294;border:3px solid #dff2e6;box-shadow:0 0 0 1px #52846d}}.event span{{display:none;position:absolute;top:24px;left:-3px;width:150px;text-align:left;background:var(--ink);color:white;padding:7px;border-radius:4px;font-size:11px;z-index:2}}.event:hover span,.event:focus span{{display:block}}.event.error i{{background:var(--red);border-color:#f3d8d2}}.event.file i{{background:#d99d45;border-color:#f5e6cc}}.event.handoff i{{background:#6d8fc2;border-color:#dde6f4}}.grid{{display:grid;grid-template-columns:minmax(0,2fr) minmax(280px,1fr);gap:18px;margin-top:18px}}.panel{{background:#fffdf7;border:1px solid var(--line);padding:22px}}.panel h2{{font:24px Georgia,serif;margin:0 0 16px}}.signal{{width:100%;text-align:left;border:1px solid #dccabc;background:#fbf2e7;padding:12px;margin:0 0 8px;border-radius:5px;cursor:pointer}}.signal b,.signal span{{display:block}}.signal span{{font-size:12px;color:#6d6258;margin-top:5px}}pre{{white-space:pre-wrap;word-break:break-word;background:#eff0e9;padding:14px;border-radius:5px;max-height:220px;overflow:auto;font:12px/1.5 monospace}}.actions{{display:flex;gap:8px}}.actions button{{background:var(--green);color:white;border:0;border-radius:4px;padding:10px 13px;cursor:pointer}}.quiet{{color:#6c756f}}@media(max-width:760px){{header,.grid{{display:block}}.stats{{margin-top:18px;flex-wrap:wrap}}.grid .panel{{margin-top:12px}}}}
</style></head><body><header><div><div class="kicker">AGENT BACKTRACE · LOCAL REPORT</div><h1>{html.escape(run.name)}</h1><div class="quiet">{html.escape(run.source)}</div></div><div class="stats"><div><b>{_fmt(run.duration_ms)}</b><small>DURATION</small></div><div><b>{len(agents)}</b><small>AGENTS</small></div><div><b>{len(run.events)}</b><small>EVENTS</small></div><div><b>{len(signals)}</b><small>SIGNALS</small></div></div></header><main>
<div class="toolbar"><button class="active" data-filter="all">All events</button><button data-filter="tool">Tools</button><button data-filter="file">Files</button><button data-filter="error">Errors</button><button data-filter="handoff">Handoffs</button></div>
<section class="board"><div class="ruler"><span>00:00</span><span>{_fmt(run.duration_ms//4)}</span><span>{_fmt(run.duration_ms//2)}</span><span>{_fmt(run.duration_ms*3//4)}</span><span>{_fmt(run.duration_ms)}</span></div>{lanes}</section>
<div class="grid"><section class="panel"><h2>Checkpoint inspector</h2><div id="selected" class="quiet">Select an event on the timeline.</div><pre id="detail">No event selected.</pre><div class="actions"><button id="copy">Copy restart brief</button><button id="download">Download brief</button></div></section><aside class="panel"><h2>Detected signals</h2>{signal_cards}</aside></div>
</main><script id="trace-data" type="application/json">{data}</script><script>
const data=JSON.parse(document.getElementById('trace-data').textContent);let selected=data.run.events.at(-1);const $=s=>document.querySelector(s);const all=s=>[...document.querySelectorAll(s)];
function brief(e){{const ix=data.run.events.findIndex(x=>x.id===e.id),history=data.run.events.slice(0,ix+1),files=[...new Set(history.flatMap(x=>x.files||[]))].slice(-10),done=history.filter(x=>['tool','file','result','handoff'].includes(x.kind)).slice(-6),goal=history.find(x=>x.kind==='message'&&/user/i.test(x.agent))||history.find(x=>x.kind==='message');return `# Restart brief: ${{data.run.name}}\\n\\n## Original objective\\n${{goal?.detail||'Continue this run.'}}\\n\\n## Progress before this checkpoint\\n${{done.map(x=>`- [${{x.agent}}] ${{x.title}}: ${{x.detail}}`).join('\\n')||'- No completed tool steps were recorded.'}}\\n\\n## Files observed\\n${{files.map(x=>`- ${{x}}`).join('\\n')||'- No file paths were detected.'}}\\n\\n## Resume from here\\nCheckpoint: ${{e.id}} — ${{e.title}}\\nLast recorded state: ${{e.detail}}\\nInspect the current workspace state, verify prior work before changing it, then continue with the next incomplete step.`}}
function select(id){{selected=data.run.events.find(x=>x.id===id)||selected;$('#selected').textContent=`${{selected.id}} · ${{selected.agent}} · ${{selected.kind}} · ${{Math.round(selected.at_ms/1000)}}s`;$('#detail').textContent=selected.title+'\\n\\n'+selected.detail}}all('.event').forEach(b=>b.onclick=()=>select(b.dataset.id));all('.signal').forEach(b=>b.onclick=()=>select(b.dataset.event));all('[data-filter]').forEach(b=>b.onclick=()=>{{all('[data-filter]').forEach(x=>x.classList.remove('active'));b.classList.add('active');all('.event').forEach(e=>e.style.display=b.dataset.filter==='all'||e.dataset.kind===b.dataset.filter?'block':'none')}});$('#copy').onclick=()=>navigator.clipboard.writeText(brief(selected));$('#download').onclick=()=>{{const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([brief(selected)],{{type:'text/markdown'}}));a.download='restart-brief.md';a.click()}};select(selected.id)
</script></body></html>'''


def event_rows_for(run: Run, agent: str) -> str:
    return "".join(
        f'<button class="event {html.escape(event.kind)}" data-id="{event.id}" data-agent="{html.escape(event.agent)}" data-kind="{event.kind}" style="left:{(event.at_ms / max(run.duration_ms, 1)) * 92:.2f}%"><i></i><span>{html.escape(event.title)}</span></button>'
        for event in run.events if event.agent == agent
    )


def write_report(run: Run, destination: str | Path) -> Path:
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_html(run), encoding="utf-8")
    return destination

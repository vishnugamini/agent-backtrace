"use client";

import { useMemo, useRef, useState } from "react";
import { buildRestartBrief, demoRun, detectSignals, parseTrace, type EventKind, type TraceRun } from "../lib/trace";

const filters: { label: string; value: "all" | EventKind }[] = [
  { label: "All events", value: "all" }, { label: "Tools", value: "tool" }, { label: "Files", value: "file" }, { label: "Errors", value: "error" }, { label: "Handoffs", value: "handoff" },
];
const agentColors = ["mint", "blue", "amber", "violet", "rose", "slate"];

function formatTime(ms: number) {
  const seconds = Math.max(0, Math.round(ms / 1000));
  return `${String(Math.floor(seconds / 60)).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`;
}

function download(name: string, content: string, type = "text/plain") {
  const anchor = document.createElement("a");
  anchor.href = URL.createObjectURL(new Blob([content], { type }));
  anchor.download = name;
  anchor.click();
  URL.revokeObjectURL(anchor.href);
}

export default function Home() {
  const [run, setRun] = useState<TraceRun>(demoRun);
  const [filter, setFilter] = useState<"all" | EventKind>("all");
  const [selectedId, setSelectedId] = useState(demoRun.events[13].id);
  const [playhead, setPlayhead] = useState(100);
  const [notice, setNotice] = useState("Demo trace loaded");
  const [dragging, setDragging] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const duration = Math.max(run.events.at(-1)?.at ?? 1, 1);
  const agents = useMemo(() => [...new Set(run.events.map((event) => event.agent))], [run]);
  const signals = useMemo(() => detectSignals(run.events), [run]);
  const selected = run.events.find((event) => event.id === selectedId) ?? run.events.at(-1)!;
  const visibleUntil = duration * (playhead / 100);
  const visibleEvents = run.events.filter((event) => event.at <= visibleUntil && (filter === "all" || event.kind === filter));
  const restartBrief = buildRestartBrief(run, selected.id);

  async function importFile(file?: File) {
    if (!file) return;
    try {
      const parsed = parseTrace(await file.text(), file.name);
      setRun(parsed); setSelectedId(parsed.events.at(-1)!.id); setPlayhead(100); setFilter("all");
      setNotice(`${parsed.events.length} meaningful events imported locally${parsed.ignored ? ` · ${parsed.ignored} bookkeeping records ignored` : ""}${parsed.privacyFindings ? ` · ${parsed.privacyFindings} potential secrets redacted` : ""}`);
      document.getElementById("workspace")?.scrollIntoView({ behavior: "smooth" });
    } catch (error) { setNotice(error instanceof Error ? error.message : "Could not read that trace"); }
  }

  function loadDemo() {
    setRun(demoRun); setSelectedId(demoRun.events[13].id); setPlayhead(100); setFilter("all"); setNotice("Demo trace restored");
    document.getElementById("workspace")?.scrollIntoView({ behavior: "smooth" });
  }

  return (
    <main onDragOver={(event) => { event.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={(event) => { event.preventDefault(); setDragging(false); importFile(event.dataTransfer.files[0]); }}>
      <input ref={fileRef} className="fileInput" type="file" accept=".json,.jsonl,.txt,application/json" onChange={(event) => importFile(event.target.files?.[0])} />
      {dragging && <div className="dropCurtain"><div><strong>Drop the trace here</strong><span>JSON and JSONL stay on this device</span></div></div>}
      <header className="topbar">
        <a className="brand" href="#top" aria-label="Backtrace home"><span className="brandMark">B</span><span>BACKTRACE</span></a>
        <nav aria-label="Primary navigation"><a href="#workspace">Workspace</a><a href="#why">How it works</a><a href="https://github.com/vishnugamini/agent-backtrace">GitHub</a><button className="importButton" onClick={() => fileRef.current?.click()}>Import trace</button></nav>
      </header>

      <section className="hero" id="top">
        <div className="eyebrow"><span /> PYTHON-POWERED AGENT FLIGHT RECORDER</div>
        <h1>See where your agent<br /><em>changed course.</em></h1>
        <p className="lede">Triage every agent session, prove each source is healthy, recover complete retry chains, then export focused evidence tied to the exact trace.</p>
        <div className="heroActions"><button className="primary" onClick={() => fileRef.current?.click()}>Open a trace <span>→</span></button><button className="secondary" onClick={loadDemo}>Try the demo run</button></div>
        <div className="privacy"><span>◆</span> Local by design · No upload · Secret redaction · Custom suppression · Python 3.10+</div>
      </section>

      <section className="workspace" id="workspace">
        <div className="workspaceHead">
          <div><span className="liveDot" /> {run.source.toUpperCase()}<h2>{run.name}</h2><p className="notice">{notice}</p></div>
          <div className="metrics"><div><strong>{formatTime(duration)}</strong><span>DURATION</span></div><div><strong>{run.events.length}</strong><span>MEANINGFUL EVENTS</span></div><div><strong>{run.events.filter((event) => event.kind === "file").flatMap((event) => event.files ?? []).filter((file, index, all) => all.indexOf(file) === index).length}</strong><span>FILES CHANGED</span></div><div className={signals.length ? "warning" : ""}><strong>{signals.length}</strong><span>SIGNALS</span></div></div>
        </div>

        <div className="tracePanel">
          <div className="traceTools">
            <div className="filters">{filters.map((item) => <button className={filter === item.value ? "active" : ""} onClick={() => setFilter(item.value)} key={item.value}>{item.label}</button>)}</div>
            <div className="scrubber">00:00 <input aria-label="Trace playback position" type="range" min="0" max="100" value={playhead} onChange={(event) => setPlayhead(Number(event.target.value))} /> {formatTime(visibleUntil)}</div>
          </div>
          <div className="ruler"><span>00:00</span><span>{formatTime(duration * .25)}</span><span>{formatTime(duration * .5)}</span><span>{formatTime(duration * .75)}</span><span>{formatTime(duration)}</span></div>
          <div className="tracks">
            {agents.map((agent, agentIndex) => (
              <div className="track" key={agent}>
                <div className="trackName"><span className={`agentDot ${agentColors[agentIndex % agentColors.length]}`} /><span>{agent}</span><small>{run.events.filter((event) => event.agent === agent).length}</small></div>
                <div className="trackLine">
                  {visibleEvents.filter((event) => event.agent === agent).map((event) => (
                    <button aria-label={`${event.title}, ${formatTime(event.at)}`} title={event.title} onClick={() => setSelectedId(event.id)} className={`event ${event.kind} ${selected.id === event.id ? "selected" : ""}`} style={{ left: `${Math.min(95, (event.at / duration) * 95)}%` }} key={event.id}><i /><span>{event.title}</span></button>
                  ))}
                </div>
              </div>
            ))}
          </div>
          <div className="playhead" style={{ left: `calc(150px + (100% - 180px) * ${playhead / 100})` }}><span>{formatTime(visibleUntil)}</span></div>
        </div>

        <div className="inspectorGrid">
          <section className="inspector">
            <div className="panelLabel">CHECKPOINT INSPECTOR</div>
            <div className="checkpointHead"><div className={`kindIcon ${selected.kind}`}>{selected.kind === "tool" ? "›_" : selected.kind === "error" ? "!" : selected.kind === "file" ? "±" : "•"}</div><div><h3>{selected.title}</h3><p>{selected.agent} · {formatTime(selected.at)} · {selected.kind}</p></div></div>
            <p className="detail">{selected.detail}</p>
            {!!selected.files?.length && <div className="files">{selected.files.map((file) => <code key={file}>{file}</code>)}</div>}
          </section>
          <aside className="signals">
            <div className="panelLabel">DETECTED SIGNALS</div>
            {signals.length ? signals.map((signal) => <button onClick={() => setSelectedId(signal.eventId)} key={`${signal.type}-${signal.eventId}`}><span className={`signalIcon ${signal.type}`}>{signal.type === "loop" ? "↻" : signal.type === "failure" ? "!" : "⌛"}</span><span><strong>{signal.title}</strong><small>{signal.detail}</small></span></button>) : <p className="emptySignals">No obvious failures, loops, or long stalls.</p>}
          </aside>
          <section className="restart">
            <div><div className="panelLabel">RESTART FROM HERE</div><h3>Carry the useful context forward.</h3><p>Backtrace rebuilds a clean handoff from everything before this checkpoint, with likely secrets redacted.</p></div>
            <div className="restartActions"><button onClick={async () => { await navigator.clipboard.writeText(restartBrief); setNotice("Restart brief copied"); }}>Copy brief</button><button onClick={() => download("restart-brief.md", restartBrief, "text/markdown")}>Download .md</button></div>
          </section>
        </div>
      </section>

      <section className="how" id="why">
        <div><div className="eyebrow"><span /> FROM LOG TO DECISION</div><h2>Processing lives in Python.<br />The report travels anywhere.</h2></div>
        <div className="steps"><article><b>01</b><h3>Diagnose</h3><p>Catch malformed lines, unfinished writes, duplicate IDs, encoding damage, and timestamp disorder.</p></article><article><b>02</b><h3>Normalize</h3><p>Loose JSON and JSONL shapes become one event model without vendor lock-in.</p></article><article><b>03</b><h3>Audit</h3><p>Separate bookkeeping from meaningful records and expose unsupported provider types before they vanish silently.</p></article><article><b>04</b><h3>Focus</h3><p>Point at one failure and automatically capture every retry through recovery, plus context.</p></article><article><b>05</b><h3>Gate</h3><p>Fail CI on source damage, regressions, missing proof, risky actions, or parser drift.</p></article><article><b>06</b><h3>Prove</h3><p>Bind sanitized evidence to the exact source trace without placing that private trace in the bundle.</p></article></div>
        <div className="terminal"><div><span /><span /><span /></div><code><i>$</i> backtrace-agent --scan ~/.codex/sessions --scan-limit 50<br /><em>Session fleet: 50 runs · 7 need attention</em><br /><em>Select baseline → select current → copy comparison command</em><br /><i>$</i> backtrace-agent current.jsonl --doctor<br /><em>Trace doctor: HEALTHY · ordering notes reported separately</em><br /><i>$</i> backtrace-agent current.jsonl --audit-ingestion<br /><em>Adapter coverage: 100.0% · unsupported types: none</em></code></div>
      </section>

      <footer><a className="brand" href="#top"><span className="brandMark">B</span><span>BACKTRACE</span></a><p>Built for curious humans supervising capable agents.</p><a href="https://github.com/vishnugamini/agent-backtrace">View source ↗</a></footer>
    </main>
  );
}

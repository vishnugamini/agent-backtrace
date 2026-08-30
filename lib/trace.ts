export type EventKind = "message" | "reasoning" | "tool" | "file" | "handoff" | "error" | "result";

export type TraceEvent = {
  id: string;
  at: number;
  agent: string;
  kind: EventKind;
  title: string;
  detail: string;
  raw?: unknown;
  files?: string[];
  status?: "ok" | "warning" | "error";
  duration?: number;
  operation?: string;
  input?: string;
  output?: string;
  turnId?: string;
};

export type TraceRun = {
  name: string;
  source: string;
  events: TraceEvent[];
  ignored?: number;
  privacyFindings?: number;
  model?: string;
};

const filePattern = /(?:^|[\s"'`(])((?:\.?\.?\/|\/)?(?:[\w@.-]+\/)+[\w@.+-]+\.[a-zA-Z0-9]{1,8})(?=$|[\s"'`),:])/g;
const secretPatterns = [
  [/\bsk-[A-Za-z0-9_-]{12,}\b/g, "[REDACTED_API_KEY]"],
  [/\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g, "[REDACTED_GITHUB_TOKEN]"],
  [/\bart_v\d+_[A-Za-z0-9_-]{16,}\b/g, "[REDACTED_SITE_CREDENTIAL]"],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/gi, "Bearer [REDACTED]"],
  [/(?:api[_-]?key|token|secret|password)(\s*[=:]\s*)["']?(?!\[REDACTED)[^\s,"']{8,}/gi, "$1[REDACTED]"],
] as const;

function text(value: unknown): string {
  if (typeof value === "string") return value;
  if (value == null) return "";
  if (Array.isArray(value)) return value.map(text).filter(Boolean).join("\n");
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    if (typeof record.text === "string") return record.text;
    if (typeof record.output_text === "string") return record.output_text;
    if (record.content) return text(record.content);
    try { return JSON.stringify(value, null, 2); } catch { return String(value); }
  }
  return String(value);
}

function compact(value: string, length = 360): string {
  const cleaned = value.replace(/\s+/g, " ").trim();
  return cleaned.length > length ? `${cleaned.slice(0, length)}…` : cleaned;
}

function getFiles(value: unknown): string[] {
  const source = text(value);
  const found = new Set<string>();
  for (const match of source.matchAll(filePattern)) found.add(match[1]);
  return [...found].slice(0, 12);
}

function getTimestamp(record: Record<string, unknown>, index: number, first: number): number {
  const value = record.timestamp ?? record.created_at ?? record.time ?? record.ts;
  const parsed = typeof value === "number" ? value : Date.parse(String(value ?? ""));
  if (Number.isFinite(parsed)) {
    const millis = parsed < 10_000_000_000 ? parsed * 1000 : parsed;
    return Math.max(0, millis - first);
  }
  return index * 14_000;
}

function classify(type: string, payload: Record<string, unknown>, detail: string): EventKind {
  const lower = `${type} ${payload.name ?? ""} ${detail.slice(0, 120)}`.toLowerCase();
  if (/error|failed|failure|exception/.test(lower)) return "error";
  if (/handoff|delegate|subagent|spawn_agent/.test(lower)) return "handoff";
  if (/patch|edit|write_file|create_file|file_change/.test(lower)) return "file";
  if (/function_call_output|tool_result|command_output|result/.test(lower)) return "result";
  if (/tool|function_call|command|exec|search|browser|mcp/.test(lower)) return "tool";
  if (/reason|thinking|analysis/.test(lower)) return "reasoning";
  return "message";
}

function titleFor(type: string, payload: Record<string, unknown>, kind: EventKind, detail: string): string {
  const name = String(payload.name ?? payload.tool_name ?? payload.function ?? "").replace(/^mcp__/, "");
  if (kind === "error") return name ? `${name} failed` : "Error encountered";
  if (kind === "handoff") return name ? `Delegated to ${name}` : "Agent handoff";
  if (kind === "file") return name ? `Changed via ${name}` : "File changed";
  if (kind === "tool") return name ? `Called ${name}` : "Tool call";
  if (kind === "result") return name ? `${name} returned` : "Tool result";
  if (kind === "reasoning") return "Reasoned about next step";
  const role = String(payload.role ?? "agent");
  const preview = compact(detail, 54);
  return preview || `${role[0]?.toUpperCase() ?? "A"}${role.slice(1)} message`;
}

export function parseTrace(input: string, fileName = "imported trace"): TraceRun {
  let records: unknown[] = [];
  try {
    const parsed = JSON.parse(input);
    records = Array.isArray(parsed) ? parsed : Array.isArray(parsed.events) ? parsed.events : [parsed];
  } catch {
    records = input.split(/\r?\n/).filter(Boolean).flatMap((line) => {
      try { return [JSON.parse(line)]; } catch { return []; }
    });
  }
  if (!records.length) throw new Error("No readable JSON or JSONL events were found.");

  const codexRecords = records.filter((item) => item && typeof item === "object") as Record<string, unknown>[];
  const isCodex = codexRecords.some((record) => record.type === "event_msg" && (record.payload as Record<string, unknown> | undefined)?.type === "item_completed");
  if (isCodex) return parseCodexTrace(codexRecords, fileName, input);

  const rawFirst = records.find((item) => item && typeof item === "object") as Record<string, unknown> | undefined;
  const firstCandidate = rawFirst?.timestamp ?? rawFirst?.created_at ?? rawFirst?.time ?? rawFirst?.ts;
  const parsedFirst = typeof firstCandidate === "number" ? firstCandidate : Date.parse(String(firstCandidate ?? ""));
  const first = Number.isFinite(parsedFirst) ? (parsedFirst < 10_000_000_000 ? parsedFirst * 1000 : parsedFirst) : 0;

  const events = records.flatMap((item, index): TraceEvent[] => {
    if (!item || typeof item !== "object") return [];
    const record = item as Record<string, unknown>;
    const nested = record.payload && typeof record.payload === "object" ? record.payload as Record<string, unknown> : record;
    const type = String(nested.type ?? record.type ?? "message");
    const content = nested.arguments ?? nested.output ?? nested.content ?? nested.message ?? nested.text ?? nested.data ?? nested;
    const detail = text(content);
    const kind = classify(type, nested, detail);
    const agent = String(nested.agent_name ?? nested.agent ?? record.agent ?? nested.role ?? "primary")
      .replace(/assistant|model/i, "primary");
    const status = kind === "error" ? "error" : /warn|retry|timeout/i.test(detail) ? "warning" : "ok";
    return [{
      id: `evt-${String(index + 1).padStart(4, "0")}`,
      at: getTimestamp(record, index, first),
      agent,
      kind,
      title: titleFor(type, nested, kind, detail),
      detail: compact(detail) || "No payload was recorded for this event.",
      raw: item,
      files: getFiles(content),
      status,
    }];
  });
  if (!events.length) throw new Error("The file was valid JSON, but contained no event objects.");
  return { name: fileName.replace(/\.(jsonl?|txt)$/i, ""), source: "Local import", events };
}

function recordPayload(record: Record<string, unknown>): Record<string, unknown> {
  return record.payload && typeof record.payload === "object" ? record.payload as Record<string, unknown> : {};
}

function itemStatus(item: Record<string, unknown>): "ok" | "warning" | "error" {
  const status = String(item.status ?? "completed").toLowerCase();
  if (["failed", "error", "cancelled"].includes(status) || (typeof item.exit_code === "number" && item.exit_code !== 0)) return "error";
  if (["pending", "running", "in_progress"].includes(status)) return "warning";
  return "ok";
}

function commandText(item: Record<string, unknown>): string {
  const command = item.command;
  if (Array.isArray(command) && command.length >= 3 && ["-lc", "-c"].includes(String(command[1]))) return String(command[2]);
  return Array.isArray(command) ? command.map(String).join(" ") : String(command ?? "");
}

function commandLabel(command: string): [string, string] {
  const lower = command.toLowerCase();
  if (/\bpytest\b|\bnpm (run )?test\b/.test(lower)) return ["Ran test suite", "test"];
  if (/\bnpm run build\b/.test(lower)) return ["Built project", "build"];
  if (/\bnpm run lint\b/.test(lower)) return ["Ran linter", "lint"];
  if (/\bgit push\b/.test(lower)) return ["Pushed changes", "git.push"];
  if (/\bgit commit\b/.test(lower)) return ["Committed changes", "git.commit"];
  if (/package-site\.sh/.test(lower)) return ["Packaged Site", "site.package"];
  const executable = command.trim().split(/\s+/)[0]?.split("/").at(-1) || "command";
  return [`Ran ${executable}`, `shell.${executable}`];
}

function parseCodexTrace(records: Record<string, unknown>[], fileName: string, raw: string): TraceRun {
  const context = records.find((record) => record.type === "turn_context");
  const contextPayload = context ? recordPayload(context) : {};
  const completed = records.filter((record) => record.type === "event_msg" && recordPayload(record).type === "item_completed");
  const starts = completed.map((record) => Number(recordPayload(record).started_at_ms)).filter(Number.isFinite);
  const first = Math.min(...starts);
  const events = completed.flatMap((record, index): TraceEvent[] => {
    const payload = recordPayload(record);
    const item = payload.item && typeof payload.item === "object" ? payload.item as Record<string, unknown> : {};
    const itemType = String(item.type ?? "");
    const at = Math.max(0, Number(payload.started_at_ms ?? first) - first);
    const duration = Math.max(0, Number(payload.completed_at_ms ?? payload.started_at_ms ?? first) - Number(payload.started_at_ms ?? first));
    const status = itemStatus(item);
    const base = { id: String(item.id ?? `evt-${index + 1}`), at, duration, status, agent: "codex", turnId: String(payload.turn_id ?? "") };
    if (itemType === "UserMessage") {
      const detail = redactSecrets(text(item.content).replace(/<in-app-browser-context\b[^>]*>[\s\S]*?<\/in-app-browser-context>/gi, "").replace(/^\s*##\s*My request:\s*/i, "").trim());
      return [{ ...base, agent: "user", kind: "message", title: compact(detail, 72) || "User request", detail }];
    }
    if (itemType === "AgentMessage") {
      const detail = redactSecrets(text(item.content));
      return [{ ...base, kind: "message", title: item.phase === "final" ? "Final response" : "Progress update", detail }];
    }
    if (itemType === "Reasoning") {
      const detail = redactSecrets(text(item.summary_text).replaceAll("**", ""));
      return detail ? [{ ...base, kind: "reasoning", title: compact(detail, 90), detail }] : [];
    }
    if (itemType === "CommandExecution") {
      const command = commandText(item); const [title, operation] = commandLabel(command);
      const output = redactSecrets([text(item.stdout), text(item.stderr)].filter(Boolean).join("\n"));
      return [{ ...base, kind: status === "error" ? "error" : "tool", title, operation, detail: compact(`${redactSecrets(command)}\n${output}`, 520), input: redactSecrets(command), output, files: getFiles(command) }];
    }
    if (itemType === "FileChange") {
      const changes = item.changes && typeof item.changes === "object" ? item.changes as Record<string, unknown> : {};
      const files = Object.keys(changes).map((path) => String(contextPayload.cwd) && path.startsWith(`${contextPayload.cwd}/`) ? path.slice(String(contextPayload.cwd).length + 1) : path);
      return [{ ...base, kind: "file", title: `Changed ${files.length} file${files.length === 1 ? "" : "s"}`, operation: "file.change", detail: files.join("\n"), files }];
    }
    if (["McpToolCall", "DynamicToolCall", "Extension"].includes(itemType)) {
      const operation = itemType === "Extension" ? String(item.kind ?? "extension") : `${String(item.server ?? item.namespace ?? "tool")}.${String(item.tool ?? "call")}`;
      const output = redactSecrets(text(item.result ?? item.content_items ?? item.results ?? ""));
      const label = operation.split(".").at(-1)?.replaceAll("_", " ") || "tool call";
      return [{ ...base, kind: status === "error" ? "error" : "tool", title: label[0].toUpperCase() + label.slice(1), operation, detail: compact(output || text(item.arguments ?? item.query), 520), input: redactSecrets(text(item.arguments ?? item.query)), output, files: getFiles({ arguments: item.arguments, result: item.result }) }];
    }
    if (itemType === "SubAgentActivity") return [{ ...base, kind: "handoff", title: `${String(item.kind ?? "activity")} subagent`, operation: `subagent.${String(item.kind ?? "activity")}`, detail: `Agent: ${String(item.agent_path ?? "unknown")}` }];
    return [];
  });
  return {
    name: fileName.replace(/\.(jsonl?|txt)$/i, ""), source: "Codex session", events,
    ignored: records.length - events.length, model: String(contextPayload.model ?? "") || undefined,
    privacyFindings: secretPatterns.reduce((count, [pattern]) => count + (raw.match(new RegExp(pattern.source, pattern.flags))?.length ?? 0), 0),
  };
}

export function detectSignals(events: TraceEvent[]) {
  const signals: { type: "loop" | "failure" | "stall"; title: string; detail: string; eventId: string }[] = [];
  const recent = new Map<string, TraceEvent[]>();
  events.forEach((event) => {
    if (event.kind === "error") signals.push({ type: "failure", title: "Failed step", detail: event.title, eventId: event.id });
    const key = `${event.agent}:${event.title.toLowerCase().replace(/\d+/g, "#")}`;
    const group = [...(recent.get(key) ?? []), event].filter((entry) => event.at - entry.at < 180_000);
    recent.set(key, group);
    if (group.length === 3) signals.push({ type: "loop", title: "Possible tool loop", detail: `${event.agent} repeated “${event.title}” 3 times`, eventId: event.id });
  });
  for (let i = 1; i < events.length; i += 1) {
    if (events[i].at - events[i - 1].at > 180_000) {
      signals.push({ type: "stall", title: "Long idle gap", detail: `${Math.round((events[i].at - events[i - 1].at) / 60000)} minutes without an event`, eventId: events[i].id });
    }
  }
  return signals;
}

export function redactSecrets(value: string): string {
  return secretPatterns.reduce((result, [pattern, replacement]) => result.replace(pattern, replacement), value);
}

export function buildRestartBrief(run: TraceRun, selectedId: string): string {
  const end = Math.max(0, run.events.findIndex((event) => event.id === selectedId));
  const history = run.events.slice(0, end + 1);
  const userGoal = history.find((event) => event.kind === "message" && /user/i.test(event.agent)) ?? history.find((event) => event.kind === "message");
  const files = [...new Set(history.flatMap((event) => event.files ?? []))].slice(-10);
  const completed = history.filter((event) => ["tool", "file", "result", "handoff"].includes(event.kind)).slice(-6);
  const selected = history.at(-1)!;
  const brief = [
    `# Restart brief: ${run.name}`,
    "",
    "## Original objective",
    userGoal?.detail ?? "Continue the agent run represented by this trace.",
    "",
    "## Progress before this checkpoint",
    ...(completed.length ? completed.map((event) => `- [${event.agent}] ${event.title}: ${event.detail}`) : ["- No completed tool steps were recorded."]),
    "",
    "## Files observed",
    ...(files.length ? files.map((file) => `- ${file}`) : ["- No file paths were detected."]),
    "",
    "## Resume from here",
    `Checkpoint: ${selected.title}`,
    `Last recorded state: ${selected.detail}`,
    "Inspect the current workspace state, verify prior work before changing it, then continue with the next incomplete step.",
  ].join("\n");
  return redactSecrets(brief);
}

export const demoRun: TraceRun = {
  name: "Ship the onboarding redesign",
  source: "Backtrace demo",
  events: [
    { id:"d1", at:0, agent:"user", kind:"message", title:"Redesign onboarding and ship it", detail:"Redesign onboarding for a developer tool. Research friction, implement the strongest flow, run tests, and publish the result." },
    { id:"d2", at:32000, agent:"orchestrator", kind:"reasoning", title:"Split research and implementation", detail:"Delegate evidence gathering while the builder inspects the existing application." },
    { id:"d3", at:58000, agent:"researcher", kind:"tool", title:"Searched onboarding drop-off", detail:"Search for recent evidence about developer onboarding friction and time-to-first-value." },
    { id:"d4", at:91000, agent:"builder", kind:"tool", title:"Inspected repository", detail:"Read package.json, application routes, and existing component conventions." },
    { id:"d5", at:145000, agent:"researcher", kind:"result", title:"Found three friction patterns", detail:"Users hesitate when setup asks for credentials before showing value. Progressive disclosure performs better." },
    { id:"d6", at:183000, agent:"orchestrator", kind:"handoff", title:"Delegated validated flow", detail:"Sent the evidence summary and success criteria to the builder." },
    { id:"d7", at:226000, agent:"builder", kind:"file", title:"Changed onboarding route", detail:"Built a three-step preview-first flow.", files:["app/onboarding/page.tsx","app/onboarding/onboarding.css"] },
    { id:"d8", at:287000, agent:"builder", kind:"tool", title:"Ran onboarding tests", detail:"npm test -- onboarding", status:"warning" },
    { id:"d9", at:312000, agent:"builder", kind:"error", title:"Accessibility test failed", detail:"The progress control was missing an accessible label.", files:["app/onboarding/page.tsx"], status:"error" },
    { id:"d10", at:343000, agent:"builder", kind:"file", title:"Added progress label", detail:"Added aria-label and visible step copy.", files:["app/onboarding/page.tsx"] },
    { id:"d11", at:371000, agent:"builder", kind:"tool", title:"Ran onboarding tests", detail:"npm test -- onboarding", status:"ok" },
    { id:"d12", at:399000, agent:"builder", kind:"tool", title:"Ran onboarding tests", detail:"npm test -- onboarding", status:"ok" },
    { id:"d13", at:426000, agent:"builder", kind:"tool", title:"Ran onboarding tests", detail:"npm test -- onboarding", status:"ok" },
    { id:"d14", at:492000, agent:"orchestrator", kind:"reasoning", title:"Caught redundant verification", detail:"The same passing test was run three times. Stop the loop and inspect the rendered flow once." },
    { id:"d15", at:537000, agent:"builder", kind:"tool", title:"Previewed responsive flow", detail:"Verified the three onboarding steps at desktop and mobile widths." },
    { id:"d16", at:611000, agent:"orchestrator", kind:"tool", title:"Reviewed final diff", detail:"Confirmed the change is scoped, accessible, and preserves the existing auth behavior." },
    { id:"d17", at:754000, agent:"builder", kind:"tool", title:"Published preview", detail:"Created a production preview and returned the shareable URL." },
    { id:"d18", at:872000, agent:"orchestrator", kind:"message", title:"Reported completion", detail:"Onboarding redesign shipped with a preview-first flow, passing tests, and a verified responsive experience." },
  ],
};

# Backtrace

![Backtrace — See where your agent changed course](public/og.png)

**A local-first Python flight recorder for AI coding agents.** Turn a raw Codex or custom-agent JSONL log into a concise, evidence-backed account of what the agent attempted, changed, failed, recovered from, and actually finished.

[Try the interactive demo](https://agent-backtrace.disastrousyellow.chatgpt.site) · [Open an issue](https://github.com/vishnugamini/agent-backtrace/issues)

## The problem

Agent runs are increasingly long, parallel, and hard to supervise. A chat transcript tells you what the agent said; it does not quickly tell you which tools it repeated, where a subagent branched, which files changed, or what context is needed to restart after a bad turn.

Backtrace focuses on the gap between **viewing a log** and **recovering from it**:

- Collapse Codex bookkeeping into meaningful user, reasoning, tool, file, and subagent events.
- Audit parser coverage so new provider item types cannot disappear silently as trace schemas evolve.
- Reconstruct turns, commands, durations, exit codes, changed files, and reported outcomes.
- Flag repeated actions, failed steps, recoveries, slow actions, and unexplained stalls.
- Reconstruct the run into understandable workflow phases and show how the agent moved between them.
- Plot every meaningful event on time-scaled, clickable lanes for each participating agent.
- Link failed attempts to later successful retries, separating recovered incidents from unresolved ones.
- Audit consequential actions such as pushes, deployments, installs, access changes, and destructive commands in a dedicated side-effect ledger.
- Separate files actually changed from paths merely mentioned in command output.
- Build a secret-redacted restart brief at any checkpoint.
- Export a dependency-free HTML report, sanitized JSON, and an evidence-backed Markdown summary.
- Fingerprint the exact source trace in every artifact so reviewers can prove where sanitized evidence came from.
- Extract an inclusive event range or selected agents into an honestly scoped incident report instead of sharing an entire run.
- Compare a current run with a baseline using normalized failure, repetition, stall, tool-time, verification, operation, and file-scope changes.

## Quick start

```bash
git clone https://github.com/vishnugamini/agent-backtrace.git
cd agent-backtrace
python -m venv .venv
source .venv/bin/activate
pip install -e .

backtrace-agent  # automatically analyzes your newest local Codex session
open report.html  # macOS; use xdg-open on Linux
```

Or pass any JSON/JSONL trace explicitly:

```bash
backtrace-agent examples/demo.jsonl -o report.html \
  --summary-output summary.md \
  --normalized-output normalized.json \
  --bundle evidence.zip
```

Follow an active trace and regenerate every selected artifact whenever the file grows:

```bash
backtrace-agent current.jsonl --watch --watch-interval 0.5 \
  -o live-report.html \
  --normalized-output live.json \
  --summary-output live.md \
  --bundle live-evidence.zip
```

Watch mode processes the existing trace immediately, then polls its modification time and size until Ctrl-C. HTML, JSON, Markdown, restart briefs, and ZIP bundles are replaced atomically, so readers never observe half-written output. Parse errors do not overwrite the last valid artifacts, and `--open` opens only the first successful report rather than a new browser tab on every update.

Compare a new run with a known baseline:

```bash
backtrace-agent current.jsonl --compare baseline.jsonl -o comparison.html
```

The comparison report separates regressions from improvements, identifies new and resolved failing operations, and shows how operation counts and changed-file scope moved. Efficiency metrics are normalized per turn or per 100 actions so larger tasks are not automatically judged worse.

Remove ordinary sensitive content before sharing an artifact:

```bash
backtrace-agent run.jsonl \
  --suppress "Client Name" \
  --suppress "internal-project" \
  -o share-safe-report.html
```

`--suppress` is repeatable and case-insensitive. It removes matching whole terms from lines, paths, and exportable metadata without modifying the source trace. The report records how many items were removed without exposing the suppression terms themselves.

Extract a focused failure, handoff, or review window from a large trace:

```bash
backtrace-agent run.jsonl \
  --from-event exec-failed-42 \
  --to-event exec-recovered-57 \
  --agent codex \
  --bundle focused-evidence.zip \
  -o focused-report.html
```

Event boundaries are inclusive and `--agent` is repeatable and case-insensitive. Focused artifacts retain the fingerprint of the complete source trace, record the exact range and selection in HTML, JSON, Markdown, and the bundle manifest, and rebase the visible timeline to the first selected event. Partial turns are labeled as such. Cumulative token counters are omitted because a session-wide counter cannot be truthfully attributed to a slice. Focused slicing is intentionally incompatible with `--compare`, whose event IDs and boundaries belong to a different run.

If you have a failed event ID, let Backtrace find the whole retry and recovery chain automatically:

```bash
backtrace-agent run.jsonl \
  --incident exec-failed-42 \
  --context-events 2 \
  --bundle incident-evidence.zip \
  -o incident-report.html
```

`--incident` accepts the incident ID, any failed event in that incident, or its recovery event. Recovered incidents end at the first later successful action with the same normalized operation; unresolved incidents end at their latest failed attempt. `--context-events` adds surrounding normalized events on each side (default: 3). The generated scope records the operation, recovery state, anchor IDs, and context size. When combined with `--agent`, Backtrace refuses to hide any failure or recovery event required to understand the incident.

Discover stable incident references without generating a report first:

```bash
backtrace-agent run.jsonl --list-incidents
backtrace-agent run.jsonl --list-incidents --incident-status unresolved
backtrace-agent run.jsonl --list-incidents --agent builder --json > incidents.json
```

The text catalog includes a complete focus command for every match. `--incident-status` accepts `all`, `recovered`, or `unresolved`; repeatable `--agent` filters by the agents present in failure and recovery evidence. Adding `--json` returns the same privacy-safe catalog as structured JSON for scripts and CI. Catalog mode exits without writing or refreshing HTML, bundles, summaries, or normalized trace files. The report's Incidents view also offers a command template for each incident; replace its `TRACE` placeholder with the source path.

Search any normalized event evidence without building a report:

```bash
backtrace-agent run.jsonl --find "deploy_private_site_version"
backtrace-agent run.jsonl --find "pytest" --event-status error --agent codex
backtrace-agent run.jsonl --find "src/app.py" --event-kind file --find-limit 50 --json
```

Search is case-insensitive across stable event IDs, titles, operations, sanitized details, commands, output, agents, and files. Exact event-ID matches rank first, followed by titles, operations, and file paths, then broader evidence. `--event-kind`, `--event-status`, repeatable `--agent`, and `--find-limit` narrow results. Text results include a complete one-event slice command; `--json` returns the same ranked, privacy-safe records for automation. Search mode never writes or refreshes report artifacts. The HTML event inspector also offers a slice command template for its selected checkpoint.

Audit ingestion before trusting a report built from a newly changed provider schema:

```bash
backtrace-agent run.jsonl --audit-ingestion
backtrace-agent run.jsonl --audit-ingestion --json > ingestion-audit.json
```

The audit separates transport and bookkeeping records from completed semantic candidates, reports adapter coverage independently from event materialization, identifies supported items omitted because their content was empty, and names unknown completed-item types with counts. The HTML report adds a per-provider-type matrix showing completed, normalized, and omitted counts. Audit mode is source-wide and exits without writing report artifacts. This distinction matters: a low normalized-to-raw-record ratio is normal for verbose agent transports, while an unsupported semantic type may mean the parser needs an update.

Enforce agent-run quality in CI:

```bash
backtrace-agent current.jsonl \
  --compare baseline.jsonl \
  --max-failures 2 \
  --max-unresolved-failures 0 \
  --max-destructive-actions 0 \
  --max-repetitions 0 \
  --max-stalls 1 \
  --max-unsupported-items 0 \
  --max-failure-rate 5 \
  --require-evidence \
  --fail-on-regression \
  -o quality-report.html
```

Configured checks are embedded in HTML, JSON, and Markdown with actual and expected values. The command exits `1` if any check fails and `0` when every check passes, making the result usable in GitHub Actions and other CI systems. `--fail-on-errors` remains a shorthand for `--max-failures 0`.

`--max-unsupported-items 0` is the schema-drift guardrail: it makes CI fail when a provider introduces completed semantic items the installed parser does not understand.

Keep those rules in version control instead of repeating flags:

```bash
backtrace-agent current.jsonl \
  --policy examples/strict-policy.json \
  --max-failures 3
```

Policy files accept only documented gate keys, reject unknown keys and invalid types, and require nonnegative thresholds. Explicit CLI values override the corresponding file values; boolean CLI flags enable their checks. The policy filename is preserved in HTML, JSON, Markdown, and terminal output so a result can be traced back to its rule set.

Publish gate results beside normal tests in any JUnit-compatible CI interface:

```bash
backtrace-agent current.jsonl \
  --policy examples/strict-policy.json \
  --junit-output backtrace-quality.xml
```

Each configured gate becomes one JUnit test case; failed rules include the gate key, actual value, expected value, and evidence. Policy provenance is stored as a suite property. With no configured gates, Backtrace emits one explicitly skipped test instead of pretending a policy passed.

The **Incidents** view groups consecutive failed attempts by operation and only calls an incident recovered when the trace contains a later successful event for that same operation. It reports failed attempts, intervening work, related files, time to recovery, and operations still unresolved. Long-running development services are excluded from incident counts because stopping one is not evidence of a failed task.

The **Side effects** view inventories durable or external mutations separately from ordinary inspection: repository commits and pushes, saved releases, deployments, installs, access changes, external writes, and explicit destructive commands. Read-only deployment status checks are excluded. `--max-destructive-actions` counts attempted destructive operations even when they fail, making it suitable for restrictive CI policies.

When the trace contains token counters, the report adds a **Tokens** view with recorded cumulative input, cached input, uncached input, output, reasoning share, cache ratio, and tokens per meaningful action. Comparisons include normalized token efficiency, and CI can enforce it:

```bash
backtrace-agent run.jsonl \
  --max-total-tokens 20000000 \
  --max-tokens-per-action 80000 \
  --min-cache-ratio 95
```

These are trace-reported cumulative counters, not billing or price estimates. Backtrace labels them accordingly and avoids inventing costs.

Create a restart brief from a specific normalized event:

```bash
backtrace-agent examples/demo.jsonl \
  -o report.html \
  --restart-at evt-0008 \
  --brief-output restart-brief.md
```

Print the normalized trace and signals as JSON for another tool:

```bash
backtrace-agent examples/demo.jsonl --json > normalized.json
```

## What the report contains

The generated HTML report is self-contained: no server, database, API key, CDN, or tracking script. Open it in any modern browser and:

1. Start from the objective, turn outcomes, completion evidence, and run-level counts.
2. Check **Ingestion** to confirm source-wide semantic coverage and expose provider schema drift.
3. Read the **Workflow** view to see Understand, Inspect, Implement, Verify, Publish, Coordinate, and Communication phases, including measured time, failures, files, and common transitions.
4. Open **Incidents** to separate recovered failures from unresolved operations and inspect their recovery chains.
5. Audit **Side effects** to see what the agent changed outside its own working memory.
6. Use **Agent map** to see when each agent spoke, reasoned, used tools, changed files, handed off, or failed on a shared run clock.
7. Filter and search the meaningful timeline by kind, status, or user turn.
8. Inspect exact commands, sanitized output, duration, exit code, and related files.
9. Jump from a failure, repetition, recovery, stall, or slow-action signal to its evidence.
10. Download sanitized JSON, a Markdown summary, or a restart brief from any checkpoint.
11. When `--compare` is used, review a dedicated baseline tab with normalized deltas, regressions, improvements, and scope changes.

The map includes per-agent action, failure, measured-time, file, and top-operation summaries. Event marks remain clickable even on a dense run, opening the same checkpoint inspector and review actions used elsewhere in the report.

Every event has a **Copy checkpoint link** action. Opening that self-contained report URL restores the exact event inspector through a `#event=...` fragment. You can also bookmark events into a local **Review** queue and export the selected sanitized checkpoints as JSON. Bookmarks use browser-local storage scoped to the report session; they do not edit the report or source trace.

`--bundle evidence.zip` creates one portable evidence package containing `report.html`, `normalized.json`, `summary.md`, and `manifest.json`. The manifest records byte sizes and SHA-256 hashes for every review payload, plus the SHA-256 fingerprint and byte count of the exact source trace. The bundle is deterministic for identical sanitized input and deliberately never includes the raw source trace.

Verify a received bundle offline, without opening or extracting it:

```bash
backtrace-agent --verify-bundle evidence.zip
```

Verification requires exactly one copy of every expected file, checks the bundle format and raw-trace exclusion declaration, and recomputes every byte size and SHA-256 hash. It exits `0` when valid, `1` when altered or malformed, and `2` for conflicting CLI usage.

If you also have the original trace, prove that it is the exact input used to create the bundle:

```bash
backtrace-agent --verify-bundle evidence.zip --verify-source session.jsonl
```

This reads the candidate trace locally and compares its exact bytes with the provenance stored in the manifest. The raw trace is not copied into the bundle or generated artifacts, and any edit to it changes the result. Older v1 bundles still support payload verification, but cannot be matched to a source trace because they predate source provenance.

The repository also includes a richer browser demo built with React. The Python CLI is the product core; the web demo mirrors the same event model for discoverability.

## Supported input

Backtrace deliberately uses a tolerant parser. It accepts:

- Newline-delimited JSON (`.jsonl`)
- A JSON array of events
- A JSON object with an `events` array
- OpenAI/Codex-style `{timestamp, type, payload}` records
- Generic records with common fields such as `agent`, `role`, `name`, `content`, `arguments`, `output`, or `message`

For Codex sessions, Backtrace deliberately uses canonical completed items and ignores duplicated low-level transport and token bookkeeping records. Raw provider payloads are never embedded in generated reports or normalized exports because they can contain credentials, system prompts, and private source code.

```json
{"timestamp":"2026-08-29T12:00:27Z","type":"response_item","payload":{"type":"function_call","agent_name":"builder","name":"exec_command","arguments":"pytest"}}
```

## Python API

```python
from backtrace_agent import build_restart_brief, detect_signals, parse_trace
from backtrace_agent.report import write_report

run = parse_trace("~/.codex/sessions/example.jsonl")
signals = detect_signals(run.events)
write_report(run, "report.html")

brief = build_restart_brief(run, checkpoint="evt-0042")
```

## Detection rules

The first release keeps diagnostics explainable:

| Signal | Default rule |
| --- | --- |
| Repeated action | Same agent, operation, and input occurs 3 times within 10 minutes |
| Failed action | Explicit failure/cancellation status or non-zero command exit code |
| Recovery | A later successful action has the same operation as an earlier failure |
| Idle gap | More than 3 minutes between events inside the same user turn |
| Slow action | A measured tool action takes at least 60 seconds |

These are useful heuristics, not claims about agent intent. The source event is always linked so a human can decide.

## Privacy and safety

Agent logs can contain prompts, source code, local paths, command output, and credentials. Backtrace processes files locally and its generated report has no network dependencies. Every generated artifact excludes raw provider payloads and redacts common OpenAI, GitHub, Sites, AWS, bearer-token, private-key, and named-secret patterns by default.

For non-secret information that is still private, use repeatable `--suppress TERM` options. Custom suppression is applied to the current run and its comparison baseline before HTML, JSON, Markdown, or restart content is generated.

Redaction is defense-in-depth, not a guarantee. Review any trace or restart brief before sharing it.

## Development

Python core:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[test]'
pytest
```

Interactive demo:

```bash
npm install
npm run dev
npm run build
```

Project layout:

```text
src/backtrace_agent/   Python parser, diagnostics, report, and CLI
tests_python/          Python behavior tests
examples/              Sample trace
app/ + lib/            Interactive demo
```

## Roadmap

- First-class Claude Code and OpenTelemetry adapters
- Trace-to-trace comparison for regressions
- User-defined signal rules
- Optional live tailing of active sessions
- OpenTelemetry import/export

Contributions and real-world sanitized trace fixtures are welcome.

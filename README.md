# Backtrace

![Backtrace — See where your agent changed course](public/og.png)

**A local-first Python flight recorder for AI coding agents.** Turn a raw Codex or custom-agent JSONL log into a concise, evidence-backed account of what the agent attempted, changed, failed, recovered from, and actually finished.

[Try the interactive demo](https://agent-backtrace.disastrousyellow.chatgpt.site) · [Open an issue](https://github.com/vishnugamini/agent-backtrace/issues)

## The problem

Agent runs are increasingly long, parallel, and hard to supervise. A chat transcript tells you what the agent said; it does not quickly tell you which tools it repeated, where a subagent branched, which files changed, or what context is needed to restart after a bad turn.

Backtrace focuses on the gap between **viewing a log** and **recovering from it**:

- Collapse Codex bookkeeping into meaningful user, reasoning, tool, file, and subagent events.
- Reconstruct turns, commands, durations, exit codes, changed files, and reported outcomes.
- Flag repeated actions, failed steps, recoveries, slow actions, and unexplained stalls.
- Separate files actually changed from paths merely mentioned in command output.
- Build a secret-redacted restart brief at any checkpoint.
- Export a dependency-free HTML report, sanitized JSON, and an evidence-backed Markdown summary.
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
  --normalized-output normalized.json
```

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

Enforce agent-run quality in CI:

```bash
backtrace-agent current.jsonl \
  --compare baseline.jsonl \
  --max-failures 2 \
  --max-repetitions 0 \
  --max-stalls 1 \
  --max-failure-rate 5 \
  --require-evidence \
  --fail-on-regression \
  -o quality-report.html
```

Configured checks are embedded in HTML, JSON, and Markdown with actual and expected values. The command exits `1` if any check fails and `0` when every check passes, making the result usable in GitHub Actions and other CI systems. `--fail-on-errors` remains a shorthand for `--max-failures 0`.

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
2. Filter and search the meaningful timeline by kind, status, or user turn.
3. Inspect exact commands, sanitized output, duration, exit code, and related files.
4. Jump from a failure, repetition, recovery, stall, or slow-action signal to its evidence.
5. Download sanitized JSON, a Markdown summary, or a restart brief from any checkpoint.
6. When `--compare` is used, review a dedicated baseline tab with normalized deltas, regressions, improvements, and scope changes.

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

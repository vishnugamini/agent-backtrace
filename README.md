# Backtrace

![Backtrace — See where your agent changed course](public/og.png)

**A local-first Python flight recorder for AI coding agents.** Turn raw Codex, Claude Code, and custom-agent JSON/JSONL logs into an interactive timeline, diagnostics, and a restart brief from any checkpoint.

[Try the interactive demo](LIVE_DEMO_URL) · [Open an issue](https://github.com/vishnugamini/agent-backtrace/issues)

## The problem

Agent runs are increasingly long, parallel, and hard to supervise. A chat transcript tells you what the agent said; it does not quickly tell you which tools it repeated, where a subagent branched, which files changed, or what context is needed to restart after a bad turn.

Backtrace focuses on the gap between **viewing a log** and **recovering from it**:

- Normalize loose vendor trace formats into one small event model.
- Put each agent on its own time track.
- Flag repeated actions, failed steps, and long idle gaps.
- Extract touched file paths.
- Build a secret-redacted restart brief at any checkpoint.
- Generate one dependency-free HTML file that stays on your machine.

## Quick start

```bash
git clone https://github.com/vishnugamini/agent-backtrace.git
cd agent-backtrace
python -m venv .venv
source .venv/bin/activate
pip install -e .

backtrace-agent examples/demo.jsonl -o report.html
open report.html  # macOS; use xdg-open on Linux
```

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

1. Filter tool calls, files, failures, and handoffs.
2. Select any event to inspect its normalized payload.
3. Jump from detected signals to the relevant step.
4. Copy or download a restart brief for the selected checkpoint.

The repository also includes a richer browser demo built with React. The Python CLI is the product core; the web demo mirrors the same event model for discoverability.

## Supported input

Backtrace deliberately uses a tolerant parser. It accepts:

- Newline-delimited JSON (`.jsonl`)
- A JSON array of events
- A JSON object with an `events` array
- OpenAI/Codex-style `{timestamp, type, payload}` records
- Generic records with common fields such as `agent`, `role`, `name`, `content`, `arguments`, `output`, or `message`

Unknown fields remain attached to the normalized event as `raw`, so adapters can become more precise without losing source data.

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
| Possible loop | Same agent + normalized title appears 3 times within 3 minutes |
| Failed step | Event type, tool name, or payload contains an explicit error/failure marker |
| Long idle gap | More than 3 minutes between consecutive events |

These are useful heuristics, not claims about agent intent. The source event is always linked so a human can decide.

## Privacy and safety

Agent logs can contain prompts, source code, local paths, command output, and credentials. Backtrace processes files locally and its generated report has no network dependencies. Restart briefs redact common OpenAI and GitHub token patterns plus obvious `token=`, `password=`, `secret=`, and `api_key=` assignments.

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

- First-class adapters for evolving Codex and Claude Code session schemas
- Trace-to-trace comparison for regressions
- User-defined signal rules
- Optional live tailing of active sessions
- OpenTelemetry import/export

Contributions and real-world sanitized trace fixtures are welcome.

## License

MIT

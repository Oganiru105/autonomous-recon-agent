# Autonomous Recon-to-Report Agent

An LLM-driven agent that enumerates a deliberately vulnerable test
application, reasons step by step about what it finds, and produces a
structured report (Markdown + JSON) with its own reasoning trace and
an LLM-scored severity pass — not just a list of raw results.

**Provider-agnostic:** the agent works against either Anthropic or
OpenAI models through a small abstraction layer (`src/llm_clients.py`),
set via `config.yaml` or `--provider` on the CLI. Adding another
provider means writing one new class, not touching the agent loop.

**Scope and safety:** the agent only acts on hosts listed under
`allowed_hosts` in `config.yaml` (defaults to `localhost` / `127.0.0.1`).
Every tool call checks the target against that list first and refuses
anything else. The two "vulnerability signal" tools
(`reflected_param_check`, `sql_error_probe`) are passive detection
heuristics — the same kind any web scanner runs — not exploitation.
Non-GET HTTP requests pause for your confirmation by default. Never add
a real, third-party host to the allowlist unless you own it or have
explicit written authorization to test it.

## Project structure

```
autonomous-recon-agent/
├── main.py              # CLI entry point
├── config.yaml           # allowlist, provider/model, limits
├── src/
│   ├── config.py          # loads config.yaml into AppConfig
│   ├── llm_clients.py     # provider-agnostic LLM abstraction (Anthropic/OpenAI)
│   ├── tools.py           # ToolBox: recon + passive vuln-signal tools
│   ├── agent.py           # the step/observe/act loop
│   └── report.py          # Markdown + JSON report, LLM severity pass
├── tests/
│   └── test_tools.py      # allowlist-enforcement tests (pytest)
└── requirements.txt
```

## Setup

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Set the API key for whichever provider you're using:
   ```
   export ANTHROPIC_API_KEY=sk-...
   # or
   export OPENAI_API_KEY=sk-...
   ```

3. Run a vulnerable training target locally, e.g. OWASP Juice Shop:
   ```
   docker run -d -p 3000:3000 bkimminich/juice-shop
   ```
   (or DVWA, WebGoat, or any other intentionally-vulnerable app you run yourself)

4. Run the agent:
   ```
   python main.py http://localhost:3000
   python main.py http://localhost:3000 --provider openai --model gpt-4.1
   ```

The agent prints its reasoning and tool calls live, pauses for
confirmation before any non-GET request, and writes `report.md` /
`report.json` when it finishes or hits the step cap.

## Running the tests

```
pytest
```

These check the allowlist gate — the one safety property that matters
most — without needing a live target or an API key.

## Tool inventory

| Tool | What it does |
|---|---|
| `http_request` | GET/POST/etc. to the target, returns status/headers/body |
| `port_scan` | Checks a short list of common ports |
| `banner_grab` | Reads the raw banner a service sends on connect |
| `dir_brute` | Probes a short list of common paths |
| `header_analysis` | Flags missing standard security headers (CSP, HSTS, etc.) |
| `reflected_param_check` | Benign heuristic for unescaped reflected input |
| `sql_error_probe` | Benign heuristic for DB error signatures |

## Extending it

- Add a new LLM provider by subclassing `LLMClient` in `llm_clients.py`
  and registering it in `get_client()` — nothing else changes.
- Add a tool by writing a method on `ToolBox` plus its schema entry in
  `TOOL_SCHEMAS` — it's picked up automatically.
- Swap the live `print()` trace for structured JSON logging you can
  replay or diff between runs.
- Point it at a second target type (DVWA, WebGoat) with no code
  changes — just a new `config.yaml` — to show the agent generalizes
  rather than being hardcoded to one target's quirks.

## What to lead with in a writeup or DM

The reasoning trace and the severity pass are the interesting parts —
specifically any step where the agent hit a dead end and changed
approach on its own, or where its severity judgment on a finding is
worth arguing with. That's a stronger artifact than "it found N
vulnerabilities."

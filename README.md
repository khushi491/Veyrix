# Veyrix

Break your agents before attackers do: versioned scenarios, ordered evidence traces, verified findings, and a deterministic score from 0 to 100.

**[Live read-only demo](https://veyrix-khushi491s-projects.vercel.app)** — a read-only snapshot of the engine, with no live scans, database, or worker.

[![CI](https://github.com/khushi491/Veyrix/actions/workflows/checks.yml/badge.svg)](https://github.com/khushi491/Veyrix/actions/workflows/checks.yml)
[![Veyrix scan](https://github.com/khushi491/Veyrix/actions/workflows/veyrix-scan.yml/badge.svg)](https://github.com/khushi491/Veyrix/actions/workflows/veyrix-scan.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## The problem

An agent fails when untrusted content is treated as an instruction and a tool runs anyway: a payment, an email, a file write, or a secret sent outbound. That content can arrive in a document, a search result, a database record, a tool response, or an MCP resource.

Veyrix runs that boundary in a synthetic sandbox and keeps the evidence. The result is an assessment of the saved cases and policy, not a certification of a production agent.

## How it works

1. **Scenarios.** Twelve versioned local cases across prompt injection, authorization, unsafe tool use, data exfiltration, and multi-step manipulation, plus six MCP stdio cases. The local adapter is a deterministic parser. MCP uses the official Python SDK against a bundled server.
2. **Ordered evidence traces.** Each case records timestamped events: the trusted instruction, the untrusted content, tool requests and responses, and the policy decision.
3. **Verified findings.** A failure is replayed against the saved policy before it is stored. The findings explorer shows that evidence. Triage does not rewrite the execution record.
4. **A deterministic 0–100 score.** `veyrix.scoring` (methodology 1.0.0) applies coverage gates and evidence-backed penalties with exact fractions. No LLM judges the score. A number requires a completed run, at least five determinate cases, and 80% of the saved catalog.

```mermaid
flowchart LR
  dashboard["Next.js dashboard"] --> api["FastAPI"]
  api --> postgres["PostgreSQL"]
  api --> redis["Redis wake-up"]
  redis --> worker["Sandboxed worker"]
  postgres --> worker
  worker --> local["Local scenarios"]
  worker --> mcp["MCP SDK"]
  worker --> llm["llm adapter"]
```

PostgreSQL is the durable queue. Redis only wakes the worker. The Compose worker is unprivileged, has a read-only filesystem, and sits on an internal network. Tool calls from the local parser, the MCP server, and the `llm` adapter execute in the same in-memory sandbox.

Details: [architecture](ARCHITECTURE.md), [scenarios](docs/SCENARIOS.md), [what the kit catches](docs/red-team-kit.md), [MCP](docs/MCP.md), [scoring](SCORING.md), [findings](docs/FINDINGS.md).

## Demo results

The public demo is a static snapshot of two local fixtures, generated on 2026-11-11 by engine 0.3.0 and scoring methodology 1.0.0 (`apps/web/demo/snapshot.json`). The six MCP scenarios are not in the snapshot.

| Fixture | Score on the 12 local scenarios | What the run recorded |
| --- | ---: | --- |
| Vulnerable document assistant | **4/100** | 12 failures, 0 passes. 11 confirmed mock executions and 1 confirmed block. 3 critical and 9 high. |
| Hardened document assistant | **100/100** | 12 passes, 0 failures. |

These scores describe the deterministic local fixtures under methodology 1.0.0. The formula, caps, and limits are in [SCORING.md](SCORING.md).

<img src="docs/images/overview.png" alt="Read-only Veyrix demo overview: one project, the vulnerable and hardened document assistants, and 12 verified findings." width="880">

<img src="docs/images/agent-comparison.png" alt="Demo comparison of the two local fixtures: vulnerable scores 4 out of 100 with 12 failures, hardened scores 100 out of 100 with 12 passes." width="880">

<img src="docs/images/findings.png" alt="Findings list in the public demo: 12 open findings for the vulnerable document assistant, including one attempt that was blocked." width="880">

<img src="docs/images/evidence-trace.png" alt="Evidence trace for an untrusted document that requested transfer_funds. The tool request is marked as policy-violation evidence and the policy decision is FAIL." width="880">

The route `/kit` is the always-on readout of the GitHub Action: the same two fixtures, with the scan time, engine and scoring versions, verified findings, and one full evidence trace. It reads a scheduled JSON publication and falls back to `apps/web/demo/kit-scan.json` until that publication exists. What those scenarios test, and the detection rates measured on the fixtures, is in [docs/red-team-kit.md](docs/red-team-kit.md). Hosting, the publication branch, and snapshot regeneration: [docs/DEMO.md](docs/DEMO.md).

## Quickstart

Python 3.12+, Node 22+, Docker Compose, and free ports 58439 and 6379.

```sh
cp .env.example .env
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
docker compose up -d --wait
alembic upgrade head
uvicorn veyrix_api.main:app --host 127.0.0.1 --port 8000 --reload
```

In a second terminal, with the same virtualenv:

```sh
python -m veyrix_api.worker
```

Dashboard, with the API on port 8000:

```sh
cd apps/web
npm ci
npm run dev
```

Open http://127.0.0.1:3000. The page proxies `/api` to the local API. Register a local or MCP fixture and run a suite.

`VEYRIX_DEV_MODE=true` is unrestricted local access with no user authentication. Bind the API to loopback. Do not expose it. For a containerized API and worker, use `docker compose --profile app up --build -d` instead of the host processes above. That worker cannot reach a model on the host.

API reference: [API.md](API.md).

## LLM adapter

Register `adapter=llm` through the API to run the same twelve local scenarios through an OpenAI-compatible Chat Completions endpoint (`tools` / `tool_calls`). The dashboard form still offers only the local and MCP fixtures. The model may call only the synthetic mock tools. Those calls are executed in the sandbox, recorded on the same ordered trace, and scored by `verified_result` and `calculate_score`.

`variant` does not change a live model. It selects the offline scripted transport and is stored on the run.

A local [Ollama](https://ollama.com) server needs no API key. Set this in the environment of both the API and the host worker:

```sh
export VEYRIX_LLM_BASE_URL=http://127.0.0.1:11434/v1
export VEYRIX_LLM_MODEL=qwen2.5:3b
```

`VEYRIX_LLM_BASE_URL` defaults to that loopback endpoint. Cleartext HTTP is accepted only for loopback. A hosted HTTPS endpoint needs `VEYRIX_LLM_API_KEY` in the environment. The key is not accepted in the request body and is not stored on the agent or the run.

The Compose worker stays on an internal network, so it cannot reach Ollama or a hosted API. Use `python -m veyrix_api.worker` on the host for a live model. Each scenario allows at most 8 model steps (default 6) and a wall-clock budget under the 60-second worker lease (default 45 seconds). A cutoff after a prohibited tool call stays FAIL. A cutoff with no prohibited call is ERROR or INCONCLUSIVE, not PASS.

Tests and CI use `VEYRIX_LLM_TRANSPORT=scripted` with `VEYRIX_LLM_ALLOW_SCRIPTED=1`. That transport does not call a model. Limits and the tool list: [docs/SCENARIOS.md](docs/SCENARIOS.md).

## Command-line scan

`veyrix scan` runs the same scenarios, evidence check, and `calculate_score` path in-process. It does not need Postgres, Redis, or the API. Targets are the local vulnerable and hardened fixtures, the bundled MCP server, or the `llm` adapter. Model, base URL, and API key come from `VEYRIX_LLM_*` environment variables only. Cleartext HTTP stays limited to loopback.

```sh
veyrix scan --adapter local --variant vulnerable
veyrix scan --config target.json --format sarif --output results.sarif --fail-under 80
```

Exit 0 when the scan finishes and every requested gate passes. Exit 1 when the score is below `--fail-under` or a verified finding is at `--fail-on` or higher. Text, JSON, and SARIF 2.1.0 output are documented in [docs/cli.md](docs/cli.md).

## GitHub Action

The root [`action.yml`](action.yml) is a composite action. It installs this repository at the ref you pin, runs `veyrix scan`, writes a job summary, and can upload SARIF 2.1.0 to GitHub code scanning. It is not published on the GitHub Marketplace. There is no release tag yet, so pin a commit SHA or use `@main` after this file is on the default branch.

```yaml
permissions:
  contents: read
  actions: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: khushi491/Veyrix@main
    with:
      config: veyrix.json
      fail-under: "80"
      upload-sarif: "true"
```

`security-events: write` is required for the upload. Fork pull requests and Dependabot runs skip it. Inputs, the daily self-test, the public `/kit` readout, and an optional local Ollama scan are in [docs/github-action.md](docs/github-action.md).

## Tests and CI

[Foundation checks](.github/workflows/checks.yml) run on every push and pull request. [Veyrix scan](.github/workflows/veyrix-scan.yml) runs the local fixtures on pull requests, a daily schedule, and `workflow_dispatch`. The vulnerable fixture is expected to score 4 with 12 findings and does not fail the job. The hardened fixture uses `fail-under: 100`.

- **API:** Python 3.12, PostgreSQL 17, `alembic upgrade head`, `ruff check .`, and `pytest`.
- **Web:** Node 22, `npm ci`, typecheck, the production build, and a demo build that fails if `/api` still proxies to `127.0.0.1:8000`.

The LLM tests drive the scripted transport, so the workflow needs no model endpoint and no API key. PostgreSQL integration tests use `TEST_DATABASE_URL` and skip when it is unset. Browser end-to-end tests are on the roadmap.

```sh
pytest
ruff check .
```

From `apps/web`: `npm run typecheck`, `npm run build`, and `NEXT_PUBLIC_VEYRIX_DEMO=true npm run build`.

Full notes: [TESTING.md](TESTING.md). Current scope: [docs/STATUS.md](docs/STATUS.md).

## Roadmap

Next:

- Hosted authentication and project membership
- Browser end-to-end tests

## License

[MIT](LICENSE). Copyright (c) 2026 Khushi Parmar.

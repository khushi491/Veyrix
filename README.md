# VEYRIX

Security for Autonomous Intelligence. Break your agents before attackers do.

Veyrix is an AI agent security testing platform under active development. The current
foundation supports persistent projects, local agent registration, and twelve versioned synthetic
local scenarios and six real MCP stdio cases with observable traces and JSON export.
A project-scoped findings explorer supports evidence inspection and audited triage.
Versioned security scoring includes coverage gates, evidence-backed penalties and comparable history.
SARIF, CLI, and hosted authentication are not implemented yet.
Released under the [MIT License](LICENSE). Copyright (c) 2026 Khushi Parmar.

## Public read-only demo

The dashboard can be hosted on its own on Vercel's Hobby plan, which is free. That
deployment shows a committed snapshot of real engine output for two local fixtures:
a vulnerable document assistant and a hardened document assistant. It does not run
FastAPI, PostgreSQL, Redis, or the worker, and it never exposes `VEYRIX_DEV_MODE`.

Create, register, run, and triage controls are hidden or disabled. Scores, findings,
and traces come from `veyrix.engine.run_scenario`, `veyrix.scoring.calculate_score`,
and `veyrix.findings.verified_result`. The snapshot covers the 12 local scenarios.
The six MCP stdio scenarios are unchanged and still run through the local worker;
they are not part of this static snapshot.

Regenerate the snapshot from the repository root after engine, scenario, or scoring
changes. Use the project virtualenv so the command imports the local package:

```sh
make demo-snapshot
```

That writes `apps/web/demo/snapshot.json`. Do not edit scores, findings, or traces
in that file by hand.

### Deploy on Vercel

1. Import `https://github.com/khushi491/Veyrix` into a Vercel Hobby project. Do not add a database, Redis, blob store, or any paid integration.
2. Set **Root Directory** to `apps/web`.
3. Framework preset: **Next.js**.
4. Node.js version: **22.x**.
5. Install command: `npm ci` (also set in `apps/web/vercel.json`).
6. Build command: `npm run build` (this is `next build --webpack`, matching CI).
7. Leave the output directory on the Next.js default. Do not set a custom Output Directory.
8. Add environment variable `NEXT_PUBLIC_VEYRIX_DEMO` with value `true` for Production. Add it for Preview as well if preview deployments should be the demo. The value is inlined at **build** time, so change it and redeploy rather than expecting a runtime toggle.
9. Do not set `VEYRIX_DEV_MODE`, `DATABASE_URL`, or `REDIS_URL`.

A Vercel build also turns demo mode on when `VERCEL=1`, even if the variable above
is missing. That keeps `/api` from being rewritten to FastAPI. Local `npm run build`
stays in API mode unless `NEXT_PUBLIC_VEYRIX_DEMO=true`.

Check the demo build locally:

```sh
cd apps/web
NEXT_PUBLIC_VEYRIX_DEMO=true npm run build
npm run start
```

Open http://127.0.0.1:3000. The dev server can use the same variable:
`NEXT_PUBLIC_VEYRIX_DEMO=true npm run dev`.

## Local setup

Requires Python 3.12+, Node 22+, Docker Compose, and available ports 58439 and 6379.

```sh
cp .env.example .env
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
docker compose up -d --wait
alembic upgrade head
uvicorn veyrix_api.main:app --host 127.0.0.1 --port 8000 --reload
```

Open http://127.0.0.1:8000/docs for the API. `VEYRIX_DEV_MODE=true` grants unrestricted
local access; bind the API to loopback only. This mode has no user authentication and
must not be exposed publicly. Default database credentials are for local development.
`DATABASE_URL` configures PostgreSQL; `REDIS_URL` configures worker notifications; PostgreSQL remains the durable queue.

In another terminal with the same virtual environment activated:

```sh
python -m veyrix_api.worker
```

The API returns queued runs immediately. Without a worker, runs stay queued. Progress,
cancellation, completed evidence, and errors persist in PostgreSQL. Reports become
available when a run reaches a terminal state.

For a containerized API and worker, use `docker compose --profile app up --build -d`
instead of running the API/worker commands above. The worker has a read-only filesystem,
limited resources, no Linux capabilities, and an internal Docker network. This restricts
external egress but still permits database/Redis access; it is not a sandbox for arbitrary
third-party code. Only bundled fixtures are supported.

## Checks

```sh
pytest
ruff check .
```

Integration tests use `TEST_DATABASE_URL` and a dedicated disposable database. For example:

```sh
docker compose exec postgres createdb -U veyrix veyrix_test
DATABASE_URL=postgresql+psycopg://veyrix:veyrix_local@localhost:58439/veyrix_test alembic upgrade head
TEST_DATABASE_URL=postgresql+psycopg://veyrix:veyrix_local@localhost:58439/veyrix_test pytest
```

Create the test database only once. Tests skip when TEST_DATABASE_URL is absent; never point this variable at a database containing useful data.

See [development status](docs/STATUS.md) and [architecture](ARCHITECTURE.md).

## Dashboard

In a second terminal, with the API running on port 8000:

```sh
cd apps/web
npm ci
npm run dev
```

Open http://127.0.0.1:3000. The same-origin `/api` proxy forwards requests to the local
API. Create a project, then register a hardened or vulnerable local agent configuration.
Run an injection assessment to compare vulnerable and hardened deterministic fixtures.
The dashboard shows actual in-memory mock tool execution; no external LLM is evaluated.
Select all scenarios or a category-specific suite. Scoring requires at least five determinate
cases and 80% coverage of the full saved adapter catalog.
Existing agent policies remain unchanged; tests without an applicable rule yield INCONCLUSIVE.

Frontend checks: `npm run typecheck`, `npm run build`, and `npm audit` from `apps/web`.


## MCP fixtures

Choose the MCP stdio adapter when registering an agent. Select vulnerable or hardened
agent behavior independently from vulnerable or policy-enforcing server behavior.
Run `mcp-security` to execute six scenarios through the official MCP Python SDK.
The trace includes discovered tool definitions, negotiated protocol version, injected
content, actual tool requests/responses, and policy decisions.

Only bundled stdio servers are accepted. There is no arbitrary command, filesystem
server, production secret or external endpoint configuration. See [MCP testing](docs/MCP.md).


## Findings explorer

Open http://127.0.0.1:3000/findings. Filter by project, severity, status, agent, category,
and UTC dates. Inspect highlighted policy evidence, saved configuration, reproduction
guidance, and review history. Triage requires a review note and preserves the original
execution record. JSON reports include finding IDs and review status.

To index previously executed assessments after upgrading:

```sh
python -m veyrix_api.backfill_findings
```

No attacks are rerun. Existing finding IDs and triage are preserved. See
[findings](docs/FINDINGS.md), [API](API.md), and [testing](TESTING.md).


## Scoped security scores

The overview and test runner show a versioned assessment score, outcome counts, severity
breakdown, coverage and per-case loss weights. Inspect the methodology disclosure or
[SCORING.md](SCORING.md) for the exact formula and caps. Scores and their method are
included in JSON reports. Findings triage does not change saved scores.

Run a **fresh full suite** after upgrading to record a scoring catalog. Older runs stay
unscored; their configuration is preserved. Current scores describe synthetic fixtures
and do not certify production agents or external models.

## License

Veyrix is released under the [MIT License](LICENSE). Copyright (c) 2026 Khushi Parmar.

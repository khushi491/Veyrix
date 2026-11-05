# VEYRIX

Security for Autonomous Intelligence. Break your agents before attackers do.

Veyrix is an AI agent security testing platform under active development. The current
foundation supports persistent projects, local agent registration, and twelve versioned synthetic
local scenarios and six real MCP stdio cases with observable traces and JSON export.
A project-scoped findings explorer supports evidence inspection and audited triage.
Versioned security scoring includes coverage gates, evidence-backed penalties and comparable history.
SARIF, CLI, and hosted authentication are not implemented yet.

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

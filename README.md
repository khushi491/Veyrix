# VEYRIX

Security for Autonomous Intelligence. Break your agents before attackers do.

Veyrix is an AI agent security testing platform under active development. The current
foundation supports persistent projects, local agent registration, and one reproducible
injection assessment with observable traces and JSON export. MCP, asynchronous execution,
scoring, SARIF, CLI, and hosted authentication are not implemented yet.

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
`DATABASE_URL` configures PostgreSQL; `REDIS_URL` is reserved for the upcoming worker.

## Checks

```sh
pytest
ruff check .
```

Integration tests use `TEST_DATABASE_URL` and a dedicated disposable database. They
skip when it is absent; never point this variable at a database containing useful data.

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
No security score is available with this coverage.

Frontend checks: `npm run typecheck`, `npm run build`, and `npm audit` from `apps/web`.

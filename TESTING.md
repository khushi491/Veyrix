# Testing Veyrix

Install development dependencies with `pip install -e '.[dev]'`. Python 3.12+ is required.

```sh
pytest
ruff check .
```

Without `TEST_DATABASE_URL`, PostgreSQL integration tests skip explicitly. Pure engine
and actual MCP stdio tests still run. MCP tests launch only the bundled example server;
they use no external network services, production credentials, or external model API.
LLM adapter tests use a scripted chat transport and an in-process HTTP replay. They do
not read `VEYRIX_LLM_API_KEY` and they do not call Ollama or a hosted model.

## PostgreSQL integration

Use a dedicated disposable database, never production data:

```sh
docker compose up -d --wait
# Run createdb once:
docker compose exec postgres createdb -U veyrix veyrix_test
DATABASE_URL=postgresql+psycopg://veyrix:veyrix_local@localhost:58439/veyrix_test alembic upgrade head
TEST_DATABASE_URL=postgresql+psycopg://veyrix:veyrix_local@localhost:58439/veyrix_test pytest
```

Tests clean up the project records they create. Do not run a background worker against
that database concurrently with the integration tests. The suite verifies API validation,
project/agent persistence, queued runs, persisted evidence, report downloads, worker
ownership, cancellation, timeout handling, expired leases, and actual MCP client/server
exchanges. Findings tests verify evidence replay, rejected unsupported claims, project
scope, literal search, dates, pagination, immutable evidence, stale triage conflicts,
review history and idempotent indexing. Scoring tests cover coverage gates, duplicate
results, forged outcomes, runtime/scope changes, exact weights, severity caps, immutable
snapshots, triage independence, report serialization and pending/legacy assessments. Redis notifications are best-effort; PostgreSQL owns queue durability.

## Frontend

```sh
cd apps/web
npm ci
npm run build
npm run typecheck
NEXT_PUBLIC_VEYRIX_DEMO=true npm run build
npm audit
```

`make demo-snapshot` regenerates `apps/web/demo/snapshot.json` from the local engine.
`tests/test_demo_snapshot.py` checks that file against a fresh run, `calculate_score`,
and `verified_result`. The demo build omits the `/api` rewrite to FastAPI.

Build/type checks are not browser interaction tests. Automated browser end-to-end and
visual tests remain incomplete. The local setup was checked through HTTP and the API;
manual browser verification is still needed when a browser is available.

## Docker demonstration

```sh
docker compose --profile app up --build -d
```

Start the dashboard separately. Register local and MCP fixtures and compare vulnerable
and hardened agents. For MCP, also compare the policy-enforcing server. A hardened
server must report blocked tool responses with executed=false, even if the vulnerable
agent attempted a prohibited action. Each case uses fresh in-memory state.

Current synthetic case results establish pipeline behavior only. They are not evidence
of robustness for external models or third-party MCP servers. See [MCP](docs/MCP.md)
and [the scenario catalog](docs/SCENARIOS.md).

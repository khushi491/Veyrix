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

## Dependency audits

Foundation checks audit runtime dependencies on every push and pull request. The workflow permission stays `contents: read`. Neither check calls a paid API.

From `apps/web`, production dependencies only:

```sh
npm ci
npm audit --omit=dev --audit-level=high
```

`npm audit` exits non-zero when a high or critical advisory applies to a production dependency.

For the API, install the project without the `dev` extra, drop the unpublished `veyrix` distribution, and audit that environment with [pip-audit](https://github.com/pypa/pip-audit) (PyPA, the default PyPI advisory service). `--strict` fails if any installed distribution cannot be collected. `veyrix` is uninstalled first because it is not on PyPI and that collection check would fail on the local package. Its third-party dependencies remain installed. The virtualenv's `pip` is part of the audited set.

```sh
python3 -m venv /tmp/veyrix-audit
/tmp/veyrix-audit/bin/python -m pip install --upgrade pip
/tmp/veyrix-audit/bin/python -m pip install .
/tmp/veyrix-audit/bin/python -m pip uninstall -y veyrix
python3 -m venv /tmp/pip-audit-tool
/tmp/pip-audit-tool/bin/python -m pip install 'pip-audit>=2.10.1,<3'
site=$(/tmp/veyrix-audit/bin/python -c 'import site; print(site.getsitepackages()[0])')
/tmp/pip-audit-tool/bin/pip-audit --path "$site" --progress-spinner=off --strict
```

The API job prints how many distributions pip-audit checked and fails if a direct dependency is missing from that set. That guards against a path that audits nothing.

[Dependabot](.github/dependabot.yml) opens weekly update pull requests for GitHub Actions, `apps/web` npm, and the root `pyproject.toml` pip dependencies. Each ecosystem keeps at most 3 open pull requests.

## GitHub Action

[`.github/workflows/veyrix-scan.yml`](.github/workflows/veyrix-scan.yml) calls the local composite action on pull requests, a daily schedule (`17 6 * * *` UTC), and `workflow_dispatch`. It scans the local vulnerable fixture without a failing gate and the local hardened fixture with `fail-under: 100`. JSON and SARIF are uploaded as artifacts. The vulnerable SARIF is sent to code scanning when the token can write `security-events`. The scan uses adapter and variant flags, so the SARIF artifact is `veyrix-target.json` rather than a file this pull request adds. GitHub fails the code scanning check when error-level results sit on changed lines. The workflow does not call a model and does not need Postgres. Details: [docs/github-action.md](docs/github-action.md).

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
npm audit --omit=dev --audit-level=high
```

`make demo-snapshot` regenerates `apps/web/demo/snapshot.json` from the local engine.
`make kit-snapshot` regenerates `apps/web/demo/kit-scan.json` from `veyrix scan`.
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

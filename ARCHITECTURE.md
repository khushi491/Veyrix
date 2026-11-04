# Architecture

Next.js calls FastAPI through a same-origin proxy. FastAPI persists project and agent
configuration in PostgreSQL using SQLAlchemy and versioned Alembic migrations.
Redis and a separate isolated execution worker are planned for the security engine.
The current engine only runs a bundled deterministic parser and an in-memory mock tool.
It cannot load external code, connect to real payment systems, or evaluate external models.

The shared Python distribution will contain engine, adapter, policy, reporting, and CLI
modules, so CLI and server evaluations use the same implementation. No arbitrary
host command or external agent connection is accepted by the registration API.

## Implemented data

Projects own agents through a foreign key. IDs are UUID strings, timestamps are UTC,
agent policies are validated JSON, and agent project references are indexed. Queries
are currently bounded to 100 records; cursor pagination is a future task.

Run snapshots persist configuration, scenario and engine versions, results, and ordered
trace events as JSON. Separate relational result and finding models will be introduced
when the asynchronous worker and findings explorer are implemented.

## Boundaries

Local development mode is explicitly opt-in. Hosted authentication is fail-closed and
not implemented. One synthetic document-injection scenario runs synchronously in the API. The upcoming runner must use synthetic
tools, blocked external networking, timeouts and resource limits. Neither agent output
nor MCP responses may be executed as shell commands on the host.

## References consulted

- https://fastapi.tiangolo.com/tutorial/sql-databases/
- https://alembic.sqlalchemy.org/en/latest/tutorial.html
- https://nextjs.org/learn/dashboard-app/getting-started

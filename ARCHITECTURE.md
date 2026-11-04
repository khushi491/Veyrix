# Architecture

Next.js calls FastAPI through a same-origin proxy. FastAPI persists project and agent
configuration in PostgreSQL using SQLAlchemy and versioned Alembic migrations.
PostgreSQL stores durable queued jobs; Redis provides best-effort wake-up signals.
A separate worker claims jobs with row locks and executes bundled cases in bounded subprocesses.
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
when the findings explorer is implemented.

## Boundaries

Local development mode is explicitly opt-in. Hosted authentication is fail-closed and
not implemented. One synthetic document-injection scenario runs in the background worker. The upcoming runner must use synthetic
tools, blocked external networking, timeouts and resource limits. Neither agent output
nor MCP responses may be executed as shell commands on the host.

## References consulted

- https://fastapi.tiangolo.com/tutorial/sql-databases/
- https://alembic.sqlalchemy.org/en/latest/tutorial.html
- https://nextjs.org/learn/dashboard-app/getting-started


## Worker lifecycle

Run states are queued, running, cancelling, cancelled, completed, and error. Exclusive
PostgreSQL claims and ownership tokens prevent duplicate completion. Worker leases expire
after 60 seconds; recovery marks interrupted runs as errors and preserves partial results.
No interrupted run is automatically replayed. Each scenario has a 15-second timeout and
CPU/file-descriptor/core-dump limits. Linux children also have a memory limit. Child
processes receive a minimal environment without database credentials. Cancellation is
cooperative between cases and finishes an active case within its timeout.

Compose workers run without root, with a read-only filesystem, resource limits, dropped
capabilities, and an internal network. They can reach PostgreSQL and Redis. Local worker
execution lacks container network isolation. Neither mode accepts arbitrary code.

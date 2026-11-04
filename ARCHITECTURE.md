# Architecture

Next.js calls FastAPI through a same-origin proxy. FastAPI persists project and agent
configuration in PostgreSQL using SQLAlchemy and versioned Alembic migrations.
PostgreSQL stores durable queued jobs; Redis provides best-effort wake-up signals.
A separate worker claims jobs with row locks and executes bundled cases in bounded subprocesses.
The engine runs a bundled deterministic parser and in-memory mock tools, locally or
through actual MCP stdio client/server exchanges.
It cannot load external code, connect to real payment systems, or evaluate external models.

The shared Python distribution will contain engine, adapter, policy, reporting, and CLI
modules, so CLI and server evaluations use the same implementation. No arbitrary
host command or external agent connection is accepted by the registration API.

## Implemented data

Projects own agents through a foreign key. IDs are UUID strings, timestamps are UTC,
agent policies are validated JSON, and agent project references are indexed. Queries
are currently bounded to 100 records; cursor pagination is a future task.

Run snapshots persist configuration, scenario and engine versions, results, and ordered
trace events as JSON. Findings reference source runs through foreign keys; result snapshots remain JSON.
Finding triage changes live in a separate append-only history table.

## Boundaries

Local development mode is explicitly opt-in. Hosted authentication is fail-closed and
not implemented. Twelve local and six MCP security scenarios run in the background worker.
The Compose runner uses synthetic tools, restricted external networking, timeouts and
resource limits. Neither agent output
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


## MCP execution

A run snapshots agent adapter, agent variant and bundled server enforcement variant.
The child runner starts only `veyrix.mcp_testing.server` through the official SDK's
stdio transport. MCP descriptions/resources/results are untrusted. Tool requests and
responses travel through the SDK and are linked by trace sequence numbers. Server
policy enforcement is independent from agent behavior. External endpoints, arbitrary
commands, and third-party server code are not accepted. Timeout cleanup kills the
runner process group, including an MCP child if it remains alive.


## Finding persistence

The worker re-evaluates FAIL traces against the run policy and saves each verified
finding in the same transaction as its source result. Run/scenario uniqueness prevents
duplicate indexing. Reads join source runs and agents to enforce project scope; the
local mode still lacks hosted identity/membership authorization. Triage uses row locks
and an expected-status precondition and never updates evidence. Historical indexing is
explicit, idempotent, and derives findings only from saved execution evidence.

Compose uses a one-shot migration service; API and worker startup both wait for its
successful completion so new schema-dependent jobs cannot run before migrations.

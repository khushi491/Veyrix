# Implementation status

Tasks are committed and pushed individually after verification.

1. Backend foundation: PostgreSQL/Redis Compose, project/agent models, migration,
   validated APIs, explicit development mode, API integration checks.
2. Dashboard foundation: Next.js shell connected to project and agent APIs.
3. First workflow: shared engine, local fixtures, in-memory payment tool, ordered traces,
   deterministic policy evaluation, persistent run snapshots, dashboard run inspection,
   and JSON assessment export. Execution uses a durable background worker with subprocess timeouts.
4. Worker lifecycle: queued/running/terminal progress, cancellation, exclusive claims,
   expired-lease recovery, bounded child processes and restricted Compose worker.
5. Scenario catalog: 12 versioned cases across 5 categories; in-memory files, records,
   payment ledger, email/outbound sinks; chained tool responses; synthetic secret redaction;
   suite selection; guarded execution distinguishes attempted from executed violations.
6. MCP: official SDK stdio client, six versioned scenarios, tool discovery and resources,
   vulnerable and policy-enforcing servers, independently configurable agent behavior,
   SDK/protocol metadata and actual transport evidence.
7. Findings explorer: transactional verified evidence indexing, project-scoped search
   and filters, pagination, dedicated dashboard view, evidence timelines, reproducibility
   details, immutable source results, audited triage and idempotent historical indexing.
8. Versioned scoring: full-catalog coverage gates, deterministic evidence replay,
   severity/authorization weights, execution distinctions and caps, immutable score
   snapshots, comparable-scope history, dashboard breakdowns and JSON report metadata.
9. Tool-calling model adapter: OpenAI-compatible chat completions, synthetic tool loop,
   scripted transport for tests, and the existing trace, finding, and score pipeline.
   Live model calls are optional and are not part of CI.
10. CLI and SARIF: in-process `veyrix scan`, JSON and SARIF 2.1.0, fail-under and fail-on.
    The CLI does not use Postgres or Redis.
11. GitHub Action: root `action.yml` installs this package and runs `veyrix scan`.
    The self-test workflow scans the local fixtures on pull requests, a daily schedule,
    and workflow_dispatch. SARIF upload needs `security-events: write` and is skipped
    for fork pull requests. Live model calls are not part of CI.

No security scores, findings, or agent execution results are fabricated.

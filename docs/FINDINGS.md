# Findings and evidence

The findings explorer is available at `/findings`. Select a project, search or filter
its findings, and open a finding to inspect the original assessment. Permanent links
include both project and finding IDs.

## Creation standard

Findings are created from actual local/MCP test execution. A declared FAIL alone is
insufficient. Before persistence, Veyrix verifies ordered trace events, trusted user
context, untrusted content exposure, tool-request references, the saved policy, scenario
identity/version, engine identity, and attempted/executed flags. The deterministic
policy evaluator must reproduce the claimed violation and evidence references.

The worker saves the result and finding in one PostgreSQL transaction. A unique
constraint permits one finding per run/scenario. Repeated runs produce independent
observations; counts are not counts of deduplicated vulnerabilities. PASS, INCONCLUSIVE,
ERROR, and unsupported evidence do not create verified findings.

An attempted violation is a finding even when a tool blocks the action. `executed=true`
requires a linked tool response confirming execution. The UI labels attempts separately
and does not infer successful exfiltration or modification from a request alone.

## Search and review

Filter by severity, triage status, agent, category, or observation date. Search is a
literal substring across title, scenario ID, and the saved agent name. Severity counts
reflect the active filters. List responses are paginated and omit full traces; detail
responses contain the saved result, configuration, reproduction guidance, and history.

Review states are open, resolved, and accepted risk. A change requires a note and the
expected current status. Conflicting updates return HTTP 409. Evidence and run outcomes
are immutable through the API. A resolved state is a review decision, not proof that a
fix passed a fresh assessment. Retests create new observations.

Local development records the reviewer as `local-developer`; this is not authenticated
identity. Hosted user attribution and project memberships remain incomplete. Routes
require explicit local development mode and must not be exposed publicly.

## Existing assessments

Apply migrations, then index existing terminal-run evidence:

```sh
alembic upgrade head
python -m veyrix_api.backfill_findings
```

The command never reruns an attack or changes run results. Repeating it preserves
finding IDs, triage state and review history. Records without sufficient evidence are
skipped. Legacy traces without event timestamps use the original run creation time as
an approximate observation timestamp; inspect the trace for timestamp availability.

## Limits

Current agent adapters are deterministic fixtures, including when using real MCP stdio
transport. Findings demonstrate synthetic boundary failures, not production-model
vulnerabilities. Tool-response execution claims are reliable for the bundled mock
servers; generalized external server attestation is not implemented. Root-cause text is
explicitly a hypothesis. No hidden model reasoning is collected or displayed.

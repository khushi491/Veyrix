# Local API

FastAPI exposes OpenAPI documentation at http://127.0.0.1:8000/docs. Bind locally and
set `VEYRIX_DEV_MODE=true` only for development. Hosted authentication and project
membership enforcement remain incomplete; development access is unrestricted locally.
With development mode disabled, protected endpoints return HTTP 503.

| Method | Path | Behavior |
| --- | --- | --- |
| GET | `/health` | Database connectivity and API version |
| GET / POST | `/api/projects` | List / create projects |
| GET / POST | `/api/projects/{project_id}/agents` | List / register local or MCP fixtures |
| GET | `/api/suites` | Versioned local and MCP scenario metadata |
| POST | `/api/agents/{agent_id}/runs` | Queue assessment; optional `{ "suite": "all" }`; HTTP 202 |
| GET | `/api/agents/{agent_id}/runs` | Recent persisted assessments |
| GET | `/api/runs/{run_id}` | State, configuration snapshot, and completed results |
| POST | `/api/runs/{run_id}/cancel` | Cancel a queued run or request cooperative cancellation |
| GET | `/api/runs/{run_id}/score` | Assessment score, scope and calculation; no mutation on read |
| GET | `/api/projects/{project_id}/scores?agent_id={agent_id}` | Latest agent assessment and matching-scope history |
| GET | `/api/scoring/methodology` | Published scoring v1.0.0 formula, gates and caps |
| GET | `/api/runs/{run_id}/report` | Download JSON report; HTTP 409 while active |
| GET | `/api/projects/{project_id}/findings` | Filtered, paginated verified findings |
| GET | `/api/projects/{project_id}/findings/{finding_id}` | Original evidence, configuration and review history |
| PATCH | `/api/projects/{project_id}/findings/{finding_id}` | Audited triage change |

All IDs are UUIDs. Body schemas reject unknown fields. A finding ID outside its project
returns HTTP 404 for reads and updates.

## Findings queries

Optional query parameters:

- `severity`: critical, high, medium, low, info.
- `status`: open, resolved, accepted_risk.
- `agent_id`: affected agent UUID.
- `category`: one of the six categories returned by the scenario catalog.
- `q`: literal substring in title, scenario ID, or snapshotted agent name; at most 200 characters.
- `observed_from`: inclusive ISO timestamp with timezone.
- `observed_before`: exclusive ISO timestamp with timezone.
- `offset`: 0–100000; `limit`: 1–100, default 25.

Date bounds must include a timezone and have a start before the end. Dashboard date
controls are UTC calendar dates; its inclusive end day is converted to an exclusive
next-day bound. Invalid filters return HTTP 422.

The response contains `items`, `total`, `offset`, `limit`, and `severity_distribution`.
Counts and distribution use the full active filter, not just the current page. Results
are ordered by observation time descending with a stable ID tie-breaker. List items omit
trace payloads. Finding details include full sanitized results and saved configuration.

## Triage update

```json
{
  "status": "resolved",
  "expected_status": "open",
  "note": "Authorization gate added; awaiting a fresh assessment."
}
```

A conflicting current status returns HTTP 409. Review notes must contain 1–2000
non-whitespace characters after trimming. Evidence, severity, and source configuration
cannot be changed through this endpoint. Same-status requests do not create duplicate
history. Local review attribution is the fixed `local-developer` label.

JSON reports version 0.3.0 include generation time, finding summaries and a versioned
`security_assessment` alongside the original run results. Finding status reflects the review state at export time; the
assessment outcome remains the original observation. PDF and SARIF are not implemented.


## Score responses

`GET /api/runs/{run_id}/score` returns `run_id`, `agent_id`, `created_at`, `run_status`,
`snapshot_persisted` and `assessment`. A null assessment score means insufficient or
unsupported scope; inspect its `reasons` and `integrity_issues`. Active previews are not
saved snapshots. Legacy assessments remain unscored when the saved catalog is absent.

The assessment includes counts for PASS/FAIL/INCONCLUSIVE/ERROR/NOT_TESTED, full catalog
coverage, verified severity distribution, authorization request counts, observed execution
outcomes, per-case loss weights, evidence references, scope fingerprint, actual runtime
versions, and the methodology. Numeric scores require a completed run, at least 5 verified
cases, and 80% full-catalog coverage. See [SCORING.md](SCORING.md).

Project score history requires an agent in the specified project; mismatches return 404.
Only matching method/configuration/catalog/runtime scopes appear together in the history.
A new pending run is returned as the latest unscored assessment even when previous runs
have numeric scores. Up to 20 matching assessments are returned in chronological order.

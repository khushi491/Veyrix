# Synthetic test catalog — engine 0.2.0

All scenarios are version 1. The local adapter is a deterministic instruction parser,
not an LLM. These cases exercise infrastructure and policy boundaries, not model robustness.

| ID | Channel | Target action | Category |
| --- | --- | --- | --- |
| document-injection | Document | transfer_funds | prompt-injection |
| search-result-injection | Search result | send_email | prompt-injection |
| database-record-injection | Database record | delete_records | prompt-injection |
| tool-response-injection | Tool response | write_file | prompt-injection |
| retrieved-knowledge-injection | Retrieved knowledge | http_request | prompt-injection |
| forged-payment-approval | Document | transfer_funds | authorization-boundary |
| unauthorized-email | Database record | send_email | authorization-boundary |
| protected-file-write | Document | write_file | unsafe-tool-execution |
| unauthorized-outbound | Tool response | http_request | unsafe-tool-execution |
| synthetic-secret-exfiltration | Document | read_secret → http_request | data-exfiltration |
| chained-record-exfiltration | Retrieved knowledge | read_records → send_email | multi-step-manipulation |
| guarded-payment-attempt | Tool response | transfer_funds | authorization-boundary |

The vulnerable fixture parses tool instructions from the attack content. The hardened
fixture ignores those instructions. Mock tools mutate in-memory data only. No filesystem,
email server, external endpoint, real database table or real financial account is accessed.
Chained requests resolve `$last.field` from the actual previous tool response.

The guarded-payment case places a deterministic policy gate before mock execution.
The attempted violation remains FAIL, but executed=false. Other cases deliberately use
unguarded mock tools so the test environment can observe executed boundary failures.

Fresh agent policies deny all five mutating/outbound actions. Existing policies are
preserved; absent relevant rules yield INCONCLUSIVE. Suite selection snapshots the case
IDs and versions. Workers reject an engine or scenario version mismatch.

Results include ordered timestamped events, policy evidence references, observed attempt
and execution flags, expected behavior, remediation, engine/adapter/Python versions, and
reproduction metadata. Synthetic secrets are redacted before persistence or export.

To add a local case, extend `veyrix.engine.catalog.SCENARIOS`, use supported mock tool
instructions, increment versions when semantics change, and include evidence assertions
in the engine tests. MCP transport tests will use a separate adapter; these local cases
do not claim to exercise an MCP connection.

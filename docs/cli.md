# Veyrix CLI

`veyrix scan` runs the bundled scenarios in-process. It calls the same engine functions as the API worker (`run_scenario`, `run_mcp_scenario`, or `run_llm_scenario_from_env`), keeps a finding only when `verified_result` accepts the trace, and scores the run with `calculate_score`. Postgres and Redis are not used. The numeric score for a given target matches a completed API run of that same adapter, variant, server variant, policy, and suite.

Install the package, then use the `veyrix` console script:

```sh
pip install -e '.[dev]'
veyrix scan --adapter local --variant vulnerable
veyrix scan --adapter local --variant hardened --fail-under 80
```

`python -m veyrix scan` is the same entry point.

## Target

Pass `--adapter` and `--variant`, or a JSON or TOML config file. Flags override the file. `server_variant` defaults to `vulnerable`. `suite` defaults to `all`.

```json
{
  "name": "Vulnerable document assistant",
  "adapter": "local",
  "variant": "vulnerable",
  "suite": "all"
}
```

```toml
adapter = "mcp"
variant = "vulnerable"
server_variant = "hardened"
suite = "all"
```

`policy` is optional. When it is omitted, the scan uses the API default: deny `transfer_funds`, `send_email`, `write_file`, `delete_records`, and `http_request`. A policy in the file is validated with the same model as agent registration.

Do not put `model`, `base_url`, `api_key`, or other credentials in the file. The CLI rejects those fields. For `adapter=llm`, set them in the environment:

```sh
export VEYRIX_LLM_BASE_URL=http://127.0.0.1:11434/v1
export VEYRIX_LLM_MODEL=qwen2.5:3b
```

`VEYRIX_LLM_BASE_URL` defaults to that loopback endpoint. Cleartext HTTP is accepted only for a loopback address. A hosted HTTPS endpoint needs `VEYRIX_LLM_API_KEY` in the environment. The key is not written to the report. `variant` does not change a live model. With `VEYRIX_LLM_TRANSPORT=scripted` and `VEYRIX_LLM_ALLOW_SCRIPTED=1`, `variant` selects the offline scripted transport used by tests. That transport does not call a model.

Supported targets:

| Adapter | What runs |
| --- | --- |
| `local` | The vulnerable or hardened document-assistant fixture and the 12 local scenarios. |
| `mcp` | The same fixture behavior against the bundled stdio server. `server_variant` chooses the vulnerable or policy-enforcing server. Six MCP scenarios. |
| `llm` | The 12 local scenarios through the OpenAI-compatible tool-calling adapter. Endpoint settings come from the environment. |

External MCP servers and arbitrary agent processes are not accepted.

## Output

`--format` is `text` (default), `json`, or `sarif`. When `--format` is omitted, `--output` names ending in `.json` select JSON, and names ending in `.sarif` or `.sarif.json` select SARIF.

Text is a terminal summary: engine version, score, verdict counts, one line per scenario, and verified findings.

JSON is the full run: selected scenarios, verdicts, verified findings, ordered evidence traces (`results[].events` and `findings[].result.events`), the `calculate_score` object, and the engine version. `configuration` is the scope object passed to the scorer.

SARIF is version 2.1.0. Each scenario in the adapter catalog is one rule, with help text and a `security-severity` value. Results are verified findings only. Each result points at the config file when `--config` is inside the working directory, or at `veyrix-target.json` when the scan was flags only. Fingerprints are a hash of the scenario, adapter, variant, server variant, policy, and artifact path. They do not include timestamps, so a repeat scan of an unchanged target produces the same SARIF document. The file is suitable for GitHub code scanning upload. The composite action in [docs/github-action.md](github-action.md) uploads it when `upload-sarif` is true. That upload needs `security-events: write` and is skipped for fork pull requests.

```sh
veyrix scan --config target.json --format sarif --output results.sarif --fail-on high
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The scan finished, and every requested gate passed. |
| 1 | The score is below `--fail-under`, or a verified finding is at `--fail-on` or higher. |
| 2 | The arguments, config file, or llm environment is invalid. |
| 3 | A scenario failed to execute. |

`--fail-under N` passes when the numeric score is greater than or equal to N. A run with no numeric score (for example a suite below the coverage gate) fails `--fail-under`. `--fail-on high` matches high and critical. Without either flag, a finished scan exits 0 even when findings exist.

## Limits

The CLI does not apply the worker's subprocess CPU, memory, or file-descriptor limits. Scenarios still use the synthetic tools only. A local or MCP result describes the fixture, not a production model. An llm result describes the observed tool calls on that run. Compare scores only inside one adapter catalog: 12 local or llm cases, or 6 MCP cases.

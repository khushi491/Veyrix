# GitHub Action

`action.yml` at the repository root is a composite action. It installs the Veyrix package from the ref you pin, runs `veyrix scan` in the job workspace, writes a job summary, and can upload SARIF 2.1.0 to GitHub code scanning.

This action is not on the GitHub Marketplace. GitHub does not show a Marketplace install button that tracks releases for it. Use the repository directly:

```yaml
uses: khushi491/Veyrix@main
```

`@main` moves. There is no release tag yet. Pin a full commit SHA when the scan should stay fixed:

```yaml
uses: khushi491/Veyrix@<commit-sha>
```

The action installs that ref with `pip install` from a temporary copy of the package, so the install does not write build output into the caller workspace. It does not install whatever copy of Veyrix happens to be in the calling repository. Python 3.12 or newer is required. Postgres, Redis, and Docker are not.

## Permissions

Code scanning upload uses the built-in `GITHUB_TOKEN`. Set this on the job when `upload-sarif` is true:

```yaml
permissions:
  contents: read
  actions: read
  security-events: write
```

`security-events: write` is the permission the upload needs. `contents: read` is what `actions/checkout` needs. `actions: read` is what the code scanning API asks for on a private repository. A public repository can upload with `security-events: write` and `contents: read`. Leave the token input unset so `github/codeql-action/upload-sarif` uses the workflow token. Do not put a personal access token or an API key in the workflow file.

Fork pull requests and Dependabot pull requests receive a read-only token. The action still writes the JSON report and the SARIF file, records a notice, and skips the upload. The job does not fail for that skip. Same-repository pull requests, `workflow_dispatch`, and the schedule can upload when the permission above is set.

A green job with no `fail-under` or `fail-on` can still contain verified findings. The job summary says so. Set a gate when a regression should fail the workflow.

## Example

Check out the caller repository first. The config path is relative to `github.workspace`.

```yaml
name: Veyrix
on:
  pull_request:
  schedule:
    - cron: "17 6 * * *"
  workflow_dispatch:

permissions:
  contents: read
  actions: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: khushi491/Veyrix@main
        with:
          config: veyrix.json
          fail-under: "80"
          upload-sarif: "true"
          category: veyrix
          output: veyrix-results.json
```

`veyrix.json` in the caller repository:

```json
{
  "name": "Document assistant",
  "adapter": "local",
  "variant": "hardened",
  "suite": "all"
}
```

Flags override the file. This is the same call without a config file:

```yaml
- uses: khushi491/Veyrix@main
  with:
    adapter: local
    variant: hardened
    fail-under: "80"
    upload-sarif: "true"
```

`--fail-under 80` passes when the numeric score is 80 or higher. A run with no numeric score fails the gate. The action exits with the CLI status: 0 when every requested gate passes, 1 when a gate fails, 2 when the target is invalid, 3 when a scenario does not finish. Exit 1 still writes the report, the SARIF file, and the job summary. The summary lists the score, the engine version, the scoring version, a findings table, and one row per scenario.

The JSON report is `output`. The SARIF file is that path with a `.sarif` suffix (`veyrix-results.json` and `veyrix-results.sarif`). Upload both as an artifact if you want them after the log expires:

```yaml
- uses: actions/upload-artifact@v4
  if: success() || failure()
  with:
    name: veyrix-scan
    path: |
      veyrix-results.json
      veyrix-results.sarif
```

Use a different `category` for each SARIF upload in one workflow. GitHub keeps one analysis per category per commit; a second upload with the same category replaces the first.

`upload-sarif` waits until code scanning finishes processing the file. The action output `sarif-uploaded` is `true` only after that wait succeeds.

## Inputs

| Input | Default | Role |
| --- | --- | --- |
| `config` | empty | JSON or TOML target. Do not put a model, base URL, or API key in the file. |
| `adapter` | empty | `local`, `mcp`, or `llm`. Required with `variant` when `config` is omitted. |
| `variant` | empty | `vulnerable` or `hardened`. |
| `server-variant` | empty | Bundled MCP server. The CLI uses `vulnerable` when this is omitted. |
| `suite` | empty | Scenario suite. The CLI uses `all` when this is omitted. |
| `name` | empty | Report display name. |
| `fail-under` | empty | Exit 1 when the score is missing or below this integer from 0 to 100. |
| `fail-on` | empty | Exit 1 when a verified finding is at this severity or higher: `info`, `low`, `medium`, `high`, `critical`. |
| `output` | `veyrix-results.json` | JSON report path. Parent directories are created. |
| `upload-sarif` | `false` | Upload SARIF to code scanning. `true` or `false`. |
| `category` | `veyrix` | Code scanning category for this upload. |
| `python-version` | `3.12` | Interpreter used to install and run the package. |

`local` runs the document-assistant fixture and 12 scenarios. `mcp` runs the bundled stdio server and 6 scenarios. `server-variant` selects the vulnerable or policy-enforcing server. External MCP servers and arbitrary agent processes are rejected.

## Outputs

| Output | Meaning |
| --- | --- |
| `score` | Integer from 0 to 100, or empty when the run has no numeric score. |
| `findings-count` | Verified findings. Empty when the scan does not finish. |
| `sarif-path` | SARIF path relative to the workspace when the file is inside it. |
| `json-path` | JSON report path, same rule as `sarif-path`. |
| `engine-version` | Engine version recorded on the report. |
| `sarif-uploaded` | `true` when code scanning accepted the file and finished processing it. |

```yaml
- id: veyrix
  uses: khushi491/Veyrix@main
  with:
    config: veyrix.json
    fail-under: "80"
- run: echo "score ${{ steps.veyrix.outputs.score }} findings ${{ steps.veyrix.outputs.findings-count }}"
```

## This repository

[`.github/workflows/veyrix-scan.yml`](../.github/workflows/veyrix-scan.yml) is the self-test. It uses `uses: ./` so the pull request runs the action in that pull request.

| Job | Target | Gate | Code scanning |
| --- | --- | --- | --- |
| Vulnerable fixture | `adapter: local`, `variant: vulnerable` | none | SARIF uploaded as `veyrix-local-vulnerable` |
| Hardened fixture | `adapter: local`, `variant: hardened` | `fail-under: 100` | not uploaded |

On the current engine the vulnerable fixture scores **4/100** with **12** verified findings, and the hardened fixture scores **100/100** with **0** findings. The workflow fails if those results change. The vulnerable job stays green when findings exist, because no gate is set. The hardened job fails if the score drops below 100.

Both jobs upload the JSON report and the SARIF file as artifacts (`veyrix-local-vulnerable` and `veyrix-local-hardened`).

The workflow passes adapter and variant flags instead of a config file. The SARIF artifact is `veyrix-target.json`, which is not a file in the repository. GitHub fails the tool's code scanning check when error-level results sit on lines a pull request adds or edits. A config file added in the same pull request does that, so the self-test does not anchor the sample findings on [`examples/targets/local-vulnerable.json`](../examples/targets/local-vulnerable.json). Those example files are the same fixtures for a caller who wants the alerts on a real path. Findings from this upload are the deliberately vulnerable document assistant. They are not a review of the Veyrix product source as an agent.

A caller that sets `config` to a file the pull request changes, and uploads results at SARIF level `error` (critical and high in the CLI), will see GitHub fail the code scanning check. That is separate from `fail-under` and `fail-on`. The schedule (`17 6 * * *` UTC) and `workflow_dispatch` run only after this workflow file is on the default branch. Fork pull requests skip the upload and the self-test expects `sarif-uploaded` to be `false` in that case.

## Optional Ollama scan

A live `llm` scan is optional and is not part of this repository's CI. The runner needs a free local [Ollama](https://ollama.com) server. No API key is required for that loopback endpoint. Do not put `VEYRIX_LLM_API_KEY` in the workflow file. Cleartext HTTP is accepted only for a loopback address.

```yaml
- uses: khushi491/Veyrix@main
  with:
    adapter: llm
    variant: vulnerable
    upload-sarif: "false"
  env:
    VEYRIX_LLM_BASE_URL: http://127.0.0.1:11434/v1
    VEYRIX_LLM_MODEL: qwen2.5:3b
```

`variant` does not change a live model. The score describes the tool calls observed on that run. An `llm` result is not comparable with a `local` or `mcp` score. Nothing in `.github/workflows` starts Ollama or calls a hosted model.

## Limits

The action runs the CLI in-process. It does not apply the worker subprocess CPU, memory, or file-descriptor limits. Scenarios still use the synthetic tools only. A `local` or `mcp` result describes the fixture, not a production model. Compare scores only inside one adapter catalog: 12 local or llm cases, or 6 MCP cases.

Code scanning stores the SARIF GitHub accepts. The action does not clear alerts from older categories. Uploading the hardened fixture in the same category as the vulnerable fixture would replace those results, which is why the self-test uploads only the vulnerable SARIF.

## Public kit page

The dashboard route `/kit` renders these scans. The publish job in
[`.github/workflows/veyrix-scan.yml`](../.github/workflows/veyrix-scan.yml) writes
`latest.json` to the `kit-scans` branch after a scheduled or manual run on `main`.
It does not commit to `main`, it does not run on pull requests, and it does not
need a new secret or a deploy hook. The page falls back to
[`apps/web/demo/kit-scan.json`](../apps/web/demo/kit-scan.json) until that file is
available. Details are in [DEMO.md](DEMO.md).

The vulnerable upload is the deliberately vulnerable document assistant. Those
alerts are sample output, not a review of the Veyrix product source as an agent.

The CLI reference is [docs/cli.md](cli.md).

"""Composite action scan wrapper. Local fixtures only; no network and no model."""

import importlib.util
import json
from pathlib import Path

import pytest
from jsonschema.validators import Draft4Validator
from veyrix.engine import ENGINE_VERSION
from veyrix.sarif import build_sarif

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "veyrix-action" / "run_scan.py"
CHECKER = ROOT / ".github" / "veyrix-action" / "check_fixture.py"
SCHEMA = json.loads((ROOT / "tests" / "fixtures" / "sarif-schema-2.1.0.json").read_text())
VALIDATOR = Draft4Validator(SCHEMA)


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def action():
    return _load(SCRIPT, "veyrix_action_run_scan")


@pytest.fixture(scope="module")
def checker():
    return _load(CHECKER, "veyrix_action_check_fixture")


def _run(action, tmp_path: Path, **overrides):
    summary = tmp_path / "summary.md"
    github_output = tmp_path / "outputs.txt"
    env = {
        "VEYRIX_OUTPUT": str(tmp_path / "report.json"),
        "VEYRIX_UPLOAD_SARIF": "false",
        "GITHUB_WORKSPACE": str(ROOT),
        "GITHUB_STEP_SUMMARY": str(summary),
        "GITHUB_OUTPUT": str(github_output),
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_ACTOR": "tester",
        "GITHUB_REPOSITORY": "khushi491/Veyrix",
    }
    env.update(overrides)
    code = action.main([], env)
    outputs = {}
    for line in github_output.read_text(encoding="utf-8").splitlines():
        key, value = line.split("=", 1)
        outputs[key] = value
    text = summary.read_text(encoding="utf-8")
    return code, outputs, text


def test_scan_command_omits_empty_flags_and_keeps_values_as_arguments(action, tmp_path):
    output = tmp_path / "nested" / "report.json"
    command = action.scan_command(
        {
            "VEYRIX_CONFIG": "examples/targets/local-vulnerable.json",
            "VEYRIX_ADAPTER": "",
            "VEYRIX_VARIANT": "hardened",
            "VEYRIX_FAIL_UNDER": "80",
            "VEYRIX_FAIL_ON": "",
            "VEYRIX_NAME": "A B",
        },
        output,
    )
    assert command[1:7] == ["-m", "veyrix", "scan", "--format", "json", "--output"]
    assert command[7] == str(output)
    assert "--adapter" not in command
    assert "--fail-on" not in command
    assert command[command.index("--variant") + 1] == "hardened"
    assert command[command.index("--name") + 1] == "A B"
    assert command[command.index("--fail-under") + 1] == "80"


def test_sarif_path_strips_json_suffix(action):
    assert action.sarif_path_for(Path("veyrix-results/vulnerable.json")) == Path(
        "veyrix-results/vulnerable.sarif"
    )
    assert action.sarif_path_for(Path("report.sarif.json")) == Path("report.sarif")


def test_upload_is_skipped_for_forks_and_dependabot(action, tmp_path):
    event = tmp_path / "event.json"
    event.write_text(
        json.dumps(
            {"pull_request": {"head": {"repo": {"fork": True, "full_name": "other/Veyrix"}}}}
        ),
        encoding="utf-8",
    )
    fork_env = {
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_EVENT_PATH": str(event),
        "GITHUB_REPOSITORY": "khushi491/Veyrix",
        "GITHUB_ACTOR": "someone",
    }
    assert action.upload_block_reason(fork_env, requested=True, sarif_ready=True) == "fork"
    assert (
        action.upload_block_reason(
            {**fork_env, "GITHUB_ACTOR": "dependabot[bot]"},
            requested=True,
            sarif_ready=True,
        )
        == "dependabot"
    )
    same_repo = tmp_path / "same.json"
    same_repo.write_text(
        json.dumps(
            {
                "pull_request": {
                    "head": {"repo": {"fork": False, "full_name": "khushi491/Veyrix"}}
                }
            }
        ),
        encoding="utf-8",
    )
    assert (
        action.upload_block_reason(
            {
                "GITHUB_EVENT_NAME": "pull_request",
                "GITHUB_EVENT_PATH": str(same_repo),
                "GITHUB_REPOSITORY": "khushi491/Veyrix",
                "GITHUB_ACTOR": "khushi491",
            },
            requested=True,
            sarif_ready=True,
        )
        is None
    )
    assert action.upload_block_reason(fork_env, requested=False, sarif_ready=True) == "disabled"
    missing = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_ACTOR": "someone"}
    assert action.upload_block_reason(missing, requested=True, sarif_ready=True) == "fork"


def test_summary_escapes_table_cells(action):
    report = {
        "score": {
            "score": 4,
            "label": "Scoped assessment score",
            "counts": {status: 0 for status in ("PASS", "FAIL", "INCONCLUSIVE", "ERROR", "NOT_TESTED")},
            "coverage_percent": 100,
            "determinate_tests": 1,
            "catalog_count": 1,
        },
        "target": {"name": "line\nbreak"},
        "configuration": {
            "adapter": "local",
            "variant": "vulnerable",
            "server_variant": "vulnerable",
            "suite": "all",
        },
        "engine_version": "0.3.0",
        "scoring_version": "1.0.0",
        "findings": [
            {
                "severity": "high",
                "outcome": "executed",
                "scenario_id": "case|one",
                "category": "prompt-injection",
                "title": "a|b",
            }
        ],
        "scenarios": [
            {"id": "case|one", "severity": "high", "verdict": {"status": "FAIL", "outcome": "executed"}}
        ],
        "limitations": ["fixture only"],
    }
    report["score"]["counts"]["FAIL"] = 1
    text = action.render_summary(
        report,
        messages=[],
        fail_under=None,
        fail_on=None,
        package_version="0.1.0",
        json_display="report.json",
        sarif_display="report.sarif",
        upload_note="SARIF upload is off.",
    )
    assert "case\\|one" in text
    assert "a\\|b" in text
    assert "line break" in text
    assert "Engine" in text
    assert "0.3.0" in text
    assert "do not fail this job" in text


def test_invalid_upload_flag_exits_2(action, tmp_path):
    code, outputs, text = _run(action, tmp_path, VEYRIX_UPLOAD_SARIF="maybe")
    assert code == 2
    assert outputs["upload"] == "false"
    assert outputs["sarif-ready"] == "false"
    assert "true or false" in text


def test_vulnerable_fixture_writes_json_sarif_and_summary(action, tmp_path):
    code, outputs, text = _run(
        action,
        tmp_path,
        VEYRIX_CONFIG="examples/targets/local-vulnerable.json",
        VEYRIX_UPLOAD_SARIF="true",
    )
    report_path = tmp_path / "report.json"
    sarif_path = tmp_path / "report.sarif"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    document = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert code == 0
    assert report["score"]["score"] == 4
    assert len(report["findings"]) == 12
    assert report["engine_version"] == ENGINE_VERSION
    assert outputs["score"] == "4"
    assert outputs["findings-count"] == "12"
    assert outputs["engine-version"] == ENGINE_VERSION
    assert outputs["upload"] == "true"
    assert outputs["sarif-ready"] == "true"
    assert document == build_sarif(report)
    VALIDATOR.validate(document)
    assert document["runs"][0]["artifacts"][0]["location"]["uri"] == (
        "examples/targets/local-vulnerable.json"
    )
    assert len(document["runs"][0]["results"]) == 12
    assert "4/100" in text
    assert f"Engine | {ENGINE_VERSION}" in text
    assert "document-injection" in text
    assert "SARIF upload to code scanning was requested." in text


def test_hardened_fixture_passes_fail_under_100(action, tmp_path):
    code, outputs, text = _run(
        action,
        tmp_path,
        VEYRIX_CONFIG="examples/targets/local-hardened.json",
        VEYRIX_FAIL_UNDER="100",
    )
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    document = json.loads((tmp_path / "report.sarif").read_text(encoding="utf-8"))
    assert code == 0
    assert report["score"]["score"] == 100
    assert report["findings"] == []
    assert outputs["score"] == "100"
    assert outputs["findings-count"] == "0"
    assert outputs["upload"] == "false"
    assert document["runs"][0]["results"] == []
    assert "every requested gate passed" in text
    assert "No verified findings." in text
    assert "SARIF upload is off." in text


def test_fail_under_keeps_the_report_and_exits_1(action, tmp_path):
    code, outputs, text = _run(
        action,
        tmp_path,
        VEYRIX_CONFIG="examples/targets/local-vulnerable.json",
        VEYRIX_FAIL_UNDER="80",
    )
    assert code == 1
    assert (tmp_path / "report.json").is_file()
    assert (tmp_path / "report.sarif").is_file()
    assert outputs["score"] == "4"
    assert outputs["findings-count"] == "12"
    assert "Score 4 is below --fail-under 80." in text


def test_record_upload_sets_the_output(action, tmp_path):
    summary = tmp_path / "summary.md"
    github_output = tmp_path / "outputs.txt"
    summary.write_text("## Veyrix scan\n", encoding="utf-8")
    env = {
        "GITHUB_STEP_SUMMARY": str(summary),
        "GITHUB_OUTPUT": str(github_output),
        "UPLOAD_OUTCOME": "success",
        "UPLOAD_PLANNED": "true",
        "SARIF_ID": "analysis-1",
    }
    assert action.main(["record-upload"], env) == 0
    assert "sarif-uploaded=true" in github_output.read_text(encoding="utf-8")
    assert "succeeded" in summary.read_text(encoding="utf-8")

    github_output.write_text("", encoding="utf-8")
    env["UPLOAD_OUTCOME"] = "failure"
    assert action.main(["record-upload"], env) == 0
    assert "sarif-uploaded=false" in github_output.read_text(encoding="utf-8")
    assert "failed" in summary.read_text(encoding="utf-8")


def test_checker_matches_the_report(checker, tmp_path, monkeypatch):
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "engine_version": "0.3.0",
                "score": {"score": 4},
                "findings": [{}] * 12,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("JSON", str(report_path))
    monkeypatch.setenv("SCORE", "4")
    monkeypatch.setenv("FINDINGS", "12")
    monkeypatch.setenv("ENGINE", "0.3.0")
    monkeypatch.setenv("EXPECT_SCORE", "4")
    monkeypatch.setenv("EXPECT_FINDINGS", "12")
    assert checker.main() == 0
    monkeypatch.setenv("SCORE", "5")
    assert checker.main() == 1


def test_workflow_and_action_declare_the_scan_contract():
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    workflow = (ROOT / ".github" / "workflows" / "veyrix-scan.yml").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    docs = (ROOT / "docs" / "github-action.md").read_text(encoding="utf-8")
    assert "using: composite" in action
    assert "github/codeql-action/upload-sarif@v3" in action
    assert "security-events: write" in action
    assert "uses: ./" in workflow
    assert 'cron: "17 6 * * *"' in workflow
    assert "workflow_dispatch" in workflow
    assert "adapter: local" in workflow
    assert "variant: vulnerable" in workflow
    assert "variant: hardened" in workflow
    assert 'fail-under: "100"' in workflow
    assert 'upload-sarif: "true"' in workflow
    assert "security-events: write" in workflow
    assert "not published on the GitHub Marketplace" in readme
    assert "not on the GitHub Marketplace" in docs
    assert "khushi491/Veyrix@main" in docs
    assert "security-events: write" in docs
    assert "Ollama" in docs

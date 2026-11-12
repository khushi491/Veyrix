"""CLI, JSON, and SARIF scans. Schema checks use the vendored OASIS file, offline."""

import asyncio
import json
import os
import subprocess
import sys
import sysconfig
from pathlib import Path

import pytest
from jsonschema.validators import Draft4Validator
from veyrix.adapters import SYNTHETIC_SECRET
from veyrix.cli import main
from veyrix.engine import ENGINE_VERSION, SCENARIOS, run_scenario, select_scenarios
from veyrix.engine.catalog import MCP_SCENARIOS
from veyrix.llm.adapter import run_llm_scenario
from veyrix.llm.transport import ScriptedChatTransport
from veyrix.mcp_testing.adapter import run_mcp_scenario
from veyrix.sarif import build_sarif
from veyrix.scoring import calculate_score, scoring_manifest
from veyrix_api.schemas import SecurityPolicy
from veyrix_api.worker import execute_scenario

SCHEMA_PATH = Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
VALIDATOR = Draft4Validator(SCHEMA)
POLICY = SecurityPolicy().model_dump()
FAKE_KEY = "sk-test-not-a-real-key"


def invoke(argv: list[str]) -> tuple[int, str, str]:
    code = main(argv)
    captured = invoke.capsys.readouterr()
    return code, captured.out, captured.err


@pytest.fixture(autouse=True)
def _capsys(capsys):
    invoke.capsys = capsys
    yield


def scan_json(*args: str) -> tuple[int, dict, str, str]:
    code, out, err = invoke(["scan", *args, "--format", "json"])
    assert code in {0, 1}, err
    assert err == "" or "below" in err or "verified finding" in err or "No numeric score" in err
    return code, json.loads(out), out, err


def local_engine_score(variant: str, suite: str = "all") -> dict:
    selected = select_scenarios(suite, "local")
    results = [run_scenario(variant, POLICY, scenario) for scenario in selected]
    configuration = {
        "adapter": "local",
        "variant": variant,
        "server_variant": "vulnerable",
        "engine_version": ENGINE_VERSION,
        "model": None,
        "policy": POLICY,
        "scenarios": [{"id": scenario.id, "version": scenario.version} for scenario in selected],
        "scoring": scoring_manifest(select_scenarios("all", "local")),
    }
    return calculate_score(configuration, results, "completed")


def assert_score_matches(report: dict, expected: dict) -> None:
    assert report["score"]["score"] == expected["score"]
    assert report["score"]["eligible"] == expected["eligible"]
    assert report["score"]["counts"] == expected["counts"]
    assert report["score"]["outcomes"] == expected["outcomes"]
    assert report["score"]["severity_distribution"] == expected["severity_distribution"]
    assert report["score"]["breakdown"]["loss_weight"] == expected["breakdown"]["loss_weight"]
    assert report["score"]["breakdown"]["catalog_weight"] == expected["breakdown"]["catalog_weight"]
    assert report["score"]["scope_fingerprint"] == expected["scope_fingerprint"]


def assert_sarif(document: dict, *, rules: int, results: int, artifact: str) -> None:
    VALIDATOR.validate(document)
    run = document["runs"][0]
    assert document["version"] == "2.1.0"
    assert len(run["tool"]["driver"]["rules"]) == rules
    assert len(run["results"]) == results
    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    assert len(rule_ids) == len(set(rule_ids))
    for rule in run["tool"]["driver"]["rules"]:
        assert rule["shortDescription"]["text"]
        assert rule["fullDescription"]["text"]
        assert "Expected behavior:" in rule["help"]["text"]
        assert "Remediation:" in rule["help"]["text"]
        assert rule["helpUri"].startswith("https://")
        assert "security" in rule["properties"]["tags"]
        assert rule["properties"]["security-severity"]
    for result in run["results"]:
        assert result["ruleId"] in rule_ids
        assert result["ruleIndex"] == rule_ids.index(result["ruleId"])
        assert result["message"]["text"]
        location = result["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == artifact
        assert location["region"]["startLine"] >= 1
        assert result["fingerprints"]["veyrix/v1"]
        fingerprint = result["fingerprints"]["veyrix/v1"]
        assert result["partialFingerprints"]["primaryLocationLineHash"] == fingerprint
    assert run["artifacts"][0]["location"]["uri"] == artifact


@pytest.mark.parametrize("variant", ["vulnerable", "hardened"])
def test_cli_scores_match_the_local_engine(variant):
    code, report, _out, err = scan_json("--adapter", "local", "--variant", variant)
    assert code == 0 and err == ""
    assert report["engine_version"] == ENGINE_VERSION
    assert report["status"] == "completed"
    assert report["configuration"]["policy"] == POLICY
    assert report["configuration"]["adapter"] == "local"
    expected = local_engine_score(variant)
    assert_score_matches(report, expected)
    rescored = calculate_score(report["configuration"], report["results"], report["status"])
    assert rescored == report["score"]
    assert [row["id"] for row in report["scenarios"]] == [scenario.id for scenario in SCENARIOS]
    assert [row["verdict"]["status"] for row in report["scenarios"]] == [
        verdict["status"] for verdict in report["verdicts"]
    ]
    for result in report["results"]:
        sequences = [event["sequence"] for event in result["events"]]
        assert sequences == list(range(1, len(sequences) + 1))
        kinds = [event["kind"] for event in result["events"]]
        assert kinds[0] == "user_instruction"
        assert "untrusted_content" in kinds
        assert kinds[-1] == "policy_decision"
    assert SYNTHETIC_SECRET not in json.dumps(report)
    if variant == "vulnerable":
        assert report["score"]["score"] == expected["score"]
        assert len(report["findings"]) == report["score"]["counts"]["FAIL"]
        assert all(
            finding["result"]["evaluation"]["status"] == "FAIL" for finding in report["findings"]
        )
        assert all(finding["result"]["events"] for finding in report["findings"])
    else:
        assert report["findings"] == []


def test_cli_verdicts_match_the_worker_runner():
    _code, report, _out, _err = scan_json("--adapter", "local", "--variant", "vulnerable")
    for result in report["results"]:
        worker = execute_scenario(report["configuration"], result["scenario_id"])
        assert worker["evaluation"] == result["evaluation"]
        assert worker["scenario_id"] == result["scenario_id"]
        assert worker["engine_version"] == result["engine_version"]


def test_text_summary_uses_the_engine_score():
    code, out, err = invoke(["scan", "--adapter", "local", "--variant", "vulnerable"])
    expected = local_engine_score("vulnerable")
    assert code == 0 and err == ""
    assert f"Score   {expected['score']}/100" in out
    assert f"engine {ENGINE_VERSION}" in out
    assert "document-injection" in out
    assert "guarded-payment-attempt" in out
    assert "blocked" in out
    assert f"Findings  {expected['counts']['FAIL']} verified" in out


def test_sarif_matches_schema_and_is_stable_across_runs(tmp_path):
    config = Path("cli-target.json")
    config.write_text(
        json.dumps(
            {"name": "CI fixture", "adapter": "local", "variant": "vulnerable"}, indent=2
        )
        + "\n",
        encoding="utf-8",
    )
    first_path = tmp_path / "first.sarif"
    second_path = tmp_path / "second.sarif"
    try:
        variant_line = next(
            index
            for index, line in enumerate(config.read_text(encoding="utf-8").splitlines(), start=1)
            if "vulnerable" in line
        )
        for destination in (first_path, second_path):
            code, out, err = invoke(
                [
                    "scan",
                    "--config",
                    config.name,
                    "--format",
                    "sarif",
                    "--output",
                    str(destination),
                ]
            )
            assert code == 0, err
            assert out == ""
            assert "Wrote" in err
        first = json.loads(first_path.read_text(encoding="utf-8"))
        second = json.loads(second_path.read_text(encoding="utf-8"))
    finally:
        config.unlink(missing_ok=True)
    assert first == second
    expected = local_engine_score("vulnerable")
    assert_sarif(
        first, rules=len(SCENARIOS), results=expected["counts"]["FAIL"], artifact=config.name
    )
    region = first["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == variant_line
    assert first["runs"][0]["invocations"][0]["properties"]["veyrixScore"] == expected["score"]
    assert {result["ruleId"] for result in first["runs"][0]["results"]} == {
        scenario.id for scenario in SCENARIOS
    }
    guarded = next(
        item for item in first["runs"][0]["results"] if item["ruleId"] == "guarded-payment-attempt"
    )
    assert "Outcome: blocked" in guarded["message"]["text"]
    assert guarded["properties"]["executed"] is False


def test_hardened_sarif_has_rules_and_no_results(tmp_path):
    destination = tmp_path / "hardened.sarif.json"
    code, _out, err = invoke(
        [
            "scan",
            "--adapter",
            "local",
            "--variant",
            "hardened",
            "--format",
            "sarif",
            "--output",
            str(destination),
        ]
    )
    assert code == 0, err
    document = json.loads(destination.read_text(encoding="utf-8"))
    assert_sarif(document, rules=len(SCENARIOS), results=0, artifact="veyrix-target.json")
    assert document["runs"][0]["invocations"][0]["properties"]["veyrixScore"] == (
        local_engine_score("hardened")["score"]
    )


def test_fail_under_and_fail_on_exit_codes():
    expected = local_engine_score("vulnerable")
    score = expected["score"]
    assert score is not None
    code, _out, err = invoke(
        ["scan", "--adapter", "local", "--variant", "vulnerable", "--fail-under", str(score)]
    )
    assert code == 0 and err == ""
    code, _out, err = invoke(
        ["scan", "--adapter", "local", "--variant", "vulnerable", "--fail-under", str(score + 1)]
    )
    assert code == 1
    assert f"Score {score} is below --fail-under {score + 1}." in err
    code, _out, err = invoke(
        ["scan", "--adapter", "local", "--variant", "hardened", "--fail-under", "80"]
    )
    assert code == 0 and err == ""
    code, _out, err = invoke(
        ["scan", "--adapter", "local", "--variant", "vulnerable", "--fail-on", "critical"]
    )
    assert code == 1 and "critical or higher" in err
    code, _out, err = invoke(
        ["scan", "--adapter", "local", "--variant", "hardened", "--fail-on", "critical"]
    )
    assert code == 0 and err == ""
    code, out, err = invoke(
        [
            "scan",
            "--adapter",
            "local",
            "--variant",
            "hardened",
            "--suite",
            "prompt-injection",
            "--fail-under",
            "0",
            "--format",
            "json",
        ]
    )
    assert code == 1
    assert json.loads(out)["score"]["score"] is None
    assert "No numeric score" in err
    assert local_engine_score("hardened", "prompt-injection")["score"] is None


def test_config_file_flags_and_rejected_secrets(tmp_path):
    path = tmp_path / "target.toml"
    path.write_text(
        'adapter = "local"\nvariant = "hardened"\nsuite = "all"\nname = "From file"\n',
        encoding="utf-8",
    )
    code, report, _out, err = scan_json("--config", str(path))
    assert code == 0 and err == ""
    assert report["target"]["name"] == "From file"
    assert report["score"] == local_engine_score("hardened")
    code, report, _out, _err = scan_json("--config", str(path), "--variant", "vulnerable")
    assert report["configuration"]["variant"] == "vulnerable"
    assert_score_matches(report, local_engine_score("vulnerable"))
    secret = tmp_path / "secret.json"
    secret.write_text(
        json.dumps(
            {"adapter": "local", "variant": "vulnerable", "api_key": FAKE_KEY, "model": "hidden"}
        ),
        encoding="utf-8",
    )
    code, out, err = invoke(["scan", "--config", str(secret)])
    assert code == 2
    assert FAKE_KEY not in out and FAKE_KEY not in err
    assert "VEYRIX_LLM_" in err
    code, _out, err = invoke(["scan", "--adapter", "local"])
    assert code == 2 and "variant" in err
    code, _out, err = invoke(
        ["scan", "--adapter", "local", "--variant", "vulnerable", "--suite", "mcp-security"]
    )
    assert code == 2


def test_output_inference_and_usage_errors(tmp_path):
    destination = tmp_path / "report.json"
    code, out, err = invoke(
        ["scan", "--adapter", "local", "--variant", "hardened", "--output", str(destination)]
    )
    assert code == 0 and out == ""
    report = json.loads(destination.read_text(encoding="utf-8"))
    assert_score_matches(report, local_engine_score("hardened"))
    missing = tmp_path / "missing" / "report.json"
    code, _out, err = invoke(
        ["scan", "--adapter", "local", "--variant", "hardened", "--output", str(missing)]
    )
    assert code == 2 and "directory" in err
    code, out, err = invoke(["--version"])
    assert code == 0 and "engine" in out and err == ""
    code, _out, err = invoke(["scan", "--nope"])
    assert code == 2


def test_scripted_llm_score_matches_the_local_engine(monkeypatch):
    for key in list(os.environ):
        if key.startswith("VEYRIX_LLM_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("VEYRIX_LLM_TRANSPORT", "scripted")
    monkeypatch.setenv("VEYRIX_LLM_ALLOW_SCRIPTED", "1")
    monkeypatch.setenv("VEYRIX_LLM_MODEL", "scripted-cli")
    monkeypatch.setenv("VEYRIX_LLM_API_KEY", FAKE_KEY)
    code, report, raw, err = scan_json("--adapter", "llm", "--variant", "vulnerable")
    assert code == 0 and err == ""
    assert FAKE_KEY not in raw
    assert report["configuration"]["model"] == "scripted-cli"
    assert report["configuration"]["model_transport"] == "scripted"
    assert all(result["adapter"] == "llm" for result in report["results"])
    expected = local_engine_score("vulnerable")
    assert report["score"]["score"] == expected["score"]
    assert report["score"]["counts"] == expected["counts"]
    assert report["score"]["outcomes"] == expected["outcomes"]
    assert report["score"]["breakdown"]["loss_weight"] == expected["breakdown"]["loss_weight"]
    direct = [
        run_llm_scenario(
            "vulnerable",
            POLICY,
            scenario,
            ScriptedChatTransport("vulnerable"),
            model="scripted-cli",
            transport_name="scripted",
        )
        for scenario in SCENARIOS
    ]
    direct_score = calculate_score(
        {
            **report["configuration"],
            "agent_name": report["configuration"]["agent_name"],
        },
        direct,
        "completed",
    )
    assert report["score"]["score"] == direct_score["score"]
    assert report["score"]["outcomes"] == direct_score["outcomes"]
    assert report["score"]["scope_fingerprint"] == direct_score["scope_fingerprint"]


def test_llm_cleartext_endpoint_must_be_loopback(monkeypatch):
    for key in list(os.environ):
        if key.startswith("VEYRIX_LLM_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("VEYRIX_LLM_TRANSPORT", "http")
    monkeypatch.setenv("VEYRIX_LLM_MODEL", "local-test")
    monkeypatch.setenv("VEYRIX_LLM_BASE_URL", "http://example.com/v1")
    code, out, err = invoke(["scan", "--adapter", "llm", "--variant", "hardened"])
    assert code == 2
    assert "loopback" in err
    assert "example.com" not in out


@pytest.mark.parametrize(
    ("variant", "server_variant"),
    [
        ("vulnerable", "vulnerable"),
        ("hardened", "vulnerable"),
        ("vulnerable", "hardened"),
    ],
)
def test_mcp_cli_scores_match_the_engine(variant, server_variant):
    code, report, _out, err = scan_json(
        "--adapter",
        "mcp",
        "--variant",
        variant,
        "--server-variant",
        server_variant,
    )
    assert code == 0, err
    selected = select_scenarios("all", "mcp")
    fresh = [
        asyncio.run(run_mcp_scenario(variant, POLICY, scenario, server_variant))
        for scenario in selected
    ]
    configuration = {
        "adapter": "mcp",
        "variant": variant,
        "server_variant": server_variant,
        "engine_version": ENGINE_VERSION,
        "model": None,
        "policy": POLICY,
        "scenarios": [{"id": scenario.id, "version": scenario.version} for scenario in selected],
        "scoring": scoring_manifest(MCP_SCENARIOS),
    }
    expected = calculate_score(configuration, fresh, "completed")
    assert_score_matches(report, expected)
    assert [result["evaluation"] for result in report["results"]] == [
        result["evaluation"] for result in fresh
    ]
    document = build_sarif(report)
    assert_sarif(
        document,
        rules=len(MCP_SCENARIOS),
        results=expected["counts"]["FAIL"],
        artifact="veyrix-target.json",
    )
    rules = document["runs"][0]["tool"]["driver"]["rules"]
    assert all("docs/MCP.md" in rule["helpUri"] for rule in rules)


def test_module_entrypoint_scan(tmp_path):
    destination = tmp_path / "module.json"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "veyrix",
            "scan",
            "--adapter",
            "local",
            "--variant",
            "hardened",
            "--output",
            str(destination),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads(destination.read_text(encoding="utf-8"))
    assert_score_matches(report, local_engine_score("hardened"))
    assert completed.stdout == ""


def test_console_script_scan(tmp_path):
    candidates = [
        Path(sysconfig.get_path("scripts")) / "veyrix",
        Path.home() / ".local" / "bin" / "veyrix",
    ]
    script = next((path for path in candidates if path.is_file()), None)
    assert script is not None, f"veyrix console script was not installed; looked in {candidates}"
    destination = tmp_path / "script.json"
    completed = subprocess.run(
        [
            str(script),
            "scan",
            "--adapter",
            "local",
            "--variant",
            "vulnerable",
            "--fail-under",
            "100",
            "--output",
            str(destination),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    report = json.loads(destination.read_text(encoding="utf-8"))
    expected = local_engine_score("vulnerable")
    assert_score_matches(report, expected)
    assert completed.returncode == 1
    assert f"Score {expected['score']} is below --fail-under 100." in completed.stderr

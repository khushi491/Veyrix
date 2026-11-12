"""SARIF 2.1.0 export. One rule per scenario; results are verified findings only."""

from typing import Any

from veyrix.engine import ENGINE_VERSION, select_scenarios
from veyrix.engine.catalog import Scenario
from veyrix.scan import ScanError
from veyrix.scoring import digest

SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
REPOSITORY = "https://github.com/khushi491/Veyrix"
LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
SECURITY_SEVERITY = {
    "critical": "9.0",
    "high": "7.0",
    "medium": "5.0",
    "low": "3.0",
    "info": "1.0",
}


def build_sarif(report: dict[str, Any]) -> dict[str, Any]:
    """Build a SARIF log from a completed scan report. No timestamps, so reruns match."""
    configuration = report["configuration"]
    adapter = configuration["adapter"]
    catalog = select_scenarios("all", adapter)
    rules = [_rule(scenario, adapter) for scenario in catalog]
    rule_index = {rule["id"]: index for index, rule in enumerate(rules)}
    artifact = report["target"]["artifact_uri"]
    results = []
    for finding in report["findings"]:
        scenario_id = finding["scenario_id"]
        if scenario_id not in rule_index:
            raise ScanError(f"Verified finding is outside the adapter catalog: {scenario_id}")
        results.append(_result(report, finding, rule_index[scenario_id], artifact))
    score = report["score"]["score"]
    return {
        "$schema": SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Veyrix",
                        "version": ENGINE_VERSION,
                        "semanticVersion": ENGINE_VERSION,
                        "informationUri": REPOSITORY,
                        "rules": rules,
                    }
                },
                "artifacts": [_artifact(artifact)],
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "veyrixScore": score,
                            "veyrixScoreLabel": report["score"]["label"],
                            "veyrixEligible": report["score"]["eligible"],
                        },
                    }
                ],
                "properties": {
                    "veyrixEngineVersion": report["engine_version"],
                    "veyrixScoringVersion": report["scoring_version"],
                    "veyrixAdapter": adapter,
                    "veyrixVariant": configuration["variant"],
                    "veyrixServerVariant": configuration["server_variant"],
                    "veyrixSuite": configuration["suite"],
                },
            }
        ],
    }


def _rule(scenario: Scenario, adapter: str) -> dict[str, Any]:
    level = LEVEL[scenario.severity]
    return {
        "id": scenario.id,
        "name": scenario.id,
        "shortDescription": {"text": scenario.title},
        "fullDescription": {
            "text": (
                f"Checks whether the agent invokes {scenario.action} because of untrusted "
                f"{scenario.channel} content."
            )
        },
        "help": {"text": _help(scenario)},
        "helpUri": _help_uri(adapter),
        "defaultConfiguration": {"enabled": True, "level": level},
        "properties": {
            "tags": ["security", scenario.category],
            "security-severity": SECURITY_SEVERITY[scenario.severity],
            "category": scenario.category,
            "severity": scenario.severity,
            "precision": "high",
        },
    }


def _help(scenario: Scenario) -> str:
    guarded = ""
    if scenario.guarded:
        guarded = (
            " This case expects a policy gate to block the tool before it executes. "
            "A blocked request is still a verified failure."
        )
    return (
        f"{scenario.title}.\n\n"
        f"Attack class: {scenario.id} version {scenario.version}. "
        f"Category: {scenario.category}. Severity: {scenario.severity}. "
        f"Untrusted channel: {scenario.channel}. "
        f"Prohibited action: {scenario.action}.{guarded}\n\n"
        f"Expected behavior: Do not invoke {scenario.action} based on "
        f"{scenario.channel} instructions.\n\n"
        "Remediation: Treat content from this channel as untrusted data, not as "
        "instructions. Preserve the trust boundary between the user task and retrieved "
        "content, and enforce policy before each tool execution. A result is emitted "
        "only after the evidence trace is replayed against the saved policy."
    )


def _help_uri(adapter: str) -> str:
    if adapter == "mcp":
        return f"{REPOSITORY}/blob/main/docs/MCP.md"
    return f"{REPOSITORY}/blob/main/docs/SCENARIOS.md"


def _artifact(uri: str) -> dict[str, Any]:
    artifact: dict[str, Any] = {
        "location": {"uri": uri},
        "description": {"text": "Veyrix scan target. Findings point at this file."},
    }
    if uri.endswith(".toml"):
        artifact["sourceLanguage"] = "toml"
    elif uri.endswith(".json"):
        artifact["sourceLanguage"] = "json"
    return artifact


def _result(
    report: dict[str, Any], finding: dict[str, Any], rule_index: int, artifact: str
) -> dict[str, Any]:
    fingerprint = _fingerprint(report, finding, artifact)
    outcome = finding.get("outcome") or "unconfirmed"
    sequences = ", ".join(str(item) for item in finding["evidence_sequences"]) or "none"
    message = (
        f"{finding['title']}. {finding['actual_behavior']} "
        f"Severity: {finding['severity']}. Outcome: {outcome}. "
        f"Attempted: {str(finding['attempted']).lower()}. "
        f"Executed: {str(finding['executed']).lower()}. "
        f"Evidence event sequences: {sequences}. "
        f"Adapter: {report['configuration']['adapter']}. "
        f"Variant: {report['configuration']['variant']}. "
        f"Engine: {finding['engine_version']}. "
        f"Remediation: {finding['remediation']}"
    )
    return {
        "ruleId": finding["scenario_id"],
        "ruleIndex": rule_index,
        "kind": "fail",
        "level": LEVEL[finding["severity"]],
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": artifact, "index": 0},
                    "region": {"startLine": report["target"]["region_start_line"]},
                }
            }
        ],
        "fingerprints": {"veyrix/v1": fingerprint},
        "partialFingerprints": {
            "primaryLocationLineHash": fingerprint,
            "veyrix/v1": fingerprint,
        },
        "properties": {
            "category": finding["category"],
            "severity": finding["severity"],
            "attempted": finding["attempted"],
            "executed": finding["executed"],
            "outcome": outcome,
            "scenarioVersion": finding["scenario_version"],
            "engineVersion": finding["engine_version"],
            "evidenceSequences": finding["evidence_sequences"],
        },
    }


def _fingerprint(report: dict[str, Any], finding: dict[str, Any], artifact: str) -> str:
    configuration = report["configuration"]
    return digest(
        {
            "v": 1,
            "adapter": configuration["adapter"],
            "variant": configuration["variant"],
            "server_variant": configuration["server_variant"],
            "scenario_id": finding["scenario_id"],
            "scenario_version": finding["scenario_version"],
            "category": finding["category"],
            "severity": finding["severity"],
            "engine_version": finding["engine_version"],
            "artifact": artifact,
            "policy": configuration["policy"],
        }
    )

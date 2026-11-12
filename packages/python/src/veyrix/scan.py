"""In-process assessments that use the same engine, evidence, and score as the API."""

import asyncio
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from veyrix_api.schemas import SecurityPolicy

from veyrix.adapters import SYNTHETIC_SECRET
from veyrix.engine import ENGINE_VERSION, run_scenario, select_scenarios
from veyrix.engine.catalog import Scenario
from veyrix.findings import verified_result
from veyrix.llm.adapter import run_llm_scenario_from_env
from veyrix.llm.config import LLMConfigError, load_llm_run_config
from veyrix.mcp_testing.adapter import run_mcp_scenario
from veyrix.scoring import (
    SCORING_VERSION,
    calculate_score,
    confirmed_blocked,
    scoring_manifest,
)

REPORT_VERSION = "1.0.0"
ADAPTERS = ("local", "mcp", "llm")
VARIANTS = ("vulnerable", "hardened")
PLACEHOLDER_ARTIFACT = "veyrix-target.json"


class TargetError(ValueError):
    """The target configuration is invalid. The message is safe to print."""


class ScanError(RuntimeError):
    """A scenario could not be executed. The message is safe to print."""


@dataclass(frozen=True)
class ScanTarget:
    """Resolved scan target. Policy is the API default when the config omits it."""

    adapter: str
    variant: str
    server_variant: str
    suite: str
    name: str
    policy: dict[str, Any]
    config_path: str | None = None
    artifact_uri: str = PLACEHOLDER_ARTIFACT
    region_start_line: int = 1


def default_name(adapter: str, variant: str, server_variant: str) -> str:
    if adapter == "local":
        if variant == "vulnerable":
            return "Vulnerable document assistant"
        return "Hardened document assistant"
    if adapter == "mcp":
        return f"MCP {variant} agent ({server_variant} server)"
    return f"LLM {variant} agent"


def normalize_policy(policy: dict[str, Any] | None) -> dict[str, Any]:
    """Validate with the API policy model so CLI and server rules match."""
    model = SecurityPolicy() if policy is None else SecurityPolicy.model_validate(policy)
    return model.model_dump()


def artifact_uri(config_path: str | None) -> str:
    """Relative SARIF artifact path. GitHub code scanning rejects absolute URIs."""
    if not config_path:
        return PLACEHOLDER_ARTIFACT
    path = Path(config_path)
    try:
        relative = path.resolve().relative_to(Path.cwd().resolve())
    except ValueError:
        relative = Path(path.name)
    if relative == Path("."):
        return PLACEHOLDER_ARTIFACT
    return quote(relative.as_posix(), safe="/")


def region_start_line(config_path: str | None, variant: str) -> int:
    """Point findings at the variant line when the config file is readable."""
    if not config_path:
        return 1
    try:
        lines = Path(config_path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return 1
    for index, line in enumerate(lines, start=1):
        if variant in line:
            return index
    return 1


def execute_scan(target: ScanTarget) -> dict[str, Any]:
    """Run the selected catalog in-process and score it with calculate_score."""
    _validate_target(target)
    selected = _selected(target)
    catalog = select_scenarios("all", target.adapter)
    model, model_transport, environment = _llm_snapshot(target)
    # Field set matches the configuration stored by veyrix_api.main.execute_local_run.
    configuration: dict[str, Any] = {
        "agent_name": target.name,
        "adapter": target.adapter,
        "server_variant": target.server_variant,
        "variant": target.variant,
        "policy": target.policy,
        "engine_version": ENGINE_VERSION,
        "environment": environment,
        "model": model,
        "suite": target.suite,
        "scenarios": [{"id": scenario.id, "version": scenario.version} for scenario in selected],
        "scoring": scoring_manifest(catalog),
    }
    if model_transport is not None:
        configuration["model_transport"] = model_transport
    results = [_execute(target, scenario, model) for scenario in selected]
    findings = [_finding(result, target.policy) for result in results]
    findings = [finding for finding in findings if finding is not None]
    report = {
        "report_version": REPORT_VERSION,
        "engine_version": ENGINE_VERSION,
        "scoring_version": SCORING_VERSION,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "status": "completed",
        "target": {
            "name": target.name,
            "adapter": target.adapter,
            "variant": target.variant,
            "server_variant": target.server_variant,
            "suite": target.suite,
            "config_path": target.config_path,
            "artifact_uri": target.artifact_uri,
            "region_start_line": target.region_start_line,
        },
        "configuration": configuration,
        "scenarios": [
            _scenario_row(scenario, result)
            for scenario, result in zip(selected, results, strict=True)
        ],
        "verdicts": [_verdict(result) for result in results],
        "findings": findings,
        "results": results,
        "score": calculate_score(configuration, results, "completed"),
        "limitations": limitations(configuration),
    }
    if SYNTHETIC_SECRET in json.dumps(report):
        raise ScanError("Refusing to emit a report that contains the synthetic secret")
    return report


def limitations(configuration: dict[str, Any]) -> list[str]:
    adapter = configuration.get("adapter")
    in_process = (
        "The CLI runs the engine in-process and does not apply the worker subprocess limits."
    )
    if adapter == "llm" and configuration.get("model_transport") == "scripted":
        return [
            "Scripted chat-completions transport; no live model was called.",
            "Scores and findings come from the same evidence pipeline as the local scenarios.",
            "This transport checks the pipeline. It does not measure a production model.",
            in_process,
        ]
    if adapter == "llm":
        return [
            (
                "OpenAI-compatible tool-calling model. "
                "The score describes observed tool use on this run only."
            ),
            "A numeric score is not a certification of the model, provider, or prompt.",
            (
                "Only bundled synthetic tools can run. "
                "The model cannot invoke host commands or real payments."
            ),
            (
                "Cleartext HTTP is limited to a loopback address. "
                "The API key stays in the environment."
            ),
            in_process,
        ]
    notes = [
        "Deterministic synthetic fixture; no external model evaluated.",
        "Synthetic fixtures do not establish robustness of external models.",
        in_process,
    ]
    if adapter == "mcp":
        notes.append(
            "Only the bundled MCP stdio server can be launched. "
            "External MCP servers are not accepted."
        )
    return notes


def outcome_label(result: dict[str, Any]) -> str | None:
    """Same executed/blocked/unconfirmed split the scorer uses."""
    evaluation = result.get("evaluation")
    if not isinstance(evaluation, dict) or evaluation.get("status") != "FAIL":
        return None
    sequences = evaluation.get("evidence_sequences")
    if not isinstance(sequences, list):
        sequences = []
    if evaluation.get("executed"):
        return "executed"
    if confirmed_blocked(result, sequences):
        return "blocked"
    return "unconfirmed"


def _validate_target(target: ScanTarget) -> None:
    if target.adapter not in ADAPTERS:
        raise TargetError("adapter must be local, mcp, or llm.")
    if target.variant not in VARIANTS or target.server_variant not in VARIANTS:
        raise TargetError("variant and server_variant must be vulnerable or hardened.")
    if not isinstance(target.policy, dict):
        raise TargetError("policy must be an object.")


def _selected(target: ScanTarget) -> tuple[Scenario, ...]:
    try:
        return select_scenarios(target.suite, target.adapter)
    except ValueError as exc:
        raise TargetError(str(exc)) from exc


def _llm_snapshot(target: ScanTarget) -> tuple[str | None, str | None, str]:
    if target.adapter != "llm":
        return None, None, "in-memory synthetic fixture"
    try:
        config = load_llm_run_config()
    except LLMConfigError as exc:
        raise TargetError(str(exc)) from exc
    environment = (
        "scripted chat-completions transport"
        if config.transport == "scripted"
        else "openai-compatible chat completions"
    )
    return config.model, config.transport, environment


def _execute(target: ScanTarget, scenario: Scenario, model: str | None) -> dict[str, Any]:
    try:
        if target.adapter == "local":
            result = run_scenario(target.variant, target.policy, scenario)
        elif target.adapter == "mcp":
            result = asyncio.run(
                run_mcp_scenario(
                    target.variant, target.policy, scenario, target.server_variant
                )
            )
        else:
            result = run_llm_scenario_from_env(target.variant, target.policy, scenario, model)
    except (TargetError, ScanError):
        raise
    except Exception as exc:
        # The scenario message stays generic so transport errors cannot leak a key.
        raise ScanError(f"Scenario {scenario.id} failed ({type(exc).__name__}).") from exc
    if (
        result.get("scenario_id") != scenario.id
        or result.get("scenario_version") != scenario.version
        or result.get("engine_version") != ENGINE_VERSION
    ):
        raise ScanError(f"Runner identity differs from the selected scenario: {scenario.id}")
    events = result.get("events")
    if not isinstance(events, list) or [event.get("sequence") for event in events] != list(
        range(1, len(events) + 1)
    ):
        raise ScanError(f"Scenario {scenario.id} did not produce an ordered evidence trace.")
    return result


def _finding(result: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any] | None:
    evidence = verified_result(result, policy)
    if evidence is None:
        return None
    evaluation = evidence["evaluation"]
    timestamp = evidence["events"][-1].get("timestamp") if evidence.get("events") else None
    return {
        "scenario_id": evidence["scenario_id"],
        "scenario_version": evidence["scenario_version"],
        "engine_version": evidence["engine_version"],
        "title": evidence["title"],
        "category": evidence["category"],
        "severity": evidence["severity"],
        "status": "open",
        "observed_at": timestamp,
        "attempted": evaluation["attempted"],
        "executed": evaluation["executed"],
        "evidence_sequences": list(evaluation["evidence_sequences"]),
        "expected_behavior": evidence["expected_behavior"],
        "actual_behavior": evidence["actual_behavior"],
        "remediation": evidence["remediation"],
        "outcome": outcome_label(evidence),
        "result": evidence,
    }


def _scenario_row(scenario: Scenario, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": scenario.id,
        "version": scenario.version,
        "title": scenario.title,
        "category": scenario.category,
        "severity": scenario.severity,
        "channel": scenario.channel,
        "action": scenario.action,
        "guarded": scenario.guarded,
        "verdict": _verdict(result),
    }


def _verdict(result: dict[str, Any]) -> dict[str, Any]:
    evaluation = result["evaluation"]
    return {
        "scenario_id": result["scenario_id"],
        "scenario_version": result["scenario_version"],
        "status": evaluation["status"],
        "reason": evaluation["reason"],
        "attempted": evaluation["attempted"],
        "executed": evaluation["executed"],
        "evidence_sequences": list(evaluation["evidence_sequences"]),
        "outcome": outcome_label(result),
    }

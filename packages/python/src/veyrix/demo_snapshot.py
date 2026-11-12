"""Export a read-only dashboard snapshot from the real local engine.

The two demo agents are configurations of ``LocalAgentAdapter``. This module does not
invent scores, findings, or traces: it runs the saved scenario catalog, scores the
results, and keeps a finding only when evidence verification accepts it.
"""

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from veyrix_api.schemas import SecurityPolicy

from veyrix.adapters import SYNTHETIC_SECRET
from veyrix.engine import ENGINE_VERSION, run_scenario, select_scenarios
from veyrix.engine.catalog import MCP_SCENARIOS, SCENARIOS
from veyrix.findings import verified_result
from veyrix.scoring import SCORING_VERSION, calculate_score, methodology, scoring_manifest

REPO_ROOT = Path(__file__).resolve().parents[4]
SNAPSHOT_PATH = REPO_ROOT / "apps" / "web" / "demo" / "snapshot.json"
REPOSITORY = "https://github.com/khushi491/Veyrix"
FORMAT_VERSION = 1

# Named fixtures executed by the snapshot. Behavior comes from LocalAgentAdapter.
DEMO_AGENTS = (
    {
        "key": "vulnerable",
        "name": "Vulnerable document assistant",
        "description": (
            "Local fixture that follows tool calls embedded in untrusted content."
        ),
        "variant": "vulnerable",
    },
    {
        "key": "hardened",
        "name": "Hardened document assistant",
        "description": (
            "Local fixture that ignores tool calls embedded in untrusted content."
        ),
        "variant": "hardened",
    },
)


def stable_id(name: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{REPOSITORY}/demo/{name}"))


def iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def reproduction_steps(agent_name: str, agent_id: str, evidence: dict[str, Any]) -> list[str]:
    scenario = f"{evidence['scenario_id']} version {evidence['scenario_version']}"
    return [
        f"Select agent {agent_name} ({agent_id}).",
        f"Use engine {evidence['engine_version']}, scenario {scenario}.",
        "Apply the saved adapter, variant, server variant, and policy shown in this assessment.",
        "Run the same suite in the isolated synthetic environment and inspect the linked tool requests.",
        "Compare fresh evidence with this saved trace; triage status does not change the recorded outcome.",
    ]


def suites() -> dict[str, Any]:
    return {
        "engine_version": ENGINE_VERSION,
        "scenarios": [
            {
                "adapter": "mcp" if scenario in MCP_SCENARIOS else "local",
                "id": scenario.id,
                "title": scenario.title,
                "category": scenario.category,
                "severity": scenario.severity,
                "version": scenario.version,
                "channel": scenario.channel,
                "guarded": scenario.guarded,
            }
            for scenario in (*SCENARIOS, *MCP_SCENARIOS)
        ],
    }


def build_snapshot(now: datetime | None = None) -> dict[str, Any]:
    """Run both demo agents through the full local catalog and score the evidence."""
    captured = now or datetime.now(UTC)
    policy = SecurityPolicy().model_dump(mode="json")
    selected = select_scenarios("all", "local")
    project_id = stable_id("project")
    project = {
        "id": project_id,
        "name": "Public demo",
        "description": (
            "Static snapshot of two local fixtures scored by the Veyrix engine. "
            "No live model, database, or worker is attached."
        ),
        "created_at": iso(captured),
    }
    agents = []
    runs = []
    score_entries: dict[str, Any] = {}
    findings = []
    reports: dict[str, Any] = {}
    for spec in DEMO_AGENTS:
        started = datetime.now(UTC)
        results = [run_scenario(spec["variant"], policy, scenario) for scenario in selected]
        finished = datetime.now(UTC)
        agent_id = stable_id(f"agent:{spec['key']}")
        run_id = stable_id(f"run:{spec['key']}")
        agent = {
            "id": agent_id,
            "project_id": project_id,
            "name": spec["name"],
            "description": spec["description"],
            "adapter": "local",
            "variant": spec["variant"],
            "server_variant": "vulnerable",
            "policy": policy,
            "created_at": iso(started),
        }
        configuration = {
            "agent_name": spec["name"],
            "adapter": "local",
            "server_variant": "vulnerable",
            "variant": spec["variant"],
            "policy": policy,
            "engine_version": ENGINE_VERSION,
            "environment": "in-memory synthetic fixture",
            "model": None,
            "suite": "all",
            "scenarios": [{"id": scenario.id, "version": scenario.version} for scenario in selected],
            "scoring": scoring_manifest(select_scenarios("all", "local")),
        }
        assessment = calculate_score(configuration, results, "completed")
        run = {
            "id": run_id,
            "agent_id": agent_id,
            "created_at": iso(started),
            "status": "completed",
            "started_at": iso(started),
            "finished_at": iso(finished),
            "error": None,
            "configuration": configuration,
            "results": results,
        }
        entry = {
            "run_id": run_id,
            "agent_id": agent_id,
            "created_at": run["created_at"],
            "run_status": "completed",
            "snapshot_persisted": True,
            "assessment": assessment,
        }
        agent_findings = []
        for result in results:
            evidence = verified_result(result, policy)
            if evidence is None:
                continue
            timestamp = evidence["events"][-1].get("timestamp")
            observed = datetime.fromisoformat(timestamp) if timestamp else finished
            finding = {
                "id": stable_id(f"finding:{spec['key']}:{result['scenario_id']}"),
                "run_id": run_id,
                "agent_id": agent_id,
                "agent_name": spec["name"],
                "scenario_id": evidence["scenario_id"],
                "scenario_version": evidence["scenario_version"],
                "engine_version": evidence["engine_version"],
                "title": evidence["title"],
                "category": evidence["category"],
                "severity": evidence["severity"],
                "status": "open",
                "observed_at": iso(observed),
                "created_at": iso(finished),
                "attempted": evidence["evaluation"]["attempted"],
                "executed": evidence["evaluation"]["executed"],
                "result": evidence,
                "configuration": configuration,
                "history": [],
                "reproduction_steps": reproduction_steps(spec["name"], agent_id, evidence),
            }
            agent_findings.append(finding)
        summary_keys = (
            "id",
            "run_id",
            "agent_id",
            "agent_name",
            "scenario_id",
            "scenario_version",
            "engine_version",
            "title",
            "category",
            "severity",
            "status",
            "observed_at",
            "created_at",
            "attempted",
            "executed",
        )
        report = {
            "report_version": "0.3.0",
            "security_assessment": entry,
            "generated_at": iso(captured),
            "findings": [{key: finding[key] for key in summary_keys} for finding in agent_findings],
            "run": run,
            "limitations": [
                "Deterministic synthetic fixture; no external model evaluated.",
                "Synthetic fixtures do not establish robustness of external models.",
                "Only bundled fixtures run in bounded subprocesses; external agent isolation is incomplete.",
            ],
        }
        agents.append(agent)
        runs.append(run)
        score_entries[run_id] = entry
        findings.extend(agent_findings)
        reports[run_id] = report
    return {
        "format_version": FORMAT_VERSION,
        "generated_at": iso(captured),
        "generator": "veyrix.demo_snapshot",
        "engine_version": ENGINE_VERSION,
        "scoring_version": SCORING_VERSION,
        "repository": REPOSITORY,
        "notes": [
            "Produced by veyrix.engine.run_scenario, veyrix.scoring.calculate_score, and veyrix.findings.verified_result.",
            "Regenerate with make demo-snapshot. Do not edit scores, findings, or traces by hand.",
            "The snapshot covers the 12 local scenarios. MCP stdio cases stay on the local worker.",
        ],
        "methodology": methodology(),
        "projects": [project],
        "agents": agents,
        "runs": runs,
        "score_entries": score_entries,
        "findings": findings,
        "suites": suites(),
        "reports": reports,
    }


def export_snapshot(path: Path = SNAPSHOT_PATH) -> dict[str, Any]:
    snapshot = build_snapshot()
    encoded = json.dumps(snapshot, indent=2) + "\n"
    if SYNTHETIC_SECRET in encoded:
        raise RuntimeError("Refusing to write a snapshot that contains the synthetic secret")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(encoded, encoding="utf-8")
    return snapshot


def main() -> None:
    snapshot = export_snapshot()
    for agent in snapshot["agents"]:
        run = next(item for item in snapshot["runs"] if item["agent_id"] == agent["id"])
        score = snapshot["score_entries"][run["id"]]["assessment"]["score"]
        count = sum(1 for finding in snapshot["findings"] if finding["agent_id"] == agent["id"])
        print(f"{agent['name']}: score {score}, findings {count}")
    print(f"Wrote {SNAPSHOT_PATH}")


if __name__ == "__main__":
    main()

import copy
import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import Session
from veyrix.engine import ENGINE_VERSION, SCENARIOS, run_scenario
from veyrix.findings import verified_result
from veyrix_api.config import settings
from veyrix_api.db import get_session
from veyrix_api.findings import persist_finding
from veyrix_api.main import app
from veyrix_api.models import Agent, Finding, FindingStatusChange, Project
from veyrix_api.models import TestRun as Run
from veyrix_api.schemas import SecurityPolicy

POLICY = SecurityPolicy().model_dump()


def test_finding_requires_matching_observed_evidence():
    result = run_scenario("vulnerable", POLICY, SCENARIOS[0])
    assert verified_result(result, POLICY) is not None
    forged = copy.deepcopy(result)
    forged["events"] = [e for e in forged["events"] if e["kind"] != "tool_request"]
    assert verified_result(forged, POLICY) is None
    forged = copy.deepcopy(result)
    forged["evaluation"]["executed"] = False
    assert verified_result(forged, POLICY) is None
    assert verified_result(result, {"rules": []}) is None
    passed = run_scenario("hardened", POLICY, SCENARIOS[0])
    passed["evaluation"]["status"] = "FAIL"
    assert verified_result(passed, POLICY) is None
    assert verified_result({"evaluation": None}, POLICY) is None
    malformed = {**result, "events": [{"sequence": 1}]}
    assert verified_result(malformed, POLICY) is None
    malformed = {**result, "evaluation": {**result["evaluation"], "evidence_sequences": [{}]}}
    assert verified_result(malformed, POLICY) is None


def test_blocked_attempt_is_a_finding_without_confirmed_execution():
    scenario = next(s for s in SCENARIOS if s.guarded)
    evidence = verified_result(run_scenario("vulnerable", POLICY, scenario), POLICY)
    assert evidence is not None
    assert evidence["evaluation"]["attempted"] is True
    assert evidence["evaluation"]["executed"] is False


@pytest.fixture
def assessment(monkeypatch):
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL must point to a disposable migrated PostgreSQL database")
    engine = create_engine(url)
    monkeypatch.setattr(settings, "veyrix_dev_mode", True)
    project_ids = []
    findings = []
    with Session(engine) as db:
        for index in range(2):
            project = Project(name=f"Findings integration {index}")
            db.add(project)
            db.flush()
            project_ids.append(project.id)
            agent = Agent(
                project_id=project.id,
                name=f"Observed agent {index}",
                adapter="local",
                variant="vulnerable",
                policy=POLICY,
            )
            db.add(agent)
            db.flush()
            cases = (
                [SCENARIOS[0], next(s for s in SCENARIOS if s.guarded)]
                if index == 0
                else [SCENARIOS[0]]
            )
            results = [run_scenario("vulnerable", POLICY, case) for case in cases]
            run = Run(
                agent_id=agent.id,
                status="completed",
                configuration={
                    "agent_name": agent.name,
                    "policy": POLICY,
                    "adapter": "local",
                    "variant": "vulnerable",
                    "engine_version": ENGINE_VERSION,
                    "scenarios": [{"id": s.id, "version": s.version} for s in cases],
                },
                results=results,
            )
            db.add(run)
            db.flush()
            for result in results:
                finding = persist_finding(db, run, result)
                assert persist_finding(db, run, result).id == finding.id
                findings.append(finding.id)
        db.commit()

    def override():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_session] = override
    try:
        with TestClient(app) as client:
            yield client, project_ids, findings, engine
    finally:
        app.dependency_overrides.clear()
        with Session(engine) as db:
            agent_ids = select(Agent.id).where(Agent.project_id.in_(project_ids))
            run_ids = select(Run.id).where(Run.agent_id.in_(agent_ids))
            finding_ids = select(Finding.id).where(Finding.run_id.in_(run_ids))
            db.execute(
                delete(FindingStatusChange).where(FindingStatusChange.finding_id.in_(finding_ids))
            )
            db.execute(delete(Finding).where(Finding.run_id.in_(run_ids)))
            db.execute(delete(Run).where(Run.agent_id.in_(agent_ids)))
            db.execute(delete(Agent).where(Agent.project_id.in_(project_ids)))
            db.execute(delete(Project).where(Project.id.in_(project_ids)))
            db.commit()
        engine.dispose()


def test_findings_are_project_scoped_searchable_and_paginated(assessment):
    client, projects, findings, _ = assessment
    path = f"/api/projects/{projects[0]}/findings"
    page = client.get(path).json()
    assert page["total"] == 2
    assert {f["id"] for f in page["items"]} == set(findings[:2])
    assert page["severity_distribution"] == {"critical": 1, "high": 1}
    assert all("result" not in f for f in page["items"])
    assert client.get(path, params={"severity": "critical"}).json()["total"] == 1
    assert client.get(path, params={"category": "authorization-boundary"}).json()["total"] == 1
    assert client.get(path, params={"status": "resolved"}).json()["total"] == 0
    assert client.get(path, params={"q": "Observed agent 0"}).json()["total"] == 2
    assert client.get(path, params={"q": "%"}).json()["total"] == 0
    assert client.get(path, params={"agent_id": str(uuid4())}).json()["total"] == 0
    first = client.get(path, params={"limit": 1}).json()
    second = client.get(path, params={"limit": 1, "offset": 1}).json()
    assert first["total"] == second["total"] == 2
    assert first["items"][0]["id"] != second["items"][0]["id"]
    assert client.get(f"{path}/{findings[-1]}").status_code == 404
    assert client.get(path, params={"observed_from": "2099-01-01T00:00:00Z"}).json()["total"] == 0
    assert client.get(path, params={"observed_from": "2026-01-01T00:00:00"}).status_code == 422
    assert (
        client.get(
            path,
            params={
                "observed_from": "2026-02-01T00:00:00Z",
                "observed_before": "2026-01-01T00:00:00Z",
            },
        ).status_code
        == 422
    )
    assert client.get(path, params={"limit": 101}).status_code == 422
    assert client.get(path, params={"severity": "imaginary"}).status_code == 422


def test_triage_is_audited_and_cannot_overwrite_evidence(assessment):
    client, projects, findings, engine = assessment
    path = f"/api/projects/{projects[0]}/findings/{findings[0]}"
    original = client.get(path).json()
    assert original["result"]["evaluation"]["evidence_sequences"]
    assert original["reproduction_steps"] and original["history"] == []
    update = {
        "status": "resolved",
        "expected_status": "open",
        "note": "Authorization gate added; pending retest.",
    }
    changed = client.patch(path, json=update)
    assert changed.status_code == 200, changed.text
    assert changed.json()["result"] == original["result"]
    assert changed.json()["configuration"] == original["configuration"]
    assert changed.json()["history"][0]["note"] == update["note"]
    assert changed.json()["history"][0]["actor"] == "local-developer"
    assert client.patch(path, json=update).status_code == 409
    assert (
        client.patch(
            path, json={"status": "open", "expected_status": "resolved", "note": " "}
        ).status_code
        == 422
    )
    assert client.patch(path, json={**update, "result": {}}).status_code == 422
    outside = f"/api/projects/{projects[1]}/findings/{findings[0]}"
    assert client.patch(outside, json=update).status_code == 404
    # Reindexing an existing result must preserve IDs, status, and original evidence.
    with Session(engine) as db:
        finding = db.get(Finding, findings[0])
        run = db.get(Run, finding.run_id)
        reindexed = persist_finding(db, run, run.results[0])
        assert reindexed.id == finding.id and reindexed.status == "resolved"
        db.commit()
    assert client.get(path).json()["history"] == changed.json()["history"]


def test_findings_api_requires_explicit_development_access(assessment, monkeypatch):
    client, projects, findings, _ = assessment
    monkeypatch.setattr(settings, "veyrix_dev_mode", False)
    path = f"/api/projects/{projects[0]}/findings"
    assert client.get(path).status_code == 503
    assert client.get(f"{path}/{findings[0]}").status_code == 503

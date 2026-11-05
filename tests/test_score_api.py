import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, delete, func, select
from sqlalchemy.orm import Session
from veyrix.engine import ENGINE_VERSION, SCENARIOS, run_scenario
from veyrix.scoring import SCORING_VERSION, scoring_manifest
from veyrix_api.config import settings
from veyrix_api.db import get_session
from veyrix_api.findings import persist_finding
from veyrix_api.main import app
from veyrix_api.models import Agent, Finding, FindingStatusChange, Project, RunScore
from veyrix_api.models import TestRun as Run
from veyrix_api.schemas import SecurityPolicy
from veyrix_api.scoring import persist_score


def run_config(agent):
    return {
        "agent_name": agent.name,
        "adapter": agent.adapter,
        "variant": agent.variant,
        "server_variant": agent.server_variant,
        "engine_version": ENGINE_VERSION,
        "model": None,
        "policy": agent.policy,
        "scenarios": [{"id": s.id, "version": s.version} for s in SCENARIOS],
        "scoring": scoring_manifest(SCENARIOS),
    }


def seed_run(db, agent, config=None):
    config = run_config(agent) if config is None else config
    results = [run_scenario(agent.variant, config["policy"], s) for s in SCENARIOS]
    run = Run(agent_id=agent.id, status="completed", configuration=config, results=results)
    db.add(run)
    db.flush()
    for result in results:
        persist_finding(db, run, result)
    persist_score(db, run)
    return run


@pytest.fixture
def score_data(monkeypatch):
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL must point to a disposable migrated PostgreSQL database")
    engine = create_engine(url)
    monkeypatch.setattr(settings, "veyrix_dev_mode", True)
    with Session(engine) as db:
        projects = [Project(name="Scoring integration"), Project(name="Other scoring project")]
        db.add_all(projects)
        db.flush()
        agents = [
            Agent(
                project_id=projects[index].id,
                name=f"Scoring {variant}",
                adapter="local",
                variant=variant,
                policy=SecurityPolicy().model_dump(),
            )
            for index, variant in [(0, "hardened"), (0, "vulnerable"), (1, "hardened")]
        ]
        db.add_all(agents)
        db.flush()
        runs = [
            seed_run(db, agents[0]),
            seed_run(db, agents[0]),
            seed_run(db, agents[1]),
            seed_run(db, agents[2]),
        ]
        db.commit()
        project_ids = [p.id for p in projects]
        agent_ids = [a.id for a in agents]
        run_ids = [r.id for r in runs]

    def override():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_session] = override
    try:
        with TestClient(app) as client:
            yield client, engine, project_ids, agent_ids, run_ids
    finally:
        app.dependency_overrides.clear()
        with Session(engine) as db:
            run_ids_query = select(Run.id).where(Run.agent_id.in_(agent_ids))
            finding_ids = select(Finding.id).where(Finding.run_id.in_(run_ids_query))
            db.execute(
                delete(FindingStatusChange).where(FindingStatusChange.finding_id.in_(finding_ids))
            )
            db.execute(delete(Finding).where(Finding.run_id.in_(run_ids_query)))
            db.execute(delete(Run).where(Run.agent_id.in_(agent_ids)))
            db.execute(delete(Agent).where(Agent.id.in_(agent_ids)))
            db.execute(delete(Project).where(Project.id.in_(project_ids)))
            db.commit()
        engine.dispose()


def test_saved_scores_reports_and_comparable_project_history(score_data):
    client, _, projects, agents, runs = score_data
    passed = client.get(f"/api/runs/{runs[1]}/score").json()
    assert passed["snapshot_persisted"] and passed["assessment"]["score"] == 100
    failed = client.get(f"/api/runs/{runs[2]}/score").json()
    assert failed["assessment"]["score"] == 4
    report = client.get(f"/api/runs/{runs[2]}/report").json()
    assert report["security_assessment"] == failed
    assert report["report_version"] == "0.3.0"
    group = client.get(f"/api/projects/{projects[0]}/scores", params={"agent_id": agents[0]}).json()
    assert group["latest"]["run_id"] == runs[1]
    assert [entry["run_id"] for entry in group["history"]] == runs[:2]
    assert (
        client.get(
            f"/api/projects/{projects[0]}/scores", params={"agent_id": agents[2]}
        ).status_code
        == 404
    )
    assert client.get(f"/api/runs/{uuid4()}/score").status_code == 404
    assert client.get("/api/scoring/methodology").json()["version"] == SCORING_VERSION


def test_triage_and_reindexing_do_not_change_score_snapshots(score_data):
    client, engine, projects, _, runs = score_data
    original = client.get(f"/api/runs/{runs[2]}/score").json()
    findings = client.get(f"/api/projects/{projects[0]}/findings").json()
    finding = findings["items"][0]
    response = client.patch(
        f"/api/projects/{projects[0]}/findings/{finding['id']}",
        json={
            "status": "resolved",
            "expected_status": "open",
            "note": "Review decision; fresh verification still required.",
        },
    )
    assert response.status_code == 200
    assert client.get(f"/api/runs/{runs[2]}/score").json() == original
    with Session(engine) as db:
        run = db.get(Run, runs[2])
        first = persist_score(db, run)
        assert persist_score(db, run) is first
        db.commit()
        assert (
            db.scalar(select(func.count()).select_from(RunScore).where(RunScore.run_id == run.id))
            == 1
        )


def test_pending_latest_run_cannot_inherit_previous_high_score(score_data):
    client, engine, projects, agents, _ = score_data
    with Session(engine) as db:
        agent = db.get(Agent, agents[0])
        run = Run(agent_id=agent.id, status="queued", configuration=run_config(agent), results=[])
        db.add(run)
        db.commit()
        run_id = run.id
    group = client.get(f"/api/projects/{projects[0]}/scores", params={"agent_id": agents[0]}).json()
    assert group["latest"]["run_id"] == run_id
    assert group["latest"]["assessment"]["score"] is None
    assert not group["latest"]["snapshot_persisted"]
    with Session(engine) as db:
        assert db.scalar(select(RunScore).where(RunScore.run_id == run_id)) is None
    assert client.post(f"/api/runs/{run_id}/cancel").json()["status"] == "cancelled"
    cancelled = client.get(f"/api/runs/{run_id}/score").json()
    assert cancelled["snapshot_persisted"] and cancelled["assessment"]["score"] is None


def test_policy_change_starts_a_separate_history_scope(score_data):
    client, engine, projects, agents, runs = score_data
    with Session(engine) as db:
        agent = db.get(Agent, agents[0])
        config = run_config(agent)
        config["policy"] = {**config["policy"], "policy_id": "changed-policy"}
        changed = seed_run(db, agent, config)
        db.commit()
        changed_id = changed.id
    group = client.get(f"/api/projects/{projects[0]}/scores", params={"agent_id": agents[0]}).json()
    assert group["latest"]["run_id"] == changed_id
    assert len(group["history"]) == 1
    assert group["history"][0]["run_id"] not in runs


def test_legacy_run_remains_unscored_without_rewriting_saved_configuration(score_data):
    client, engine, _, agents, _ = score_data
    with Session(engine) as db:
        agent = db.get(Agent, agents[0])
        config = run_config(agent)
        config.pop("scoring")
        run = Run(
            agent_id=agent.id,
            status="completed",
            configuration=config,
            results=[run_scenario(agent.variant, agent.policy, s) for s in SCENARIOS],
        )
        db.add(run)
        db.commit()
        run_id = run.id
    score = client.get(f"/api/runs/{run_id}/score").json()
    assert score["assessment"]["score"] is None
    assert not score["snapshot_persisted"]
    assert "fresh assessment" in score["assessment"]["reasons"][0]
    assert "scoring" not in client.get(f"/api/runs/{run_id}").json()["configuration"]


def test_score_endpoints_require_explicit_local_access(score_data, monkeypatch):
    client, _, projects, agents, runs = score_data
    monkeypatch.setattr(settings, "veyrix_dev_mode", False)
    assert client.get(f"/api/runs/{runs[0]}/score").status_code == 503
    assert client.get("/api/scoring/methodology").status_code == 503
    assert (
        client.get(
            f"/api/projects/{projects[0]}/scores", params={"agent_id": agents[0]}
        ).status_code
        == 503
    )


def test_history_orders_instants_with_different_fractional_precision(score_data):
    client, engine, projects, agents, runs = score_data
    whole_second = datetime(2026, 11, 5, 12, tzinfo=UTC)
    with Session(engine) as db:
        db.get(Run, runs[0]).created_at = whole_second
        db.get(Run, runs[1]).created_at = whole_second + timedelta(microseconds=1)
        db.commit()
    response = client.get(f"/api/projects/{projects[0]}/scores", params={"agent_id": agents[0]})
    assert response.status_code == 200
    assert response.json()["latest"]["run_id"] == runs[1]
    assert [entry["run_id"] for entry in response.json()["history"]] == runs[:2]

import os
import subprocess
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import Session
from veyrix.engine import ENGINE_VERSION, SCENARIO_VERSION, SCENARIOS
from veyrix_api.models import Agent, Finding, FindingStatusChange, Project
from veyrix_api.models import TestRun as Run
from veyrix_api.worker import claim_next, process_one, recover_interrupted, update_owned


@pytest.fixture
def queued_run():
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL must reference a disposable migrated PostgreSQL database")
    engine = create_engine(url)
    with Session(engine) as db:
        project = Project(name="Worker integration")
        db.add(project)
        db.flush()
        agent = Agent(
            project_id=project.id,
            name="Fixture",
            adapter="local",
            variant="vulnerable",
            policy={"rules": [{"action": "transfer_funds", "effect": "deny"}]},
        )
        db.add(agent)
        db.flush()
        run = Run(
            agent_id=agent.id,
            status="queued",
            configuration={
                "variant": agent.variant,
                "policy": agent.policy,
                "engine_version": ENGINE_VERSION,
                "scenarios": [{"id": s.id, "version": SCENARIO_VERSION} for s in SCENARIOS],
            },
            results=[],
        )
        db.add(run)
        db.commit()
        ids = project.id, agent.id, run.id
    try:
        yield engine, ids[2]
    finally:
        with Session(engine) as db:
            finding_ids = select(Finding.id).where(Finding.run_id == ids[2])
            db.execute(
                delete(FindingStatusChange).where(FindingStatusChange.finding_id.in_(finding_ids))
            )
            db.execute(delete(Finding).where(Finding.run_id == ids[2]))
            for model, record_id in [(Run, ids[2]), (Agent, ids[1]), (Project, ids[0])]:
                db.delete(db.get(model, record_id))
            db.commit()
        engine.dispose()


def test_claim_is_exclusive_and_completed_run_is_not_replayed(queued_run):
    engine, run_id = queued_run
    claimed = claim_next(engine)
    assert claimed[0] == run_id
    assert claim_next(engine) is None
    token = claimed[1]
    assert update_owned(engine, run_id, "wrong-token") is False
    assert update_owned(engine, run_id, token, finish=True) is False
    assert process_one(engine) is False


def test_expired_worker_does_not_replay_or_overwrite(queued_run):
    engine, run_id = queued_run
    _, token, _ = claim_next(engine)
    with Session(engine) as db:
        run = db.get(Run, run_id)
        run.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
    recover_interrupted(engine)
    assert not update_owned(engine, run_id, token, result={"late": "result"})
    with Session(engine) as db:
        run = db.get(Run, run_id)
        assert run.status == "error" and run.results == []
        assert "interrupted" in run.error


def test_cancellation_stops_following_scenarios(queued_run, monkeypatch):
    engine, run_id = queued_run

    def cancelling_runner(*args):
        with Session(engine) as db:
            run = db.get(Run, run_id)
            run.status = "cancelling"
            db.commit()
        return {
            "scenario_version": SCENARIO_VERSION,
            "scenario_id": args[1],
            "engine_version": ENGINE_VERSION,
            "observed": True,
        }

    monkeypatch.setattr("veyrix_api.worker.execute_scenario", cancelling_runner)
    assert process_one(engine)
    with Session(engine) as db:
        run = db.get(Run, run_id)
        assert run.status == "cancelled"
        assert len(run.results) == 1
        assert run.finished_at is not None


def test_timeout_is_an_error_not_a_security_pass(queued_run, monkeypatch):
    engine, run_id = queued_run

    def timeout(*args):
        raise subprocess.TimeoutExpired("bundled-runner", 15)

    monkeypatch.setattr("veyrix_api.worker.execute_scenario", timeout)
    assert process_one(engine)
    with Session(engine) as db:
        run = db.get(Run, run_id)
        assert run.status == "error" and run.results == []
        assert "timeout" in run.error

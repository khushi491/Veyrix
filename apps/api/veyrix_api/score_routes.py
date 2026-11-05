"""Scoped assessment scores; no aggregation across incompatible configurations."""

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from veyrix.scoring import SCORING_VERSION, methodology

from veyrix_api.dependencies import Db, local_access
from veyrix_api.models import Agent, RunScore, TestRun
from veyrix_api.scoring import assessment_entry

router = APIRouter(prefix="/api", dependencies=[Depends(local_access)])


@router.get("/scoring/methodology")
def scoring_methodology() -> dict:
    return methodology()


@router.get("/runs/{run_id}/score")
def run_score(run_id: UUID, db: Db) -> dict:
    run = db.get(TestRun, str(run_id))
    if run is None:
        raise HTTPException(404, "Run not found")
    return assessment_entry(db, run)


@router.get("/projects/{project_id}/scores")
def agent_scores(project_id: UUID, agent_id: UUID, db: Db) -> dict:
    agent = db.get(Agent, str(agent_id))
    if agent is None or agent.project_id != str(project_id):
        raise HTTPException(404, "Agent not found in this project")
    latest = db.scalar(
        select(TestRun)
        .where(TestRun.agent_id == agent.id)
        .order_by(TestRun.created_at.desc(), TestRun.id.desc())
        .limit(1)
    )
    if latest is None:
        return {
            "agent_id": agent.id,
            "agent_name": agent.name,
            "latest": None,
            "history": [],
            "methodology": methodology(),
        }
    entry = assessment_entry(db, latest)
    fingerprint = entry["assessment"]["scope_fingerprint"]
    history = [entry]
    if fingerprint:
        runs = db.scalars(
            select(TestRun)
            .join(RunScore, RunScore.run_id == TestRun.id)
            .where(
                TestRun.agent_id == agent.id,
                RunScore.methodology_version == SCORING_VERSION,
                RunScore.scope_fingerprint == fingerprint,
            )
            .order_by(TestRun.created_at.desc(), TestRun.id.desc())
            .limit(20)
        )
        history.extend(assessment_entry(db, run) for run in runs if run.id != latest.id)
    history = sorted(
        history, key=lambda item: (datetime.fromisoformat(item["created_at"]), item["run_id"])
    )[-20:]
    return {
        "agent_id": agent.id,
        "agent_name": agent.name,
        "latest": entry,
        "history": history,
        "methodology": methodology(),
    }

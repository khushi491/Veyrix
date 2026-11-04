import json
from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Response
from sqlalchemy import select, text
from sqlalchemy.orm import Session
from veyrix.engine import ENGINE_VERSION, SCENARIOS, run_scenario

from veyrix_api.config import settings
from veyrix_api.db import get_session
from veyrix_api.models import Agent, Project, TestRun
from veyrix_api.schemas import AgentCreate, AgentRead, ProjectCreate, ProjectRead, RunRead

app = FastAPI(title="Veyrix API", version="0.1.0")
Db = Annotated[Session, Depends(get_session)]


def local_access() -> None:
    if not settings.veyrix_dev_mode:
        raise HTTPException(
            503, "Hosted authentication is not implemented; enable local development mode"
        )


Local = Depends(local_access)


@app.get("/health")
def health(db: Db) -> dict[str, str]:
    db.execute(text("SELECT 1"))
    return {"status": "ok", "version": "0.1.0"}


@app.get("/api/projects", response_model=list[ProjectRead], dependencies=[Local])
def projects(db: Db) -> list[Project]:
    return list(db.scalars(select(Project).order_by(Project.created_at.desc()).limit(100)))


@app.post("/api/projects", response_model=ProjectRead, status_code=201, dependencies=[Local])
def create_project(payload: ProjectCreate, db: Db) -> Project:
    project = Project(**payload.model_dump())
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


def require_project(project_id: UUID, db: Session) -> Project:
    project = db.get(Project, str(project_id))
    if project is None:
        raise HTTPException(404, "Project not found")
    return project


@app.get("/api/projects/{project_id}/agents", response_model=list[AgentRead], dependencies=[Local])
def agents(project_id: UUID, db: Db) -> list[Agent]:
    require_project(project_id, db)
    return list(db.scalars(select(Agent).where(Agent.project_id == str(project_id)).limit(100)))


@app.post(
    "/api/projects/{project_id}/agents",
    response_model=AgentRead,
    status_code=201,
    dependencies=[Local],
)
def create_agent(project_id: UUID, payload: AgentCreate, db: Db) -> Agent:
    require_project(project_id, db)
    agent = Agent(project_id=str(project_id), **payload.model_dump())
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return agent


@app.post(
    "/api/agents/{agent_id}/runs", response_model=RunRead, status_code=201, dependencies=[Local]
)
def execute_local_run(agent_id: UUID, db: Db) -> TestRun:
    agent = db.get(Agent, str(agent_id))
    if agent is None:
        raise HTTPException(404, "Agent not found")
    results = [run_scenario(agent.variant, agent.policy, scenario) for scenario in SCENARIOS]
    run = TestRun(
        agent_id=agent.id,
        status="completed",
        configuration={
            "agent_name": agent.name,
            "adapter": agent.adapter,
            "variant": agent.variant,
            "policy": agent.policy,
            "engine_version": ENGINE_VERSION,
            "environment": "in-memory synthetic fixture",
            "model": None,
        },
        results=results,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


@app.get("/api/agents/{agent_id}/runs", response_model=list[RunRead], dependencies=[Local])
def agent_runs(agent_id: UUID, db: Db) -> list[TestRun]:
    if db.get(Agent, str(agent_id)) is None:
        raise HTTPException(404, "Agent not found")
    return list(
        db.scalars(
            select(TestRun)
            .where(TestRun.agent_id == str(agent_id))
            .order_by(TestRun.created_at.desc())
            .limit(100)
        )
    )


@app.get("/api/runs/{run_id}", response_model=RunRead, dependencies=[Local])
def run_details(run_id: UUID, db: Db) -> TestRun:
    run = db.get(TestRun, str(run_id))
    if run is None:
        raise HTTPException(404, "Run not found")
    return run


@app.get("/api/runs/{run_id}/report", dependencies=[Local])
def json_report(run_id: UUID, db: Db) -> Response:
    run = run_details(run_id, db)
    report = {
        "report_version": "0.1.0",
        "run": RunRead.model_validate(run).model_dump(mode="json"),
        "limitations": [
            "Deterministic synthetic fixture; no external model evaluated.",
            "One scenario; insufficient coverage for a security score.",
            "Execution is synchronous; isolated container runner is not implemented.",
        ],
    }
    return Response(
        json.dumps(report, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="veyrix-{run.id}.json"'},
    )

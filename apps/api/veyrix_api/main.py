import json
from datetime import UTC, datetime
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Response
from sqlalchemy import select, text
from sqlalchemy.orm import Session
from veyrix.engine import ENGINE_VERSION, SCENARIOS, select_scenarios
from veyrix.engine.catalog import MCP_SCENARIOS

from veyrix_api.dependencies import Db, local_access
from veyrix_api.finding_routes import router as finding_router
from veyrix_api.finding_routes import summary as finding_summary
from veyrix_api.jobs import notify_worker
from veyrix_api.models import Agent, Finding, Project, TestRun
from veyrix_api.schemas import (
    AgentCreate,
    AgentRead,
    ProjectCreate,
    ProjectRead,
    RunCreate,
    RunRead,
)

app = FastAPI(title="Veyrix API", version="0.1.0")
app.include_router(finding_router)


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
    "/api/agents/{agent_id}/runs", response_model=RunRead, status_code=202, dependencies=[Local]
)
def execute_local_run(agent_id: UUID, db: Db, payload: RunCreate | None = None) -> TestRun:
    agent = db.get(Agent, str(agent_id))
    if agent is None:
        raise HTTPException(404, "Agent not found")
    suite = payload.suite if payload else "all"
    try:
        selected = select_scenarios(suite, agent.adapter)
    except ValueError as exc:
        raise HTTPException(422, "Selected suite is unavailable for this adapter") from exc
    run = TestRun(
        agent_id=agent.id,
        status="queued",
        configuration={
            "agent_name": agent.name,
            "adapter": agent.adapter,
            "server_variant": agent.server_variant,
            "variant": agent.variant,
            "policy": agent.policy,
            "engine_version": ENGINE_VERSION,
            "environment": "in-memory synthetic fixture",
            "model": None,
            "suite": suite,
            "scenarios": [{"id": s.id, "version": s.version} for s in selected],
        },
        results=[],
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    notify_worker()
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
    if run.status in {"queued", "running", "cancelling"}:
        raise HTTPException(409, "Assessment is still active; export after it finishes")
    report = {
        "report_version": "0.2.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "findings": [
            finding_summary(*row).model_dump(mode="json")
            for row in db.execute(
                select(Finding, TestRun, Agent)
                .join(TestRun, Finding.run_id == TestRun.id)
                .join(Agent, TestRun.agent_id == Agent.id)
                .where(TestRun.id == run.id)
                .order_by(Finding.observed_at, Finding.id)
            )
        ],
        "run": RunRead.model_validate(run).model_dump(mode="json"),
        "limitations": [
            "Deterministic synthetic fixture; no external model evaluated.",
            "Synthetic fixtures do not establish robustness of external models.",
            "Only bundled fixtures run in bounded subprocesses; external agent isolation is incomplete.",
        ],
    }
    return Response(
        json.dumps(report, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="veyrix-{run.id}.json"'},
    )


@app.post("/api/runs/{run_id}/cancel", response_model=RunRead, dependencies=[Local])
def cancel_run(run_id: UUID, db: Db) -> TestRun:
    run = db.scalar(select(TestRun).where(TestRun.id == str(run_id)).with_for_update())
    if run is None:
        raise HTTPException(404, "Run not found")
    if run.status == "queued":
        run.status = "cancelled"
        run.finished_at = datetime.now(UTC)
    elif run.status == "running":
        run.status = "cancelling"
    db.commit()
    db.refresh(run)
    return run


@app.get("/api/suites", dependencies=[Local])
def suites() -> dict:
    return {
        "engine_version": ENGINE_VERSION,
        "scenarios": [
            {
                "adapter": "mcp" if s in MCP_SCENARIOS else "local",
                "id": s.id,
                "title": s.title,
                "category": s.category,
                "severity": s.severity,
                "version": s.version,
                "channel": s.channel,
                "guarded": s.guarded,
            }
            for s in (*SCENARIOS, *MCP_SCENARIOS)
        ],
    }

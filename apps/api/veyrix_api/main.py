from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from veyrix_api.config import settings
from veyrix_api.db import get_session
from veyrix_api.models import Agent, Project
from veyrix_api.schemas import AgentCreate, AgentRead, ProjectCreate, ProjectRead

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

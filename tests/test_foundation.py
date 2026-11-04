import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from veyrix_api.config import settings
from veyrix_api.db import get_session
from veyrix_api.main import app
from veyrix_api.models import Base
from veyrix_api.schemas import AgentCreate, ProjectCreate


def test_configuration_validation():
    with pytest.raises(ValidationError):
        ProjectCreate(name="   ")
    with pytest.raises(ValidationError):
        AgentCreate(name="unsafe", adapter="shell")
    with pytest.raises(ValidationError):
        AgentCreate(name="unsafe", policy={"rules": [{"action": "arbitrary_shell"}]})


def test_development_mode_is_explicit(monkeypatch):
    monkeypatch.setattr(settings, "veyrix_dev_mode", False)
    with TestClient(app) as client:
        assert client.get("/api/projects").status_code == 503


def test_postgres_project_and_agent_persistence(monkeypatch):
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("Set TEST_DATABASE_URL to a disposable migrated PostgreSQL database")
    engine = create_engine(url)
    monkeypatch.setattr(settings, "veyrix_dev_mode", True)

    def session_override():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = session_override
    project_id = None
    try:
        with TestClient(app) as client:
            assert client.get("/health").status_code == 200
            project = client.post("/api/projects", json={"name": "Integration " + str(uuid4())})
            assert project.status_code == 201
            project_id = project.json()["id"]
            agent = client.post(f"/api/projects/{project_id}/agents", json={"name": "Hardened"})
            assert agent.status_code == 201
            assert agent.json()["variant"] == "hardened"
            assert (
                client.get(f"/api/projects/{project_id}/agents").json()[0]["id"]
                == agent.json()["id"]
            )
            assert any(p["id"] == project_id for p in client.get("/api/projects").json())
            assert (
                client.post(f"/api/projects/{uuid4()}/agents", json={"name": "orphan"}).status_code
                == 404
            )
            assert client.post("/api/projects", json={"name": ""}).status_code == 422
        # A fresh connection observes the committed records.
        with engine.connect() as connection:
            table = Base.metadata.tables["agents"]
            assert connection.execute(
                table.select().where(table.c.project_id == project_id)
            ).first()
    finally:
        if project_id:
            with engine.begin() as connection:
                for name in ("agents", "projects"):
                    table = Base.metadata.tables[name]
                    column = table.c.project_id if name == "agents" else table.c.id
                    connection.execute(table.delete().where(column == project_id))
        app.dependency_overrides.clear()
        engine.dispose()

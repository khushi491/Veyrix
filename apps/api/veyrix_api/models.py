from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Record:
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class Project(Record, Base):
    __tablename__ = "projects"
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text, default="")


class Agent(Record, Base):
    __tablename__ = "agents"
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text, default="")
    adapter: Mapped[str] = mapped_column(String(32))
    variant: Mapped[str] = mapped_column(String(32))
    server_variant: Mapped[str] = mapped_column(String(32), default="vulnerable")
    policy: Mapped[dict] = mapped_column(JSON)


class TestRun(Record, Base):
    __tablename__ = "test_runs"
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    configuration: Mapped[dict] = mapped_column(JSON)
    results: Mapped[list] = mapped_column(JSON)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    worker_token: Mapped[str | None] = mapped_column(String(36))
    error: Mapped[str | None] = mapped_column(Text)


class Finding(Record, Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("run_id", "scenario_id", name="uq_findings_run_scenario"),)
    run_id: Mapped[str] = mapped_column(ForeignKey("test_runs.id"), index=True)
    scenario_id: Mapped[str] = mapped_column(String(120))
    scenario_version: Mapped[str] = mapped_column(String(32))
    engine_version: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(300))
    category: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    attempted: Mapped[bool] = mapped_column(Boolean)
    executed: Mapped[bool] = mapped_column(Boolean)
    result: Mapped[dict] = mapped_column(JSON)


class FindingStatusChange(Record, Base):
    __tablename__ = "finding_status_changes"
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    previous_status: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32))
    note: Mapped[str] = mapped_column(Text)
    actor: Mapped[str] = mapped_column(String(120), default="local-developer")

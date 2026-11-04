"""Project-scoped searchable findings with immutable evidence and audited triage."""

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select

from veyrix_api.dependencies import Db, local_access
from veyrix_api.models import Agent, Finding, FindingStatusChange, Project, TestRun
from veyrix_api.schemas import (
    FindingCategory,
    FindingChangeRead,
    FindingDetail,
    FindingPage,
    FindingStatus,
    FindingSummary,
    FindingUpdate,
    Severity,
)

router = APIRouter(
    prefix="/api/projects/{project_id}/findings", dependencies=[Depends(local_access)]
)


def project_query(project_id: UUID):
    return (
        select(Finding, TestRun, Agent)
        .join(TestRun, Finding.run_id == TestRun.id)
        .join(Agent, TestRun.agent_id == Agent.id)
        .where(Agent.project_id == str(project_id))
    )


def summary(finding: Finding, run: TestRun, agent: Agent) -> FindingSummary:
    return FindingSummary(
        **{
            key: getattr(finding, key)
            for key in FindingSummary.model_fields
            if key not in {"agent_id", "agent_name"}
        },
        agent_id=agent.id,
        agent_name=run.configuration.get("agent_name", agent.name),
    )


def detail(db, finding: Finding, run: TestRun, agent: Agent) -> FindingDetail:
    history = db.scalars(
        select(FindingStatusChange)
        .where(FindingStatusChange.finding_id == finding.id)
        .order_by(FindingStatusChange.created_at, FindingStatusChange.id)
    )
    return FindingDetail(
        **summary(finding, run, agent).model_dump(),
        result=finding.result,
        configuration=run.configuration,
        history=[FindingChangeRead.model_validate(item) for item in history],
        reproduction_steps=[
            f"Select agent {run.configuration.get('agent_name', agent.name)} ({agent.id}).",
            f"Use engine {finding.engine_version}, scenario {finding.scenario_id} version {finding.scenario_version}.",
            "Apply the saved adapter, variant, server variant, and policy shown in this assessment.",
            "Run the same suite in the isolated synthetic environment and inspect the linked tool requests.",
            "Compare fresh evidence with this saved trace; triage status does not change the recorded outcome.",
        ],
    )


@router.get("", response_model=FindingPage)
def list_findings(
    project_id: UUID,
    db: Db,
    severity: Severity | None = None,
    status: FindingStatus | None = None,
    agent_id: UUID | None = None,
    category: FindingCategory | None = None,
    q: str = Query("", max_length=200),
    observed_from: datetime | None = None,
    observed_before: datetime | None = None,
    offset: int = Query(0, ge=0, le=100000),
    limit: int = Query(25, ge=1, le=100),
) -> FindingPage:
    if db.get(Project, str(project_id)) is None:
        raise HTTPException(404, "Project not found")
    for value in (observed_from, observed_before):
        if value is not None and value.tzinfo is None:
            raise HTTPException(422, "Date filters must include a timezone")
    if observed_from and observed_before and observed_from >= observed_before:
        raise HTTPException(422, "Date range must have a start before its end")
    query = project_query(project_id)
    for column, value in (
        (Finding.severity, severity),
        (Finding.status, status),
        (Agent.id, str(agent_id) if agent_id else None),
        (Finding.category, category),
    ):
        if value is not None:
            query = query.where(column == value)
    if q.strip():
        # Escaped LIKE is a literal substring search, including %, _ and backslash.
        query = query.where(
            or_(
                Finding.title.icontains(q.strip(), autoescape=True),
                Finding.scenario_id.icontains(q.strip(), autoescape=True),
                TestRun.configuration["agent_name"]
                .as_string()
                .icontains(q.strip(), autoescape=True),
            )
        )
    if observed_from:
        query = query.where(Finding.observed_at >= observed_from)
    if observed_before:
        query = query.where(Finding.observed_at < observed_before)
    filtered = query.with_only_columns(Finding.id, Finding.severity).subquery()
    total = db.scalar(select(func.count()).select_from(filtered))
    distribution = dict(
        db.execute(select(filtered.c.severity, func.count()).group_by(filtered.c.severity)).all()
    )
    rows = db.execute(
        query.order_by(Finding.observed_at.desc(), Finding.id.desc()).offset(offset).limit(limit)
    )
    return FindingPage(
        items=[summary(*row) for row in rows],
        total=total,
        offset=offset,
        limit=limit,
        severity_distribution=distribution,
    )


@router.get("/{finding_id}", response_model=FindingDetail)
def finding_detail(project_id: UUID, finding_id: UUID, db: Db) -> FindingDetail:
    row = db.execute(project_query(project_id).where(Finding.id == str(finding_id))).first()
    if row is None:
        raise HTTPException(404, "Finding not found in this project")
    return detail(db, *row)


@router.patch("/{finding_id}", response_model=FindingDetail)
def update_finding(
    project_id: UUID, finding_id: UUID, payload: FindingUpdate, db: Db
) -> FindingDetail:
    row = db.execute(
        project_query(project_id).where(Finding.id == str(finding_id)).with_for_update(of=Finding)
    ).first()
    if row is None:
        raise HTTPException(404, "Finding not found in this project")
    finding, run, agent = row
    if finding.status != payload.expected_status:
        raise HTTPException(409, "Finding status changed; refresh before saving")
    if finding.status != payload.status:
        db.add(
            FindingStatusChange(
                finding_id=finding.id,
                previous_status=finding.status,
                status=payload.status,
                note=payload.note,
                actor="local-developer",
            )
        )
        finding.status = payload.status
    db.commit()
    db.refresh(finding)
    return detail(db, finding, run, agent)

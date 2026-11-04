"""Transactional finding creation from persisted execution evidence."""

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session
from veyrix.findings import verified_result

from veyrix_api.models import Finding, TestRun


def persist_finding(db: Session, run: TestRun, result: dict) -> Finding | None:
    if result.get("engine_version") != run.configuration.get("engine_version"):
        return None
    cases = run.configuration.get("scenarios")
    if cases is not None and not any(
        s["id"] == result.get("scenario_id") and s["version"] == result.get("scenario_version")
        for s in cases
    ):
        return None
    evidence = verified_result(result, run.configuration.get("policy", {}))
    if evidence is None:
        return None
    existing = db.scalar(
        select(Finding).where(
            Finding.run_id == run.id, Finding.scenario_id == evidence["scenario_id"]
        )
    )
    if existing is not None:
        return existing
    timestamp = evidence["events"][-1].get("timestamp")
    observed_at = datetime.fromisoformat(timestamp) if timestamp else run.created_at
    if observed_at.tzinfo is None:
        observed_at = observed_at.replace(tzinfo=UTC)
    finding = Finding(
        run_id=run.id,
        scenario_id=evidence["scenario_id"],
        scenario_version=evidence["scenario_version"],
        engine_version=evidence["engine_version"],
        title=evidence["title"],
        category=evidence["category"],
        severity=evidence["severity"],
        status="open",
        observed_at=observed_at,
        attempted=evidence["evaluation"]["attempted"],
        executed=evidence["evaluation"]["executed"],
        result=evidence,
    )
    db.add(finding)
    db.flush()
    return finding

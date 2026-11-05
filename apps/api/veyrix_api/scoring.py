"""Run score snapshots and read-only assessment previews."""

from datetime import UTC

from sqlalchemy import select
from sqlalchemy.orm import Session
from veyrix.scoring import SCORING_VERSION, calculate_score

from veyrix_api.models import RunScore, TestRun


def stored_score(db: Session, run: TestRun) -> RunScore | None:
    return db.scalar(
        select(RunScore).where(
            RunScore.run_id == run.id, RunScore.methodology_version == SCORING_VERSION
        )
    )


def assessment_entry(db: Session, run: TestRun) -> dict:
    saved = stored_score(db, run)
    assessment = (
        saved.assessment if saved else calculate_score(run.configuration, run.results, run.status)
    )
    return {
        "run_id": run.id,
        "agent_id": run.agent_id,
        "created_at": run.created_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "run_status": run.status,
        "snapshot_persisted": saved is not None,
        "assessment": assessment,
    }


def persist_score(db: Session, run: TestRun) -> RunScore:
    # Caller owns the run row lock and transaction. Never overwrite a saved assessment.
    existing = stored_score(db, run)
    if existing:
        return existing
    assessment = calculate_score(run.configuration, run.results, run.status)
    score = RunScore(
        run_id=run.id,
        methodology_version=SCORING_VERSION,
        scope_fingerprint=assessment["scope_fingerprint"],
        score=assessment["score"],
        assessment=assessment,
    )
    db.add(score)
    return score

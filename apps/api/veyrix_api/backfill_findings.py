"""Index existing terminal-run evidence; idempotent, never reruns an attack."""

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from veyrix_api.db import engine
from veyrix_api.findings import persist_finding
from veyrix_api.models import TestRun


def backfill(db_engine: Engine = engine) -> int:
    indexed = 0
    cursor = ""
    while True:
        with Session(db_engine) as db:
            ids = list(
                db.scalars(
                    select(TestRun.id)
                    .where(
                        TestRun.id > cursor, TestRun.status.in_(["completed", "cancelled", "error"])
                    )
                    .order_by(TestRun.id)
                    .limit(100)
                )
            )
        if not ids:
            return indexed
        for run_id in ids:
            with Session(db_engine) as db:
                run = db.scalar(select(TestRun).where(TestRun.id == run_id).with_for_update())
                for result in run.results:
                    finding = persist_finding(db, run, result)
                    indexed += finding is not None
                db.commit()
        cursor = ids[-1]


if __name__ == "__main__":
    count = backfill()
    print(
        f"Indexed {count} verified scenario results; existing finding IDs and triage are preserved."
    )

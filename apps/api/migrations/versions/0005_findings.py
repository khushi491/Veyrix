"""Persist verified findings and auditable triage changes."""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("run_id", sa.String(36), sa.ForeignKey("test_runs.id"), nullable=False),
        sa.Column("scenario_id", sa.String(120), nullable=False),
        sa.Column("scenario_version", sa.String(32), nullable=False),
        sa.Column("engine_version", sa.String(32), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempted", sa.Boolean(), nullable=False),
        sa.Column("executed", sa.Boolean(), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.UniqueConstraint("run_id", "scenario_id", name="uq_findings_run_scenario"),
    )
    for column in ("run_id", "category", "severity", "status", "observed_at"):
        op.create_index(f"ix_findings_{column}", "findings", [column])
    op.create_table(
        "finding_status_changes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("previous_status", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("actor", sa.String(120), nullable=False),
    )
    op.create_index(
        "ix_finding_status_changes_finding_id", "finding_status_changes", ["finding_id"]
    )


def downgrade() -> None:
    op.drop_table("finding_status_changes")
    op.drop_table("findings")

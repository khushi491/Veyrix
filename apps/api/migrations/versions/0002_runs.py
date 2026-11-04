"""Persist reproducible run snapshots and observable evidence."""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "test_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("agent_id", sa.String(36), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("configuration", sa.JSON(), nullable=False),
        sa.Column("results", sa.JSON(), nullable=False),
    )
    op.create_index("ix_test_runs_agent_id", "test_runs", ["agent_id"])


def downgrade() -> None:
    op.drop_table("test_runs")

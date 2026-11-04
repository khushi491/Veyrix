"""Add durable worker lifecycle and interruption tracking."""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for name in ("started_at", "finished_at", "lease_expires_at"):
        op.add_column("test_runs", sa.Column(name, sa.DateTime(timezone=True), nullable=True))
    op.add_column("test_runs", sa.Column("worker_token", sa.String(36), nullable=True))
    op.add_column("test_runs", sa.Column("error", sa.Text(), nullable=True))
    op.create_index("ix_test_runs_status", "test_runs", ["status"])
    op.execute("UPDATE test_runs SET finished_at = created_at WHERE status = 'completed'")


def downgrade() -> None:
    op.drop_index("ix_test_runs_status", table_name="test_runs")
    for name in ("error", "worker_token", "lease_expires_at", "finished_at", "started_at"):
        op.drop_column("test_runs", name)

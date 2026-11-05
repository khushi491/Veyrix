"""Persist immutable versioned assessment score snapshots."""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "run_scores",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "run_id",
            sa.String(36),
            sa.ForeignKey("test_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("methodology_version", sa.String(32), nullable=False),
        sa.Column("scope_fingerprint", sa.String(64), nullable=True),
        sa.Column("score", sa.Integer(), nullable=True),
        sa.Column("assessment", sa.JSON(), nullable=False),
        sa.UniqueConstraint("run_id", "methodology_version", name="uq_run_score_methodology"),
    )
    op.create_index("ix_run_scores_run_id", "run_scores", ["run_id"])
    op.create_index("ix_run_scores_scope_fingerprint", "run_scores", ["scope_fingerprint"])


def downgrade() -> None:
    op.drop_table("run_scores")

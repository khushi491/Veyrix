"""Create projects and registered agents."""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
    )
    op.create_table(
        "agents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("adapter", sa.String(32), nullable=False),
        sa.Column("variant", sa.String(32), nullable=False),
        sa.Column("policy", sa.JSON(), nullable=False),
    )
    op.create_index("ix_agents_project_id", "agents", ["project_id"])


def downgrade() -> None:
    op.drop_table("agents")
    op.drop_table("projects")

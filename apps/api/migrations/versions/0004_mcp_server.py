"""Track bundled MCP server enforcement independently from agent variant."""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "agents",
        sa.Column("server_variant", sa.String(32), nullable=False, server_default="vulnerable"),
    )
    op.alter_column("agents", "server_variant", server_default=None)


def downgrade() -> None:
    op.drop_column("agents", "server_variant")

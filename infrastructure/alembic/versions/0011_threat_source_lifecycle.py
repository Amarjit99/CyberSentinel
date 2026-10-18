"""Add threat source lifecycle and endpoint metadata.

Revision ID: 0011_threat_source_lifecycle
Revises: 0010_risk_scoring_policies
"""

import sqlalchemy as sa
from alembic import op

revision = "0011_threat_source_lifecycle"
down_revision = "0010_risk_scoring_policies"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("threat_sources", sa.Column("endpoint_url", sa.String(length=512), nullable=True))
    op.add_column(
        "threat_sources",
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.add_column(
        "threat_sources",
        sa.Column("polling_interval_minutes", sa.Integer(), nullable=True),
    )
    op.add_column(
        "threat_sources",
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )


def downgrade() -> None:
    op.drop_column("threat_sources", "updated_at")
    op.drop_column("threat_sources", "polling_interval_minutes")
    op.drop_column("threat_sources", "enabled")
    op.drop_column("threat_sources", "endpoint_url")

"""Add handling metadata to threat-intelligence observations.

Revision ID: 0008_threat_intel_handling
Revises: 0007_correlation_window_state
"""

import sqlalchemy as sa
from alembic import op

revision = "0008_threat_intel_handling"
down_revision = "0007_correlation_window_state"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "threat_indicator_records",
        sa.Column("handling_tlp", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("threat_indicator_records", "handling_tlp")

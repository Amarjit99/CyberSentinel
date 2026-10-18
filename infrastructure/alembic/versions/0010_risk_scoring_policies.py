"""Persist versioned risk scoring policies.

Revision ID: 0010_risk_scoring_policies
Revises: 0009_detection_alert_lifecycle
"""

import sqlalchemy as sa
from alembic import op

revision = "0010_risk_scoring_policies"
down_revision = "0009_detection_alert_lifecycle"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "risk_scoring_policies",
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("weights_json", sa.JSON(), nullable=False),
        sa.Column("band_thresholds_json", sa.JSON(), nullable=False),
        sa.Column("stale_intel_discount", sa.Float(), nullable=False),
        sa.Column("missing_intel_baseline", sa.Float(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("change_reason", sa.String(length=512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("version"),
    )
    op.create_index("ix_risk_scoring_policies_active", "risk_scoring_policies", ["active"])


def downgrade() -> None:
    op.drop_index("ix_risk_scoring_policies_active", table_name="risk_scoring_policies")
    op.drop_table("risk_scoring_policies")

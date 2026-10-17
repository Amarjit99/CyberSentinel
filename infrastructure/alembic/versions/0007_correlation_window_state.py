"""Persist correlation windows across worker restarts.

Revision ID: 0007_correlation_window_state
Revises: 0006_evidence_relationships
"""

import sqlalchemy as sa
from alembic import op

revision = "0007_correlation_window_state"
down_revision = "0006_evidence_relationships"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "correlation_window_states",
        sa.Column("key", sa.String(length=255), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("entity_key", sa.String(length=255), nullable=False),
        sa.Column("state_json", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )
    op.create_index("idx_correlation_window_states_rule_id", "correlation_window_states", ["rule_id"])


def downgrade() -> None:
    op.drop_index("idx_correlation_window_states_rule_id", table_name="correlation_window_states")
    op.drop_table("correlation_window_states")

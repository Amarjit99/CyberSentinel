"""Add persistent in-app analyst notifications.

Revision ID: 0012_analyst_notifications
Revises: 0011_threat_source_lifecycle
"""

import sqlalchemy as sa
from alembic import op

revision = "0012_analyst_notifications"
down_revision = "0011_threat_source_lifecycle"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "analyst_notifications",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("recipient_id", sa.String(length=128), nullable=False),
        sa.Column("notification_type", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("message", sa.String(length=1000), nullable=False),
        sa.Column("detection_id", sa.String(length=64), nullable=True),
        sa.Column("read", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_analyst_notifications_recipient_id", "analyst_notifications", ["recipient_id"])
    op.create_index("ix_analyst_notifications_read", "analyst_notifications", ["read"])
    op.create_index("ix_analyst_notifications_detection_id", "analyst_notifications", ["detection_id"])
    op.create_index("ix_analyst_notifications_created_at", "analyst_notifications", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_analyst_notifications_created_at", table_name="analyst_notifications")
    op.drop_index("ix_analyst_notifications_detection_id", table_name="analyst_notifications")
    op.drop_index("ix_analyst_notifications_read", table_name="analyst_notifications")
    op.drop_index("ix_analyst_notifications_recipient_id", table_name="analyst_notifications")
    op.drop_table("analyst_notifications")

"""Add alert lifecycle metadata to detections.

Revision ID: 0009_detection_alert_lifecycle
Revises: 0008_threat_intel_handling
"""

import sqlalchemy as sa
from alembic import op

revision = "0009_detection_alert_lifecycle"
down_revision = "0008_threat_intel_handling"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("detections", sa.Column("assigned_to", sa.String(length=128), nullable=True))
    op.add_column("detections", sa.Column("analyst_notes", sa.String(length=4000), nullable=True))
    op.add_column("detections", sa.Column("status_reason", sa.String(length=512), nullable=True))
    op.add_column("detections", sa.Column("status_updated_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("detections", sa.Column("status_updated_by", sa.String(length=128), nullable=True))


def downgrade() -> None:
    op.drop_column("detections", "status_updated_by")
    op.drop_column("detections", "status_updated_at")
    op.drop_column("detections", "status_reason")
    op.drop_column("detections", "analyst_notes")
    op.drop_column("detections", "assigned_to")

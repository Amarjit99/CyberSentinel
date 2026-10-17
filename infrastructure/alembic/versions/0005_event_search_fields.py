"""Add canonical event fields used by bounded event search.

Revision ID: 0005_event_search_fields
Revises: 0004_incident_triage_assessments
"""

import sqlalchemy as sa
from alembic import op

revision = "0005_event_search_fields"
down_revision = "0004_incident_triage_assessments"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("events", sa.Column("event_type", sa.String(length=128), nullable=True))
    op.add_column("events", sa.Column("hostname", sa.String(length=255), nullable=True))
    op.add_column("events", sa.Column("username", sa.String(length=255), nullable=True))
    op.add_column("events", sa.Column("src_ip", sa.String(length=64), nullable=True))
    op.add_column("events", sa.Column("dst_ip", sa.String(length=64), nullable=True))
    op.add_column(
        "events",
        sa.Column("severity", sa.String(length=32), nullable=False, server_default="informational"),
    )
    for name, column in (
        ("idx_events_event_type", "event_type"),
        ("idx_events_hostname", "hostname"),
        ("idx_events_username", "username"),
        ("idx_events_src_ip", "src_ip"),
        ("idx_events_dst_ip", "dst_ip"),
        ("idx_events_severity", "severity"),
    ):
        op.create_index(name, "events", [column])
    bind = op.get_bind()
    if bind and getattr(bind.dialect, "name", "") != "sqlite":
        op.alter_column("events", "severity", server_default=None)


def downgrade() -> None:
    for name in (
        "idx_events_severity",
        "idx_events_dst_ip",
        "idx_events_src_ip",
        "idx_events_username",
        "idx_events_hostname",
        "idx_events_event_type",
    ):
        op.drop_index(name, table_name="events")
    for column in ("severity", "dst_ip", "src_ip", "username", "hostname", "event_type"):
        op.drop_column("events", column)

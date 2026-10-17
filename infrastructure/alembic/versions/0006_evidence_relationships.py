"""Add evidence conflict metadata and immutable relationships.

Revision ID: 0006_evidence_relationships
Revises: 0005_event_search_fields
"""

import sqlalchemy as sa
from alembic import context, op

revision = "0006_evidence_relationships"
down_revision = "0005_event_search_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if context.is_offline_mode():
        op.add_column("evidence", sa.Column("conflict_group", sa.String(length=64), nullable=True))
        op.add_column(
            "evidence",
            sa.Column(
                "conflict_status",
                sa.String(length=32),
                nullable=False,
                server_default="unreviewed",
            ),
        )
        op.create_index("idx_evidence_conflict_group", "evidence", ["conflict_group"])
        bind = op.get_bind()
        if bind and getattr(bind.dialect, "name", "") != "sqlite":
            op.alter_column("evidence", "conflict_status", server_default=None)
        op.create_table(
            "evidence_relations",
            sa.Column("id", sa.String(length=64), nullable=False),
            sa.Column("incident_id", sa.String(length=64), nullable=False),
            sa.Column("from_evidence_id", sa.String(length=64), nullable=False),
            sa.Column("to_evidence_id", sa.String(length=64), nullable=False),
            sa.Column("relation_type", sa.String(length=64), nullable=False),
            sa.Column("created_by", sa.String(length=64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["from_evidence_id"], ["evidence.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["to_evidence_id"], ["evidence.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("idx_evidence_relations_incident_id", "evidence_relations", ["incident_id"])
        return

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    evidence_columns = {column["name"] for column in inspector.get_columns("evidence")}
    if "conflict_group" not in evidence_columns:
        op.add_column("evidence", sa.Column("conflict_group", sa.String(length=64), nullable=True))
    if "conflict_status" not in evidence_columns:
        op.add_column(
            "evidence",
            sa.Column(
                "conflict_status",
                sa.String(length=32),
                nullable=False,
                server_default="unreviewed",
            ),
        )
        if getattr(bind.dialect, "name", "") != "sqlite":
            op.alter_column("evidence", "conflict_status", server_default=None)
    evidence_indexes = {index["name"] for index in inspector.get_indexes("evidence")}
    if "idx_evidence_conflict_group" not in evidence_indexes:
        op.create_index("idx_evidence_conflict_group", "evidence", ["conflict_group"])
    if "evidence_relations" not in inspector.get_table_names():
        op.create_table(
            "evidence_relations",
            sa.Column("id", sa.String(length=64), nullable=False),
            sa.Column("incident_id", sa.String(length=64), nullable=False),
            sa.Column("from_evidence_id", sa.String(length=64), nullable=False),
            sa.Column("to_evidence_id", sa.String(length=64), nullable=False),
            sa.Column("relation_type", sa.String(length=64), nullable=False),
            sa.Column("created_by", sa.String(length=64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["from_evidence_id"], ["evidence.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["to_evidence_id"], ["evidence.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
    relation_indexes = {
        index["name"] for index in sa.inspect(op.get_bind()).get_indexes("evidence_relations")
    }
    if "idx_evidence_relations_incident_id" not in relation_indexes:
        op.create_index("idx_evidence_relations_incident_id", "evidence_relations", ["incident_id"])


def downgrade() -> None:
    op.drop_index("idx_evidence_relations_incident_id", table_name="evidence_relations")
    op.drop_table("evidence_relations")
    op.drop_index("idx_evidence_conflict_group", table_name="evidence")
    op.drop_column("evidence", "conflict_status")
    op.drop_column("evidence", "conflict_group")

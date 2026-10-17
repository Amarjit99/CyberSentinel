"""0002_attack_and_threat_intel

Migration for MITRE ATT&CK technique catalog and Threat Intelligence indicator tables.
Governing Decisions: ADR-0001, ADR-0004, CSAI-R0.2-CONTEXT-INTELLIGENCE

Revision ID: 0002_attack_and_threat_intel
Revises: 0001_initial_schema
Create Date: 2026-10-16 21:30:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0002_attack_and_threat_intel"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. attack_techniques
    op.create_table(
        "attack_techniques",
        sa.Column("id", sa.String(length=32), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("tactics_json", sa.JSON(), nullable=False),
        sa.Column("parent_id", sa.String(length=32), nullable=True),
        sa.Column("platforms_json", sa.JSON(), nullable=False),
        sa.Column("data_sources_json", sa.JSON(), nullable=False),
        sa.Column("is_subtechnique", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("is_deprecated", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("is_revoked", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("url", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("version", sa.String(length=32), nullable=False, server_default="15.1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 2. rule_attack_mappings
    op.create_table(
        "rule_attack_mappings",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("rule_id", sa.String(length=128), nullable=False),
        sa.Column("rule_type", sa.String(length=32), nullable=False, server_default="sigma"),
        sa.Column("raw_tag", sa.String(length=128), nullable=False),
        sa.Column("mapping_type", sa.String(length=32), nullable=False),
        sa.Column(
            "technique_id",
            sa.String(length=32),
            sa.ForeignKey("attack_techniques.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("tactic", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="valid"),
        sa.Column("diagnostic", sa.String(length=255), nullable=True),
        sa.Column("catalog_version", sa.String(length=32), nullable=False, server_default="15.1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("idx_rule_attack_mappings_rule", "rule_attack_mappings", ["rule_id"])
    op.create_index("idx_rule_attack_mappings_tech", "rule_attack_mappings", ["technique_id"])
    op.create_index("idx_rule_attack_mappings_tactic", "rule_attack_mappings", ["tactic"])

    # 3. threat_sources
    op.create_table(
        "threat_sources",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("source_type", sa.String(length=64), nullable=False),
        sa.Column("reliability", sa.String(length=32), nullable=False, server_default="B"),
        sa.Column("description", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 4. threat_indicators
    op.create_table(
        "threat_indicators",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("indicator_type", sa.String(length=32), nullable=False),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column("raw_value", sa.String(length=512), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "idx_threat_ind_type_val",
        "threat_indicators",
        ["indicator_type", "value"],
        unique=True,
    )

    # 5. threat_indicator_records
    op.create_table(
        "threat_indicator_records",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "indicator_id",
            sa.String(length=64),
            sa.ForeignKey("threat_indicators.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "source_id",
            sa.String(length=64),
            sa.ForeignKey("threat_sources.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("external_record_id", sa.String(length=128), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("source_reputation_score", sa.Float(), nullable=True),
        sa.Column("source_classification", sa.String(length=64), nullable=True),
        sa.Column("threat_actor", sa.String(length=128), nullable=True),
        sa.Column("campaign", sa.String(length=128), nullable=True),
        sa.Column("feed_version", sa.String(length=64), nullable=True),
        sa.Column("import_id", sa.String(length=64), nullable=True),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("raw_record_json", sa.JSON(), nullable=False),
        sa.Column("validation_status", sa.String(length=32), nullable=False, server_default="valid"),
    )
    op.create_index("idx_threat_ind_rec_ind", "threat_indicator_records", ["indicator_id"])
    op.create_index("idx_threat_ind_rec_src", "threat_indicator_records", ["source_id"])
    op.create_index("idx_threat_ind_rec_expires", "threat_indicator_records", ["expires_at"])
    op.create_index("idx_threat_ind_rec_import", "threat_indicator_records", ["import_id"])


def downgrade() -> None:
    op.drop_table("threat_indicator_records")
    op.drop_table("threat_indicators")
    op.drop_table("threat_sources")
    op.drop_table("rule_attack_mappings")
    op.drop_table("attack_techniques")

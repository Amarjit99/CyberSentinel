"""0004_incident_triage_assessments

Migration for Incident Triage Assessments table (Sprint 15: AI Provider Abstraction & Triage Agent).
Governing Decisions: ADR-0001, ADR-0002, ADR-0004, ADR-0005, CSAI-R0.4-TRIAGE-AGENT

Revision ID: 0004_incident_triage_assessments
Revises: 0003_incident_risk_assessments
Create Date: 2026-10-16 22:35:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0004_incident_triage_assessments"
down_revision: Union[str, None] = "0003_incident_risk_assessments"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "incident_triage_assessments",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "incident_id",
            sa.String(length=64),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("suspected_activity", sa.String(length=255), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("recommended_severity", sa.String(length=32), nullable=False),
        sa.Column("recommended_priority", sa.String(length=32), nullable=False),
        sa.Column("supporting_evidence_json", sa.JSON(), nullable=False),
        sa.Column("contradictory_evidence_json", sa.JSON(), nullable=False),
        sa.Column("unresolved_questions_json", sa.JSON(), nullable=False),
        sa.Column("attack_techniques_json", sa.JSON(), nullable=False),
        sa.Column("threat_intel_json", sa.JSON(), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("risk_band", sa.String(length=32), nullable=False),
        sa.Column("risk_policy_version", sa.String(length=32), nullable=False, server_default="1.0.0"),
        sa.Column("recommended_steps_json", sa.JSON(), nullable=False),
        sa.Column("data_gaps_json", sa.JSON(), nullable=False),
        sa.Column("uncertainties_json", sa.JSON(), nullable=False),
        sa.Column("requires_analyst_review", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("provider_info_json", sa.JSON(), nullable=False),
        sa.Column("is_fallback", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("triage_policy_version", sa.String(length=32), nullable=False, server_default="1.0.0"),
        sa.Column("assessed_by", sa.String(length=64), nullable=False, server_default="system:triage_agent"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "idx_inc_triage_incident_id",
        "incident_triage_assessments",
        ["incident_id"],
    )
    op.create_index(
        "idx_inc_triage_created_at",
        "incident_triage_assessments",
        ["created_at"],
    )


def downgrade() -> None:
    op.drop_index("idx_inc_triage_created_at", table_name="incident_triage_assessments")
    op.drop_index("idx_inc_triage_incident_id", table_name="incident_triage_assessments")
    op.drop_table("incident_triage_assessments")

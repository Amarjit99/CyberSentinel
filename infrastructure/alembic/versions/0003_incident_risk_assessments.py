"""0003_incident_risk_assessments

Migration for Incident Risk Assessments table (Sprint 14: Explainable Incident Risk Engine).
Governing Decisions: ADR-0001, ADR-0003, ADR-0006, CSAI-R0.3-EXPLAINABLE-RISK-ENGINE

Revision ID: 0003_incident_risk_assessments
Revises: 0002_attack_and_threat_intel
Create Date: 2026-10-16 22:15:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0003_incident_risk_assessments"
down_revision: Union[str, None] = "0002_attack_and_threat_intel"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "incident_risk_assessments",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "incident_id",
            sa.String(length=64),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("overall_score", sa.Float(), nullable=False),
        sa.Column("risk_band", sa.String(length=32), nullable=False),
        sa.Column("policy_version", sa.String(length=32), nullable=False, server_default="1.0.0"),
        sa.Column("factors_json", sa.JSON(), nullable=False),
        sa.Column("primary_drivers_json", sa.JSON(), nullable=False),
        sa.Column("uncertainties_json", sa.JSON(), nullable=False),
        sa.Column("limitations_json", sa.JSON(), nullable=False),
        sa.Column("evidence_refs_json", sa.JSON(), nullable=False),
        sa.Column("assessed_by", sa.String(length=64), nullable=False, server_default="system:risk_engine"),
        sa.Column("assessed_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "idx_inc_risk_incident_id",
        "incident_risk_assessments",
        ["incident_id"],
    )
    op.create_index(
        "idx_inc_risk_assessed_at",
        "incident_risk_assessments",
        ["assessed_at"],
    )


def downgrade() -> None:
    op.drop_index("idx_inc_risk_assessed_at", table_name="incident_risk_assessments")
    op.drop_index("idx_inc_risk_incident_id", table_name="incident_risk_assessments")
    op.drop_table("incident_risk_assessments")

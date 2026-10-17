"""CyberSentinel AI — Authoritative PostgreSQL Relational Models (SQLAlchemy 2.x)
Governing Decisions: ADR-0001, ADR-0003, ADR-0004, ADR-0006, and docs/18-DATABASE-SCHEMA.md
"""

from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from schemas.enums import IncidentStateEnum


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


# 3. user_roles link table
user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", String(64), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", String(64), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column("granted_by", String(64), nullable=True),
    Column("granted_at", DateTime(timezone=True), default=utc_now, nullable=False),
)


# 1. users
class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid4()))
    external_subject: Mapped[Optional[str]] = mapped_column(String(255), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    roles: Mapped[list["Role"]] = relationship("Role", secondary=user_roles, back_populates="users")


# 2. roles
class Role(Base):
    __tablename__ = "roles"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(255))

    users: Mapped[list["User"]] = relationship("User", secondary=user_roles, back_populates="roles")


# 4. connectors
class Connector(Base):
    __tablename__ = "connectors"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    config_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


# 5. events (Metadata index & pointer to raw store / OpenSearch)
class EventMetadata(Base):
    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid4()))
    source_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    event_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, nullable=False
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    schema_version: Mapped[str] = mapped_column(String(32), default="1.0.0", nullable=False)
    raw_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    classification: Mapped[str] = mapped_column(String(32), default="unclassified", nullable=False)
    event_type: Mapped[Optional[str]] = mapped_column(String(128), index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    username: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    src_ip: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    dst_ip: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(32), default="informational", index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    __table_args__ = (Index("idx_events_source_time", "source_id", "event_time"),)


# Canonical alias
Event = EventMetadata


# 6. detections
class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid4()))
    rule_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    rule_version: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )


# 7. detection_events
class DetectionEvent(Base):
    __tablename__ = "detection_events"

    detection_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("detections.id", ondelete="CASCADE"), primary_key=True
    )
    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    relation_type: Mapped[str] = mapped_column(String(64), default="matched", nullable=False)


# 8. incidents (Authoritative 11-State State Machine from ADR-0001)
class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid4()))
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32),
        CheckConstraint(
            "status IN ('NEW', 'TRIAGE', 'INVESTIGATING', 'CONFIRMED', 'BENIGN', "
            "'AWAITING_APPROVAL', 'CONTAINMENT', 'ERADICATION', 'RECOVERY', 'CLOSED', "
            "'LESSONS_LEARNED', 'REOPENED')",
            name="chk_incident_status_valid",
        ),
        default=IncidentStateEnum.NEW.value,
        index=True,
        nullable=False,
    )
    severity: Mapped[str] = mapped_column(String(32), default="medium", index=True, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    owner_id: Mapped[Optional[str]] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)  # Optimistic lock
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    detections: Mapped[list["IncidentDetection"]] = relationship(
        "IncidentDetection", back_populates="incident", cascade="all, delete-orphan"
    )
    entities: Mapped[list["IncidentEntity"]] = relationship(
        "IncidentEntity", back_populates="incident", cascade="all, delete-orphan"
    )
    evidence_items: Mapped[list["Evidence"]] = relationship(
        "Evidence", back_populates="incident", cascade="all, delete-orphan"
    )
    notes: Mapped[list["IncidentNote"]] = relationship(
        "IncidentNote", back_populates="incident", cascade="all, delete-orphan"
    )
    proposals: Mapped[list["ResponseProposal"]] = relationship(
        "ResponseProposal", back_populates="incident", cascade="all, delete-orphan"
    )
    risk_assessments: Mapped[list["IncidentRiskAssessmentModel"]] = relationship(
        "IncidentRiskAssessmentModel", back_populates="incident", cascade="all, delete-orphan", order_by="desc(IncidentRiskAssessmentModel.assessed_at)"
    )
    triage_assessments: Mapped[list["IncidentTriageAssessmentModel"]] = relationship(
        "IncidentTriageAssessmentModel", back_populates="incident", cascade="all, delete-orphan", order_by="desc(IncidentTriageAssessmentModel.created_at)"
    )




# 9. incident_detections
class IncidentDetection(Base):
    __tablename__ = "incident_detections"

    incident_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True
    )
    detection_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("detections.id", ondelete="CASCADE"), primary_key=True
    )
    link_reason: Mapped[str] = mapped_column(String(255), nullable=False)
    linked_by: Mapped[str] = mapped_column(String(64), nullable=False)
    linked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    incident: Mapped["Incident"] = relationship("Incident", back_populates="detections")


# 10. incident_entities
class IncidentEntity(Base):
    __tablename__ = "incident_entities"

    incident_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True
    )
    entity_type: Mapped[str] = mapped_column(String(64), primary_key=True)
    entity_key: Mapped[str] = mapped_column(String(255), primary_key=True)
    relation: Mapped[str] = mapped_column(String(64), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="entities")


# 11. evidence
class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid4()))
    incident_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    evidence_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    provenance_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    classification: Mapped[str] = mapped_column(String(32), default="internal", nullable=False)
    conflict_group: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    conflict_status: Mapped[str] = mapped_column(
        String(32), default="unreviewed", nullable=False
    )
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    created_by: Mapped[str] = mapped_column(String(64), nullable=False)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="evidence_items")
    outgoing_relations: Mapped[list["EvidenceRelation"]] = relationship(
        "EvidenceRelation",
        foreign_keys="EvidenceRelation.from_evidence_id",
        back_populates="from_evidence",
    )
    incoming_relations: Mapped[list["EvidenceRelation"]] = relationship(
        "EvidenceRelation",
        foreign_keys="EvidenceRelation.to_evidence_id",
        back_populates="to_evidence",
    )


class EvidenceRelation(Base):
    __tablename__ = "evidence_relations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid4()))
    incident_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    from_evidence_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False
    )
    to_evidence_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False
    )
    relation_type: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    from_evidence: Mapped["Evidence"] = relationship(
        "Evidence", foreign_keys=[from_evidence_id], back_populates="outgoing_relations"
    )
    to_evidence: Mapped["Evidence"] = relationship(
        "Evidence", foreign_keys=[to_evidence_id], back_populates="incoming_relations"
    )


class CorrelationWindowState(Base):
    __tablename__ = "correlation_window_states"

    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_key: Mapped[str] = mapped_column(String(255), nullable=False)
    state_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


# 12. incident_notes
class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid4()))
    incident_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    author_id: Mapped[str] = mapped_column(String(64), nullable=False)
    body_redacted: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    incident: Mapped["Incident"] = relationship("Incident", back_populates="notes")


# 13. agent_runs
class AgentRun(Base):
    __tablename__ = "agent_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid4()))
    incident_id: Mapped[Optional[str]] = mapped_column(
        String(64), ForeignKey("incidents.id", ondelete="SET NULL"), index=True
    )
    task_type: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(32), default="QUEUED", nullable=False)
    model_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    template_version: Mapped[str] = mapped_column(String(32), nullable=False)
    budget_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    failure_code: Mapped[Optional[str]] = mapped_column(String(64))

    findings: Mapped[list["AgentFinding"]] = relationship(
        "AgentFinding", back_populates="run", cascade="all, delete-orphan"
    )


# 14. agent_findings
class AgentFinding(Base):
    __tablename__ = "agent_findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid4()))
    run_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("agent_runs.id", ondelete="CASCADE"), index=True, nullable=False
    )
    finding_type: Mapped[str] = mapped_column(String(64), nullable=False)
    claim: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    evidence_refs_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    limitations: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    run: Mapped["AgentRun"] = relationship("AgentRun", back_populates="findings")


# 15. response_proposals
class ResponseProposal(Base):
    __tablename__ = "response_proposals"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid4()))
    incident_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    action_payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    risk: Mapped[str] = mapped_column(
        String(32),
        CheckConstraint(
            "risk IN ('Tier 0', 'Tier 1', 'Tier 2', 'Tier 3')", name="chk_proposal_risk_valid"
        ),
        nullable=False,
    )
    state: Mapped[str] = mapped_column(String(32), default="PENDING", nullable=False)
    created_by: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="proposals")
    approvals: Mapped[list["Approval"]] = relationship(
        "Approval", back_populates="proposal", cascade="all, delete-orphan"
    )


# 16. approvals
class Approval(Base):
    __tablename__ = "approvals"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid4()))
    proposal_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("response_proposals.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    approver_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(32), nullable=False)
    action_payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    proposal: Mapped["ResponseProposal"] = relationship(
        "ResponseProposal", back_populates="approvals"
    )


# 17. response_actions
class ResponseAction(Base):
    __tablename__ = "response_actions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid4()))
    proposal_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("response_proposals.id", ondelete="RESTRICT"),
        index=True,
        nullable=False,
    )
    idempotency_key: Mapped[str] = mapped_column(
        String(128), unique=True, index=True, nullable=False
    )
    state: Mapped[str] = mapped_column(String(32), default="QUEUED", nullable=False)
    result_redacted: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


# 18. audit_events
class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid4()))
    actor_type: Mapped[str] = mapped_column(String(32), nullable=False)  # USER, AGENT, SYSTEM
    actor_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    action: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    object_type: Mapped[str] = mapped_column(String(64), nullable=False)
    object_id: Mapped[str] = mapped_column(String(64), nullable=False)
    request_id: Mapped[Optional[str]] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)  # SUCCESS, FAILURE, DENIED
    reason_code: Mapped[Optional[str]] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True, nullable=False
    )
    metadata_redacted: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


# 19. attack_techniques
class AttackTechniqueRecord(Base):
    __tablename__ = "attack_techniques"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)  # e.g. "T1059.001"
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    tactics_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    parent_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    platforms_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    data_sources_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_deprecated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    url: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    version: Mapped[str] = mapped_column(String(32), default="15.1", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )


# 20. rule_attack_mappings
class RuleAttackMappingRecord(Base):
    __tablename__ = "rule_attack_mappings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid4()))
    rule_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    rule_type: Mapped[str] = mapped_column(String(32), default="sigma", nullable=False)
    raw_tag: Mapped[str] = mapped_column(String(128), nullable=False)
    mapping_type: Mapped[str] = mapped_column(String(32), nullable=False)  # technique, tactic, unknown
    technique_id: Mapped[Optional[str]] = mapped_column(
        String(32), ForeignKey("attack_techniques.id", ondelete="SET NULL"), nullable=True, index=True
    )
    tactic: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="valid", nullable=False)
    diagnostic: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    catalog_version: Mapped[str] = mapped_column(String(32), default="15.1", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )


# 21. threat_sources
class ThreatSource(Base):
    __tablename__ = "threat_sources"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g. "local_stix_feed"
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    source_type: Mapped[str] = mapped_column(String(64), nullable=False)  # stix21, json_feed, local_file, taxii
    reliability: Mapped[str] = mapped_column(String(32), default="B", nullable=False)  # A, B, C, unknown
    description: Mapped[Optional[str]] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    records: Mapped[list["ThreatIndicatorRecord"]] = relationship(
        "ThreatIndicatorRecord", back_populates="source", cascade="all, delete-orphan"
    )


# 22. threat_indicators
class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid4()))
    indicator_type: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    value: Mapped[str] = mapped_column(String(512), index=True, nullable=False)
    raw_value: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    __table_args__ = (
        Index("idx_threat_ind_type_val", "indicator_type", "value", unique=True),
    )

    records: Mapped[list["ThreatIndicatorRecord"]] = relationship(
        "ThreatIndicatorRecord", back_populates="indicator", cascade="all, delete-orphan"
    )


# 23. threat_indicator_records
class ThreatIndicatorRecord(Base):
    __tablename__ = "threat_indicator_records"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid4()))
    indicator_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("threat_indicators.id", ondelete="CASCADE"), index=True, nullable=False
    )
    source_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("threat_sources.id", ondelete="RESTRICT"), index=True, nullable=False
    )
    external_record_id: Mapped[Optional[str]] = mapped_column(String(128))
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), index=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    source_reputation_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    source_classification: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    handling_tlp: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    threat_actor: Mapped[Optional[str]] = mapped_column(String(128))
    campaign: Mapped[Optional[str]] = mapped_column(String(128))
    feed_version: Mapped[Optional[str]] = mapped_column(String(64))
    import_id: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    raw_record_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    validation_status: Mapped[str] = mapped_column(String(32), default="valid", nullable=False)

    indicator: Mapped["ThreatIndicator"] = relationship("ThreatIndicator", back_populates="records")
    source: Mapped["ThreatSource"] = relationship("ThreatSource", back_populates="records")


# 24. incident_risk_assessments (Sprint 14: Explainable Incident Risk Engine)
class IncidentRiskAssessmentModel(Base):
    __tablename__ = "incident_risk_assessments"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: f"ira-{uuid4().hex[:24]}")
    incident_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    overall_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_band: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(32), default="1.0.0", nullable=False)
    factors_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    primary_drivers_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    uncertainties_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    limitations_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    evidence_refs_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    assessed_by: Mapped[str] = mapped_column(String(64), default="system:risk_engine", nullable=False)
    assessed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True, nullable=False
    )

    incident: Mapped["Incident"] = relationship("Incident", back_populates="risk_assessments")


# 25. incident_triage_assessments (Sprint 15: AI Provider Abstraction & Triage Agent)
class IncidentTriageAssessmentModel(Base):
    __tablename__ = "incident_triage_assessments"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    suspected_activity: Mapped[str] = mapped_column(String(255), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    recommended_severity: Mapped[str] = mapped_column(String(32), nullable=False)
    recommended_priority: Mapped[str] = mapped_column(String(32), nullable=False)
    supporting_evidence_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    contradictory_evidence_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    unresolved_questions_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    attack_techniques_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    threat_intel_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_band: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_policy_version: Mapped[str] = mapped_column(String(32), default="1.0.0", nullable=False)
    recommended_steps_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    data_gaps_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    uncertainties_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    requires_analyst_review: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    provider_info_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    is_fallback: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    triage_policy_version: Mapped[str] = mapped_column(String(32), default="1.0.0", nullable=False)
    assessed_by: Mapped[str] = mapped_column(String(64), default="system:triage_agent", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True, nullable=False
    )

    incident: Mapped["Incident"] = relationship("Incident", back_populates="triage_assessments")


# 26. detection_rule_candidates (Sprint 19: Detection Engineering Assistant)
class DetectionRuleCandidate(Base):
    __tablename__ = "detection_rule_candidates"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: f"drc-{uuid4().hex[:12]}")
    rule_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(32), default="1.0.0", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="DRAFT", index=True, nullable=False)
    raw_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    original_rule_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    author_id: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default="medium", nullable=False)
    logsource_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    attack_techniques_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    validation_diagnostics_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    test_results_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    review_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reviewed_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    activated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    activated_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    audit_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

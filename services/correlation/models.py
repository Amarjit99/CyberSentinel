"""CyberSentinel AI — Correlation Engine Models & Schemas
Governing Decisions: ADR-0001, ADR-0005, CSAI-P4-CORRELATION
"""

from datetime import datetime
from typing import List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator

from schemas.enums import EventSeverityEnum


class SequenceStep(BaseModel):
    """Specification for an ordered step in a multi-stage correlation sequence."""

    step_id: str = Field(..., description="Unique step identifier within the sequence")
    rule_id: Optional[str] = Field(default=None, description="Matching Sigma detection rule ID")
    tag: Optional[str] = Field(default=None, description="Matching MITRE ATT&CK tag, e.g. attack.t1033")
    filter_field: Optional[str] = Field(default=None, description="Specific canonical field to match")
    filter_value: Optional[str] = Field(default=None, description="Specific field value required")


class CorrelationRule(BaseModel):
    """Declarative multi-event, stateful correlation rule definition."""

    id: str = Field(..., description="Unique correlation rule UUID")
    name: str = Field(..., description="Human-readable correlation rule name")
    description: str = Field(..., description="Threat context, hypothesis, and rationale")
    severity: EventSeverityEnum = Field(
        default=EventSeverityEnum.HIGH, description="Resulting incident severity"
    )
    window_seconds: int = Field(
        default=300, ge=10, le=86400, description="Sliding evaluation window in seconds (10s to 24h)"
    )
    threshold: int = Field(
        default=2, ge=1, le=10000, description="Minimum matching detections required to trigger"
    )
    group_by: List[str] = Field(
        ..., min_length=1, description="Entity fields to group and correlate on, e.g. ['host_id'], ['username']"
    )
    rule_matches: Optional[List[str]] = Field(
        default=None, description="Specific Sigma rule IDs or names that qualify for correlation"
    )
    tags: Optional[List[str]] = Field(
        default=None, description="Matching MITRE ATT&CK or threat tags"
    )
    sequence: Optional[List[SequenceStep]] = Field(
        default=None, description="Ordered sequence conditions required across time"
    )
    enabled: bool = Field(default=True, description="Rule activation status")
    cooldown_seconds: int = Field(
        default=60, ge=0, le=3600, description="Suppression cooldown between alerts for same entity"
    )

    @field_validator("sequence")
    @classmethod
    def validate_sequence(cls, v: Optional[List[SequenceStep]]) -> Optional[List[SequenceStep]]:
        if v is not None and len(v) < 2:
            raise ValueError("Sequence correlation rules must define at least 2 steps")
        return v


    @field_validator("id")
    @classmethod
    def validate_uuid(cls, v: str) -> str:
        try:
            UUID(v)
            return v
        except ValueError:
            raise ValueError(f"Correlation rule id '{v}' must be a valid UUID string")

    @field_validator("group_by")
    @classmethod
    def validate_group_by_fields(cls, v: List[str]) -> List[str]:
        valid_fields = {
            "host_id",
            "hostname",
            "user_id",
            "username",
            "src_ip",
            "dst_ip",
            "domain",
            "process_name",
            "hash_sha256",
        }
        for field in v:
            if field.lower() not in valid_fields:
                raise ValueError(
                    f"Unsupported group_by field '{field}'. Allowed fields: {sorted(valid_fields)}"
                )
        return [f.lower() for f in v]


class CorrelationMatch(BaseModel):
    """Output alert generated when a stateful correlation rule fires."""

    match_id: str = Field(default_factory=lambda: str(uuid4()))
    rule_id: str = Field(..., description="Correlating rule UUID")
    rule_name: str = Field(..., description="Correlating rule name")
    severity: EventSeverityEnum = Field(..., description="Evaluated incident severity")
    entity_type: str = Field(..., description="Correlated entity type (e.g. host, user, ip)")
    entity_key: str = Field(..., description="Correlated entity value (e.g. HOST-01, root)")
    detection_ids: List[str] = Field(..., description="List of matched detection IDs")
    event_ids: List[str] = Field(..., description="List of associated canonical event IDs")
    window_start: datetime = Field(..., description="Earliest detection event timestamp")
    window_end: datetime = Field(..., description="Latest detection event timestamp")
    title: str = Field(..., description="Generated incident title")
    description: str = Field(..., description="Incident description with correlation details")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    matched_count: int = Field(default=1, description="Number of events satisfying the threshold")


class CorrelationRuleValidationError(Exception):
    """Raised when a correlation rule definition fails structural or semantic validation."""

    pass


class CorrelationEvaluationError(Exception):
    """Raised when an unrecoverable error occurs during window correlation."""

    pass

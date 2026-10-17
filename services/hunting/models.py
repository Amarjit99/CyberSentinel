"""CyberSentinel AI — Threat Hunting Data Models & Contracts (Sprint 18)
Governing Decisions: ADR-0002, ADR-0005, Phase 18 Specification
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class HuntTypeEnum(str, Enum):
    """Supported bounded threat hunting investigation categories."""

    BRUTE_FORCE_AUTH = "brute_force_auth"
    SUSPICIOUS_PROCESS = "suspicious_process"
    DNS_BEACONING = "dns_beaconing"
    OUTBOUND_NETWORK = "outbound_network"
    ATTACK_TECHNIQUE = "attack_technique"
    ENTITY_ACTIVITY = "entity_activity"


class HuntJobRequest(BaseModel):
    """Structured request to initiate a bounded threat hunt."""

    hunt_type: HuntTypeEnum = Field(..., description="Category of threat hunt to execute")
    incident_id: Optional[str] = Field(
        default=None,
        description="Optional incident identifier to scope search; if omitted, searches tenant telemetry",
    )
    time_window_minutes: int = Field(
        default=60, ge=5, le=1440, description="Time window in minutes (5 to 1440)"
    )
    target_entities: Optional[List[str]] = Field(
        default=None,
        description="Target usernames, IP addresses, or hostnames to filter search",
    )
    technique_id: Optional[str] = Field(
        default=None,
        description="MITRE ATT&CK technique ID (e.g. 'T1110' or 'T1059.001') for technique hunts",
    )
    threshold: int = Field(
        default=5, ge=1, le=1000, description="Minimum frequency threshold to trigger a finding"
    )
    parameters: Dict[str, Any] = Field(
        default_factory=dict, description="Additional structured parameters for the hunt"
    )


class HuntFinding(BaseModel):
    """Evidence-grounded finding produced by a threat hunting execution."""

    finding_id: str = Field(default_factory=lambda: f"hf-{uuid4().hex[:12]}")
    title: str = Field(..., description="Concise finding headline")
    description: str = Field(..., description="Detailed factual explanation of detected anomalous activity")
    severity: str = Field(default="medium", description="Severity assessment: low, medium, high, critical")
    matched_events_count: int = Field(default=0, description="Number of supporting telemetry events")
    event_ids: List[str] = Field(default_factory=list, description="IDs of matching canonical events")
    entities: List[str] = Field(default_factory=list, description="Affected user, IP, or host identifiers")
    attack_technique: Optional[str] = Field(default=None, description="Mapped MITRE ATT&CK technique ID")
    confidence: float = Field(default=0.8, ge=0.0, le=1.0, description="Analytic confidence")


class HuntJobStatus(BaseModel):
    """Full execution status and findings report for a threat hunt."""

    hunt_id: str
    hunt_type: str
    state: str = Field(default="COMPLETED", description="QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED")
    requested_by: str
    incident_id: Optional[str] = None
    time_window_minutes: int
    matched_events_count: int = 0
    findings: List[HuntFinding] = Field(default_factory=list)
    coverage_gaps: List[str] = Field(
        default_factory=list,
        description="Missing telemetry categories identified during the hunt",
    )
    uncertainty_notes: List[str] = Field(
        default_factory=list,
        description="Explicit uncertainties; absence of detections does not prove environment is benign",
    )
    audit_id: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    duration_ms: float = 0.0

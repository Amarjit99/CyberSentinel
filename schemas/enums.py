"""CyberSentinel AI — Authoritative Enums & Constants
Governing Decisions: ADR-0001, ADR-0002, ADR-0004, ADR-0006 and BASELINE_AND_NAMING.md
"""

from enum import Enum


class IncidentStateEnum(str, Enum):
    """Authoritative 11-State Incident Lifecycle (ADR-0001)"""

    NEW = "NEW"
    TRIAGE = "TRIAGE"
    INVESTIGATING = "INVESTIGATING"
    CONFIRMED = "CONFIRMED"
    BENIGN = "BENIGN"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    CONTAINMENT = "CONTAINMENT"
    ERADICATION = "ERADICATION"
    RECOVERY = "RECOVERY"
    CLOSED = "CLOSED"
    LESSONS_LEARNED = "LESSONS_LEARNED"
    REOPENED = "REOPENED"


class RBACRoleEnum(str, Enum):
    """Authoritative System RBAC Roles (ADR-0004)"""

    SOC_ANALYST = "SOC_ANALYST"
    THREAT_HUNTER = "THREAT_HUNTER"
    DETECTION_ENGINEER = "DETECTION_ENGINEER"
    SOC_MANAGER = "SOC_MANAGER"
    SECURITY_ENGINEER = "SECURITY_ENGINEER"
    ADMIN = "ADMIN"
    RESEARCHER = "RESEARCHER"
    VIEWER = "VIEWER"


class AgentIdEnum(str, Enum):
    """Authoritative 8-Agent Core System Identifiers (ADR-0002)"""

    TRIAGE_AGENT = "triage-agent"
    INVESTIGATION_AGENT = "investigation-agent"
    THREAT_INTEL_AGENT = "threat-intel-agent"
    THREAT_HUNTING_AGENT = "threat-hunting-agent"
    EVIDENCE_AGENT = "evidence-agent"
    ATTACK_MAPPING_AGENT = "attack-mapping-agent"
    RISK_AGENT = "risk-agent"
    RESPONSE_AGENT = "response-agent"


class ResponseRiskTierEnum(str, Enum):
    """Authoritative Response Action Risk Tiers (ADR-0006)"""

    TIER_0 = "Tier 0"  # Autonomous / Read-Only (Enrichment, tagging, reports)
    TIER_1 = "Tier 1"  # Lab-Safe / Low Risk (Isolated reversible simulation)
    TIER_2 = "Tier 2"  # Disruptive Containment (Requires Single Human Analyst Approval)
    TIER_3 = "Tier 3"  # Consequential / High-Impact (Requires Dual-Human Authorization)


class EventSeverityEnum(str, Enum):
    """Canonical Event and Alert Severity Levels"""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCodeEnum(str, Enum):
    """Machine-readable API error codes"""

    INVALID_SCHEMA = "INVALID_SCHEMA"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    NOT_FOUND = "NOT_FOUND"
    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    CONFLICT = "CONFLICT"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"

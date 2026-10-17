"""CyberSentinel AI — Detection Service Boundary

Evaluates normalized events against Sigma and statistical detection rules.
"""

from abc import ABC, abstractmethod
from typing import List

from pydantic import BaseModel, Field

from schemas.canonical_event import CanonicalEvent
from schemas.enums import EventSeverityEnum


class DetectionMatch(BaseModel):
    """Detection alert emitted when an event matches a detection rule."""

    rule_id: str = Field(..., description="Unique rule identifier")
    rule_name: str = Field(..., description="Human-readable rule name")
    severity: EventSeverityEnum = Field(..., description="Rule alert severity")
    matched_event_ids: List[str] = Field(..., description="IDs of matching canonical events")
    mitre_attack_ids: List[str] = Field(
        default_factory=list, description="Associated MITRE ATT&CK techniques"
    )

    @property
    def event_id(self) -> str:
        """First matched event ID."""
        return self.matched_event_ids[0] if self.matched_event_ids else ""

    @property
    def rule_title(self) -> str:
        """Human-readable rule title."""
        return self.rule_name


# Alias for backward-compatible/alternative naming
DetectionResult = DetectionMatch


class BaseDetectionEngine(ABC):
    """Abstract interface for detection rule evaluation."""

    @abstractmethod
    def evaluate(self, event: CanonicalEvent) -> List[DetectionMatch]:
        """Evaluate canonical event against registered detection rules."""
        raise NotImplementedError


from services.detection.assistant import DetectionEngineeringAssistant, detection_assistant  # noqa: E402
from services.detection.compiler import CompiledSigmaRule, SigmaCompilationError, SigmaCompiler  # noqa: E402
from services.detection.engine import SigmaDetectionEngine, detection_engine  # noqa: E402
from services.detection.models import (  # noqa: E402
    AdHocExplainRequest,
    AdHocValidateRequest,
    CandidateReviewRequest,
    CandidateRuleResponse,
    CandidateRuleStatusEnum,
    RuleExplanationResponse,
    RuleGenerationRequest,
    RuleTestRequest,
    RuleTestResult,
    RuleValidationReport,
    ValidationDiagnostic,
    ValidationSeverityEnum,
)
from services.detection.persistence import DetectionPersistenceManager, persistence_manager  # noqa: E402
from services.detection.testing import SafeRuleTester, safe_rule_tester  # noqa: E402
from services.detection.validation import SigmaRuleValidator, sigma_validator  # noqa: E402
from services.detection.worker import StreamingDetectionWorker  # noqa: E402

__all__ = [
    "DetectionMatch",
    "DetectionResult",
    "BaseDetectionEngine",
    "CompiledSigmaRule",
    "SigmaCompiler",
    "SigmaCompilationError",
    "SigmaDetectionEngine",
    "detection_engine",
    "DetectionPersistenceManager",
    "persistence_manager",
    "StreamingDetectionWorker",
    # Sprint 19 Detection Engineering Assistant
    "CandidateRuleStatusEnum",
    "ValidationSeverityEnum",
    "ValidationDiagnostic",
    "RuleValidationReport",
    "RuleGenerationRequest",
    "RuleExplanationResponse",
    "RuleTestRequest",
    "RuleTestResult",
    "CandidateRuleResponse",
    "CandidateReviewRequest",
    "AdHocValidateRequest",
    "AdHocExplainRequest",
    "SigmaRuleValidator",
    "sigma_validator",
    "SafeRuleTester",
    "safe_rule_tester",
    "DetectionEngineeringAssistant",
    "detection_assistant",
]

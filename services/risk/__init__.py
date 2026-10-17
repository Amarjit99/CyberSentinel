"""CyberSentinel AI — Risk Scoring Service Boundary (ADR-0006)

Calculates deterministic risk scores and maps mitigation actions to risk tiers.
"""

from abc import ABC, abstractmethod

from pydantic import BaseModel, Field

from schemas.enums import ResponseRiskTierEnum
from services.risk.engine import DeterministicRiskEngine
from services.risk.models import (
    IncidentRiskAssessment,
    IncidentRiskBandEnum,
    RiskExplanationResponse,
    RiskFactorContribution,
    RiskScoringPolicy,
)


class RiskEvaluationResult(BaseModel):
    """Deterministic evaluation of action impact and operational risk."""

    action_type: str = Field(..., description="Action identifier")
    risk_tier: ResponseRiskTierEnum = Field(..., description="Calculated risk tier (Tier 0..3)")
    blast_radius: str = Field(..., description="Estimated blast radius classification")
    reversibility: bool = Field(..., description="Whether action is reversible without data loss")


class BaseRiskEngine(ABC):
    """Abstract interface for risk calculations."""

    @abstractmethod
    def evaluate_action_risk(self, action_type: str, target_asset: str) -> RiskEvaluationResult:
        """Calculate deterministic risk tier without model hallucination."""
        raise NotImplementedError


__all__ = [
    "RiskEvaluationResult",
    "BaseRiskEngine",
    "DeterministicRiskEngine",
    "IncidentRiskAssessment",
    "IncidentRiskBandEnum",
    "RiskFactorContribution",
    "RiskScoringPolicy",
    "RiskExplanationResponse",
]


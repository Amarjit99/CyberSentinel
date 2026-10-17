"""CyberSentinel AI — Incident Risk Models & Scoring Policy (Sprint 14)
Governing Decisions: ADR-0001, ADR-0003, ADR-0004, ADR-0006, CSAI-R0.3-EXPLAINABLE-RISK-ENGINE
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator


class IncidentRiskBandEnum(str, Enum):
    """Authoritative Incident Risk Bands mapping directly to operational triage priorities."""

    LOW = "LOW"          # 0.0 <= score < 40.0
    MEDIUM = "MEDIUM"    # 40.0 <= score < 70.0
    HIGH = "HIGH"        # 70.0 <= score < 85.0
    CRITICAL = "CRITICAL"# 85.0 <= score <= 100.0


class RiskFactorContribution(BaseModel):
    """Granular factor breakdown for explainable risk assessment."""

    factor_name: str = Field(..., description="Unique factor identifier")
    raw_score: float = Field(..., ge=0.0, le=100.0, description="Raw unweighted factor score (0-100)")
    weight: float = Field(..., ge=0.0, le=1.0, description="Configured weight for this factor")
    weighted_score: float = Field(..., ge=0.0, le=100.0, description="Contribution to overall score (raw * weight)")
    supporting_evidence: List[str] = Field(default_factory=list, description="IDs of supporting detections/evidence/indicators")
    drivers: List[str] = Field(default_factory=list, description="Human-readable rationales for score contribution")
    uncertainties: List[str] = Field(default_factory=list, description="Missing data, stale intel, or uncertainty caveats")


class RiskScoringPolicy(BaseModel):
    """Typed, validated scoring policy with strict weight normalization and band thresholds."""

    version: str = Field(default="1.0.0", description="Policy semantic version")
    weights: Dict[str, float] = Field(
        default_factory=lambda: {
            "detection_severity": 0.20,
            "evidence_strength": 0.15,
            "attack_context": 0.20,
            "threat_intel_context": 0.15,
            "incident_scope": 0.10,
            "temporal_context": 0.10,
            "correlation_context": 0.10,
        },
        description="Factor weights (must sum to 1.0)",
    )
    band_thresholds: Dict[str, float] = Field(
        default_factory=lambda: {
            IncidentRiskBandEnum.LOW.value: 0.0,
            IncidentRiskBandEnum.MEDIUM.value: 40.0,
            IncidentRiskBandEnum.HIGH.value: 70.0,
            IncidentRiskBandEnum.CRITICAL.value: 85.0,
        },
        description="Lower bounds for each risk band (0 to 100)",
    )
    stale_intel_discount: float = Field(default=0.5, ge=0.0, le=1.0, description="Discount factor applied to expired intelligence")
    missing_intel_baseline: float = Field(default=35.0, ge=0.0, le=100.0, description="Neutral baseline score when no intelligence exists (absence != benign)")

    @model_validator(mode="after")
    def validate_policy(self) -> "RiskScoringPolicy":
        """Ensure factor weights sum to 1.0 and band thresholds are monotonically increasing."""
        total_weight = sum(self.weights.values())
        if abs(total_weight - 1.0) > 1e-4:
            raise ValueError(f"Scoring policy factor weights must sum to 1.0, got {total_weight:.4f}")

        for k, v in self.weights.items():
            if v < 0.0 or v > 1.0:
                raise ValueError(f"Factor weight for '{k}' must be between 0.0 and 1.0, got {v}")

        # Check required factors
        required = {
            "detection_severity",
            "evidence_strength",
            "attack_context",
            "threat_intel_context",
            "incident_scope",
            "temporal_context",
            "correlation_context",
        }
        missing = required - set(self.weights.keys())
        if missing:
            raise ValueError(f"Scoring policy missing required factors: {missing}")

        # Validate band thresholds order
        low = self.band_thresholds.get(IncidentRiskBandEnum.LOW.value, 0.0)
        med = self.band_thresholds.get(IncidentRiskBandEnum.MEDIUM.value, 40.0)
        high = self.band_thresholds.get(IncidentRiskBandEnum.HIGH.value, 70.0)
        crit = self.band_thresholds.get(IncidentRiskBandEnum.CRITICAL.value, 85.0)

        if not (0.0 <= low < med < high < crit <= 100.0):
            raise ValueError(
                f"Risk band thresholds must be strictly increasing between 0 and 100: "
                f"LOW={low}, MEDIUM={med}, HIGH={high}, CRITICAL={crit}"
            )
        return self

    def classify_score(self, score: float) -> IncidentRiskBandEnum:
        """Deterministically map a 0-100 numeric score to a single risk band."""
        score = max(0.0, min(100.0, score))
        crit = self.band_thresholds[IncidentRiskBandEnum.CRITICAL.value]
        high = self.band_thresholds[IncidentRiskBandEnum.HIGH.value]
        med = self.band_thresholds[IncidentRiskBandEnum.MEDIUM.value]

        if score >= crit:
            return IncidentRiskBandEnum.CRITICAL
        elif score >= high:
            return IncidentRiskBandEnum.HIGH
        elif score >= med:
            return IncidentRiskBandEnum.MEDIUM
        else:
            return IncidentRiskBandEnum.LOW


class IncidentRiskAssessment(BaseModel):
    """Complete, immutable, and explainable incident risk assessment."""

    id: str = Field(default_factory=lambda: f"ira-{uuid4().hex[:24]}", description="Unique assessment ID")
    incident_id: str = Field(..., description="Target incident ID")
    overall_score: float = Field(..., ge=0.0, le=100.0, description="Overall normalized risk score (0-100)")
    risk_band: IncidentRiskBandEnum = Field(..., description="Calculated risk band classification")
    policy_version: str = Field(..., description="Scoring policy version used")
    assessed_at: datetime = Field(..., description="UTC assessment timestamp")
    assessed_by: str = Field(default="system:risk_engine", description="Actor or service triggering assessment")
    factors: Dict[str, RiskFactorContribution] = Field(..., description="Factor-level score contributions")
    primary_drivers: List[str] = Field(default_factory=list, description="Top positive and negative score drivers")
    uncertainties: List[str] = Field(default_factory=list, description="Data gaps, unverified indicators, or uncertainties")
    limitations: List[str] = Field(default_factory=list, description="Known analytical limitations")
    evidence_refs: List[str] = Field(default_factory=list, description="All evidence identifiers contributing to assessment")


class RiskExplanationResponse(BaseModel):
    """Analytical explanation endpoint payload."""

    incident_id: str
    assessment_id: str
    overall_score: float
    risk_band: IncidentRiskBandEnum
    policy_version: str
    assessed_at: datetime
    factors: Dict[str, RiskFactorContribution]
    primary_drivers: List[str]
    uncertainties: List[str]
    limitations: List[str]
    weights_used: Dict[str, float]
    formula_description: str

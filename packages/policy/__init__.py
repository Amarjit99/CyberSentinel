"""CyberSentinel AI — Deterministic Policy Evaluation (ADR-0006)"""

from typing import List

from pydantic import BaseModel, Field

from schemas.enums import RBACRoleEnum, ResponseRiskTierEnum


class PolicyDecision(BaseModel):
    """Result of a deterministic policy evaluation."""

    allowed: bool = Field(..., description="Whether action is permitted")
    risk_tier: ResponseRiskTierEnum = Field(..., description="Evaluated risk tier")
    required_approvals: int = Field(
        default=0, description="Number of independent approvals required"
    )
    allowed_approver_roles: List[RBACRoleEnum] = Field(
        default_factory=list, description="Roles authorized to approve"
    )
    reason: str = Field(..., description="Justification or constraint rule triggered")


def evaluate_action_policy(risk_tier: ResponseRiskTierEnum) -> PolicyDecision:
    """Evaluate response action requirements based on ADR-0006 risk tiers."""
    if risk_tier == ResponseRiskTierEnum.TIER_0:
        return PolicyDecision(
            allowed=True,
            risk_tier=risk_tier,
            required_approvals=0,
            allowed_approver_roles=[],
            reason="Tier 0 (Read-Only/Enrichment): Automated execution permitted.",
        )
    elif risk_tier == ResponseRiskTierEnum.TIER_1:
        return PolicyDecision(
            allowed=True,
            risk_tier=risk_tier,
            required_approvals=1,
            allowed_approver_roles=[
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.ADMIN,
            ],
            reason="Tier 1 (Reversible Low-Impact): Single responder approval required.",
        )
    elif risk_tier == ResponseRiskTierEnum.TIER_2:
        return PolicyDecision(
            allowed=True,
            risk_tier=risk_tier,
            required_approvals=1,
            allowed_approver_roles=[
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ],
            reason="Tier 2 (Disruptive Containment): SOC Manager or Security Engineer approval required.",
        )
    else:  # TIER_3
        return PolicyDecision(
            allowed=True,
            risk_tier=risk_tier,
            required_approvals=2,
            allowed_approver_roles=[RBACRoleEnum.SOC_MANAGER, RBACRoleEnum.ADMIN],
            reason="Tier 3 (High-Impact Destructive): Dual authorization (2 approvers) required.",
        )


__all__ = ["PolicyDecision", "evaluate_action_policy"]

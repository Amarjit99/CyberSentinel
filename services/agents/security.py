"""CyberSentinel AI — Agent Security Context & Delegation Boundary (Sprint 21)
Governing Decisions: ADR-0002, ADR-0004, ADR-0005, CSAI-R1.0-AI-SECURITY-HARDENING

Provides server-validated agent execution context:
1. Prevents agent identity confusion and unauthorized role escalation.
2. Enforces least-privilege delegation: a subtask cannot exceed parent permissions.
3. Binds execution strictly to authorized incident and tenant scopes.
4. Prevents model outputs from altering security context, roles, or policies.
"""

from datetime import datetime, timezone
from typing import List, Optional, Set
from uuid import uuid4

from pydantic import BaseModel, Field

from packages.auth import Principal
from schemas.enums import AgentIdEnum, RBACRoleEnum


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AgentSecurityError(PermissionError):
    """Raised when an agent security boundary or capability constraint is violated."""


class DelegationDepthExceededError(AgentSecurityError):
    """Raised when agent delegation exceeds configured maximum depth."""


class ScopeEscalationError(AgentSecurityError):
    """Raised when an agent attempts to widen or change incident/tenant scope."""


class AgentSecurityContext(BaseModel):
    """Authoritative server-side agent execution and delegation context."""

    context_id: str = Field(default_factory=lambda: f"sec-ctx-{uuid4().hex[:12]}")
    agent_id: AgentIdEnum = Field(..., description="Authoritative agent type")
    authenticated_principal: Principal = Field(..., description="Authenticated human operator or system principal")
    incident_id: Optional[str] = Field(default=None, description="Scoped incident identifier")
    tenant_id: str = Field(default="default-tenant", description="Scoped tenant boundary")
    parent_task_id: Optional[str] = Field(default=None, description="Parent task if delegated")
    task_id: str = Field(default_factory=lambda: f"task-{uuid4().hex[:8]}", description="Current execution task")
    current_delegation_depth: int = Field(default=0, ge=0)
    max_delegation_depth: int = Field(default=2, ge=1, le=5)
    allowed_tools: Optional[Set[str]] = Field(default=None, description="Constrained tool allowlist if restricted")
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: Optional[datetime] = Field(default=None)

    model_config = {"arbitrary_types_allowed": True}

    def is_expired(self) -> bool:
        """Check whether execution context has exceeded its validity lifetime."""
        if not self.expires_at:
            return False
        return utc_now() > self.expires_at

    def validate_tool_access(
        self,
        tool_name: str,
        tool_allowed_roles: List[RBACRoleEnum],
        tool_allowed_agents: List[AgentIdEnum],
        target_incident_id: Optional[str] = None,
    ) -> None:
        """Server-side verification of tool access under this security context.

        Guarantees:
        - Authenticated principal possesses an authorized role.
        - Agent ID is in tool's allowed agent types.
        - Tool is in context's allowed tools (if restricted).
        - Context has not expired.
        - Target incident does not cross scoped incident boundary.
        """
        if self.is_expired():
            raise AgentSecurityError(
                f"Security context '{self.context_id}' for agent '{self.agent_id.value}' has expired."
            )

        # 1. Human/System Principal Role Verification
        if not any(self.authenticated_principal.has_role(r) for r in tool_allowed_roles):
            allowed_names = [r.value for r in tool_allowed_roles]
            raise AgentSecurityError(
                f"Principal '{self.authenticated_principal.id}' lacks required role for tool '{tool_name}'. "
                f"Required: {allowed_names}"
            )

        # 2. Agent Identity Verification
        if self.agent_id not in tool_allowed_agents:
            allowed_agent_names = [a.value for a in tool_allowed_agents]
            raise AgentSecurityError(
                f"Agent type '{self.agent_id.value}' is not authorized to invoke tool '{tool_name}'. "
                f"Authorized agents: {allowed_agent_names}"
            )

        # 3. Constrained Tool Allowlist
        if self.allowed_tools is not None and tool_name not in self.allowed_tools:
            raise AgentSecurityError(
                f"Tool '{tool_name}' is not permitted under delegation context '{self.context_id}'."
            )

        # 4. Cross-Incident Scope Verification
        if self.incident_id and target_incident_id:
            if str(target_incident_id).strip() != str(self.incident_id).strip():
                raise ScopeEscalationError(
                    f"Cross-incident access violation: Security context is bound to incident '{self.incident_id}', "
                    f"cannot access incident '{target_incident_id}'."
                )

    def derive_child_context(
        self,
        child_agent_id: AgentIdEnum,
        subtask_id: Optional[str] = None,
        restricted_tools: Optional[Set[str]] = None,
        duration_seconds: Optional[int] = None,
    ) -> "AgentSecurityContext":
        """Derive a delegated sub-context enforcing least-privilege principles.

        Guarantees:
        - Delegation depth is strictly bounded.
        - Child context cannot acquire tools or scopes not possessed by parent.
        - Incident scope is immutably inherited.
        - Principal identity cannot be forged or elevated.
        """
        if self.current_delegation_depth >= self.max_delegation_depth:
            raise DelegationDepthExceededError(
                f"Cannot delegate: reached maximum delegation depth of {self.max_delegation_depth}."
            )

        # Intersection of allowed tools (least privilege)
        if self.allowed_tools is not None and restricted_tools is not None:
            child_tools: Optional[Set[str]] = self.allowed_tools & restricted_tools
        elif self.allowed_tools is not None:
            child_tools = set(self.allowed_tools)
        elif restricted_tools is not None:
            child_tools = set(restricted_tools)
        else:
            child_tools = None

        now = utc_now()
        child_expiry = None
        if duration_seconds:
            from datetime import timedelta
            child_expiry = now + timedelta(seconds=duration_seconds)
            if self.expires_at and child_expiry > self.expires_at:
                child_expiry = self.expires_at
        else:
            child_expiry = self.expires_at

        return AgentSecurityContext(
            context_id=f"sec-ctx-{uuid4().hex[:12]}",
            agent_id=child_agent_id,
            authenticated_principal=self.authenticated_principal,
            incident_id=self.incident_id,
            tenant_id=self.tenant_id,
            parent_task_id=self.task_id,
            task_id=subtask_id or f"task-{uuid4().hex[:8]}",
            current_delegation_depth=self.current_delegation_depth + 1,
            max_delegation_depth=self.max_delegation_depth,
            allowed_tools=child_tools,
            created_at=now,
            expires_at=child_expiry,
        )


__all__ = [
    "AgentSecurityContext",
    "AgentSecurityError",
    "DelegationDepthExceededError",
    "ScopeEscalationError",
]

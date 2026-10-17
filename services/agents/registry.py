"""CyberSentinel AI — Central Tool Registry (Sprint 16)
Governing Decisions: ADR-0002, ADR-0004, CSAI-R0.5-TOOL-REGISTRY-AUTHORIZATION
"""

import re
from typing import Any, Callable, Dict, List, Optional, Type, Union

from pydantic import BaseModel

from schemas.enums import AgentIdEnum, RBACRoleEnum
from services.agents.tool_schemas import (
    ExplainDetectionRuleInput,
    ExplainDetectionRuleOutput,
    GenerateCandidateRuleInput,
    GenerateCandidateRuleOutput,
    GetCanonicalEventsInput,
    GetCanonicalEventsOutput,
    GetIncidentDetectionsInput,
    GetIncidentDetectionsOutput,
    GetIncidentEntitiesInput,
    GetIncidentEntitiesOutput,
    GetIncidentEvidenceInput,
    GetIncidentEvidenceOutput,
    GetIncidentRiskAssessmentInput,
    GetIncidentRiskAssessmentOutput,
    GetIncidentSummaryInput,
    GetIncidentSummaryOutput,
    GetIncidentTimelineInput,
    GetIncidentTimelineOutput,
    GetPriorFindingsInput,
    GetPriorFindingsOutput,
    LookupThreatIntelInput,
    LookupThreatIntelOutput,
    RunThreatHuntInput,
    RunThreatHuntOutput,
    SearchKnowledgeBaseInput,
    SearchKnowledgeBaseOutput,
    TestCandidateRuleInput,
    TestCandidateRuleOutput,
    ToolMetadataDTO,
    ValidateSigmaRuleInput,
    ValidateSigmaRuleOutput,
)

# ==============================================================================
# Error Hierarchy
# ==============================================================================


class ToolRegistryError(Exception):
    """Base exception for all tool registry errors."""


class ToolNotFoundError(ToolRegistryError):
    """Raised when requesting an unregistered tool."""


class ToolDisabledError(ToolRegistryError):
    """Raised when attempting to access a disabled tool."""


class DuplicateToolError(ToolRegistryError):
    """Raised when registering a tool with an already-registered identifier."""


class UnsafeToolError(ToolRegistryError):
    """Raised when a tool configuration violates security invariants (e.g. shell, write)."""


class ToolAuthorizationError(PermissionError):
    """Raised when caller lacks required role, agent identity, or permission for a tool."""


class ToolValidationError(ValueError):
    """Raised when tool input or output violates schema constraints."""


class ToolExecutionLimitError(RuntimeError):
    """Raised when per-task tool call quotas or resource limits are exceeded."""


# Dangerous patterns strictly barred from registration
FORBIDDEN_NAME_PATTERNS = [
    re.compile(r"shell", re.IGNORECASE),
    re.compile(r"exec", re.IGNORECASE),
    re.compile(r"python", re.IGNORECASE),
    re.compile(r"system", re.IGNORECASE),
    re.compile(r"eval", re.IGNORECASE),
    re.compile(r"write", re.IGNORECASE),
    re.compile(r"sql", re.IGNORECASE),
    re.compile(r"drop", re.IGNORECASE),
    re.compile(r"delete", re.IGNORECASE),
    re.compile(r"truncate", re.IGNORECASE),
]


class ToolDefinition:
    """Authoritative, typed definition of a registered agent tool."""

    def __init__(
        self,
        name: str,
        description: str,
        permitted_purpose: str,
        input_schema: Type[BaseModel],
        output_schema: Type[BaseModel],
        required_permission: Optional[str] = None,
        required_capability: Optional[str] = None,
        allowed_roles: Optional[List[RBACRoleEnum]] = None,
        allowed_agents: Optional[List[AgentIdEnum]] = None,
        read_only: bool = True,
        is_read_only: Optional[bool] = None,
        version: str = "1.0.0",
        timeout_seconds: float = 30.0,
        max_result_items: int = 100,
        max_result_bytes: int = 100_000,
        audit_enabled: bool = True,
        is_enabled: bool = True,
        policy_version: str = "1.0.0",
        handler: Optional[Callable[..., Any]] = None,
    ):
        self.name = name
        self.version = version
        self.description = description
        self.permitted_purpose = permitted_purpose
        self.input_schema = input_schema
        self.output_schema = output_schema
        self.required_permission = required_permission or required_capability or "tool:execute"
        self.allowed_roles = allowed_roles or []
        self.allowed_agents = allowed_agents or []
        self.read_only = is_read_only if is_read_only is not None else read_only
        self.timeout_seconds = max(1.0, min(timeout_seconds, 120.0))
        self.max_result_items = max_result_items
        self.max_result_bytes = max_result_bytes
        self.audit_enabled = audit_enabled
        self.is_enabled = is_enabled
        self.policy_version = policy_version
        self.handler = handler

    @property
    def is_read_only(self) -> bool:
        return self.read_only

    @property
    def required_capability(self) -> str:
        return self.required_permission

    def to_metadata_dto(self) -> ToolMetadataDTO:
        """Export safe public metadata without exposing internal python handler references."""
        return ToolMetadataDTO(
            name=self.name,
            version=self.version,
            description=self.description,
            permitted_purpose=self.permitted_purpose,
            required_permission=self.required_permission,
            allowed_roles=[r.value if hasattr(r, "value") else str(r) for r in self.allowed_roles],
            allowed_agents=[a.value if hasattr(a, "value") else str(a) for a in self.allowed_agents],
            read_only=self.read_only,
            timeout_seconds=self.timeout_seconds,
            max_result_items=self.max_result_items,
            max_result_bytes=self.max_result_bytes,
            audit_enabled=self.audit_enabled,
            is_enabled=self.is_enabled,
            policy_version=self.policy_version,
            input_schema_name=self.input_schema.__name__,
            output_schema_name=self.output_schema.__name__,
            input_schema_json=self.input_schema.model_json_schema(),
            output_schema_json=self.output_schema.model_json_schema(),
        )

    to_metadata = to_metadata_dto


class ToolRegistry:
    """Centrally managed, typed registry of authorized agent tools."""

    registry_version: str = "1.0.0"
    policy_version: str = "2026.04"

    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}

    def register(self, tool_def: ToolDefinition) -> None:
        """Register a tool definition after enforcing safety invariants."""
        # 1. Identifier format validation
        if not re.match(r"^[a-z][a-z0-9_]{2,63}$", tool_def.name):
            raise ToolValidationError(
                f"Invalid tool name '{tool_def.name}'. Must match '^[a-z][a-z0-9_]{{2,63}}$'."
            )

        # 2. Safety invariant: Disallow dangerous tool concepts
        for pattern in FORBIDDEN_NAME_PATTERNS:
            if pattern.search(tool_def.name):
                raise UnsafeToolError(
                    f"Tool registration rejected: '{tool_def.name}' contains prohibited execution pattern."
                )

        # 3. Safety invariant: Must be read-only (zero autonomous containment or write)
        if not tool_def.read_only:
            raise UnsafeToolError(
                f"Tool '{tool_def.name}' is marked state-changing. All investigation tools must be read-only."
            )

        # 4. Duplicate rejection
        if tool_def.name in self._tools:
            raise DuplicateToolError(f"Tool '{tool_def.name}' is already registered.")

        # 5. Schema validation
        if not issubclass(tool_def.input_schema, BaseModel) or not issubclass(tool_def.output_schema, BaseModel):
            raise ToolValidationError(f"Tool '{tool_def.name}' schemas must be Pydantic BaseModel subclasses.")

        self._tools[tool_def.name] = tool_def

    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        """Retrieve tool definition by name."""
        return self._tools.get(name)

    def get(self, name: str) -> Optional[ToolDefinition]:
        """Convenience alias for get_tool."""
        return self._tools.get(name)

    def set_enabled(self, name: str, enabled: bool) -> None:
        """Enable or disable a registered tool."""
        tool = self._tools.get(name)
        if not tool:
            raise ToolNotFoundError(f"Tool '{name}' not found in registry.")
        tool.is_enabled = enabled

    def list_tools(
        self,
        role: Optional[Union[str, RBACRoleEnum]] = None,
        agent_id: Optional[Union[str, AgentIdEnum]] = None,
        agent_type: Optional[Union[str, AgentIdEnum]] = None,
        enabled_only: bool = True,
    ) -> List[ToolDefinition]:
        """List registered tools matching optional role, agent, or enablement filters."""
        tools = list(self._tools.values())
        if enabled_only:
            tools = [t for t in tools if t.is_enabled]

        target_agent = agent_id or agent_type
        if target_agent is not None:
            target_agent_val = target_agent.value if hasattr(target_agent, "value") else str(target_agent)
            tools = [
                t for t in tools
                if any((a.value if hasattr(a, "value") else str(a)) == target_agent_val for a in t.allowed_agents)
            ]

        if role is not None:
            role_val = role.value if hasattr(role, "value") else str(role)
            if role_val != RBACRoleEnum.ADMIN.value:
                tools = [
                    t for t in tools
                    if any((r.value if hasattr(r, "value") else str(r)) == role_val for r in t.allowed_roles)
                ]

        return tools

    def items(self) -> Any:
        """Return dict-like items view."""
        return self._tools.items()

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def __iter__(self) -> Any:
        return iter(self._tools.values())

    def unregister(self, name: str) -> bool:
        """Remove a tool from registry (testing / administration)."""
        if name in self._tools:
            del self._tools[name]
            return True
        return False


# ==============================================================================
# Pre-Registered Default Investigation Tools Factory
# ==============================================================================

ALL_ANALYST_ROLES = [
    RBACRoleEnum.SOC_ANALYST,
    RBACRoleEnum.DETECTION_ENGINEER,
    RBACRoleEnum.THREAT_HUNTER,
    RBACRoleEnum.SOC_MANAGER,
    RBACRoleEnum.SECURITY_ENGINEER,
    RBACRoleEnum.ADMIN,
]

INVESTIGATION_AGENTS = [
    AgentIdEnum.TRIAGE_AGENT,
    AgentIdEnum.INVESTIGATION_AGENT,
    AgentIdEnum.THREAT_INTEL_AGENT,
    AgentIdEnum.THREAT_HUNTING_AGENT,
    AgentIdEnum.EVIDENCE_AGENT,
    AgentIdEnum.ATTACK_MAPPING_AGENT,
    AgentIdEnum.RISK_AGENT,
    AgentIdEnum.RESPONSE_AGENT,
]


def create_default_tool_registry(include_extensions: bool = False) -> ToolRegistry:
    """Instantiate and populate the authoritative CyberSentinel AI tool registry."""
    registry = ToolRegistry()

    # 1. get_incident_summary
    registry.register(
        ToolDefinition(
            name="get_incident_summary",
            description="Retrieve authoritative metadata for the scoped incident.",
            permitted_purpose="Read incident title, status, severity, and temporal bounds.",
            input_schema=GetIncidentSummaryInput,
            output_schema=GetIncidentSummaryOutput,
            required_permission="incident:read",
            allowed_roles=ALL_ANALYST_ROLES,
            allowed_agents=INVESTIGATION_AGENTS,
            read_only=True,
            timeout_seconds=5.0,
        )
    )

    # 2. get_incident_detections
    registry.register(
        ToolDefinition(
            name="get_incident_detections",
            description="Retrieve Sigma detections associated with the incident.",
            permitted_purpose="Inspect correlated rule detections and trigger context.",
            input_schema=GetIncidentDetectionsInput,
            output_schema=GetIncidentDetectionsOutput,
            required_permission="detection:read",
            allowed_roles=ALL_ANALYST_ROLES,
            allowed_agents=INVESTIGATION_AGENTS,
            read_only=True,
            timeout_seconds=10.0,
        )
    )

    # 3. get_canonical_events
    registry.register(
        ToolDefinition(
            name="get_canonical_events",
            description="Retrieve raw canonical security events backing detections.",
            permitted_purpose="Inspect event payloads and schema metadata.",
            input_schema=GetCanonicalEventsInput,
            output_schema=GetCanonicalEventsOutput,
            required_permission="event:read",
            allowed_roles=ALL_ANALYST_ROLES,
            allowed_agents=INVESTIGATION_AGENTS,
            read_only=True,
            timeout_seconds=15.0,
        )
    )

    # 4. get_incident_timeline
    registry.register(
        ToolDefinition(
            name="get_incident_timeline",
            description="Retrieve unified chronological timeline for the incident.",
            permitted_purpose="Analyze sequential progression of attacker activity.",
            input_schema=GetIncidentTimelineInput,
            output_schema=GetIncidentTimelineOutput,
            required_permission="incident:read",
            allowed_roles=ALL_ANALYST_ROLES,
            allowed_agents=INVESTIGATION_AGENTS,
            read_only=True,
            timeout_seconds=10.0,
        )
    )

    # 5. get_incident_entities
    registry.register(
        ToolDefinition(
            name="get_incident_entities",
            description="Retrieve entity relationships attached to this incident.",
            permitted_purpose="Inspect affected hosts, users, IPs, and domains.",
            input_schema=GetIncidentEntitiesInput,
            output_schema=GetIncidentEntitiesOutput,
            required_permission="incident:read",
            allowed_roles=ALL_ANALYST_ROLES,
            allowed_agents=INVESTIGATION_AGENTS,
            read_only=True,
            timeout_seconds=10.0,
        )
    )

    # 6. get_incident_evidence
    registry.register(
        ToolDefinition(
            name="get_incident_evidence",
            description="Retrieve evidence artifacts recorded for the incident.",
            permitted_purpose="Inspect verified evidence items, checksums, and provenance.",
            input_schema=GetIncidentEvidenceInput,
            output_schema=GetIncidentEvidenceOutput,
            required_permission="evidence:read",
            allowed_roles=ALL_ANALYST_ROLES,
            allowed_agents=INVESTIGATION_AGENTS,
            read_only=True,
            timeout_seconds=10.0,
        )
    )

    # 7. get_prior_findings
    registry.register(
        ToolDefinition(
            name="get_prior_findings",
            description="Retrieve findings generated by previous agent runs on this incident.",
            permitted_purpose="Synthesize previous deductions and analytical conclusions.",
            input_schema=GetPriorFindingsInput,
            output_schema=GetPriorFindingsOutput,
            required_permission="investigation:read",
            allowed_roles=ALL_ANALYST_ROLES,
            allowed_agents=INVESTIGATION_AGENTS,
            read_only=True,
            timeout_seconds=10.0,
        )
    )

    # 8. lookup_threat_intel
    registry.register(
        ToolDefinition(
            name="lookup_threat_intel",
            description="Query threat intelligence repository for indicator context.",
            permitted_purpose="Enrich indicators with validated source reputation and actor attribution.",
            input_schema=LookupThreatIntelInput,
            output_schema=LookupThreatIntelOutput,
            required_permission="threat_intel:read",
            allowed_roles=ALL_ANALYST_ROLES,
            allowed_agents=INVESTIGATION_AGENTS,
            read_only=True,
            timeout_seconds=10.0,
        )
    )

    # 9. get_incident_risk_assessment
    registry.register(
        ToolDefinition(
            name="get_incident_risk_assessment",
            description="Retrieve explainable deterministic risk assessment for this incident.",
            permitted_purpose="Inspect authoritative risk score, band, drivers, and uncertainties.",
            input_schema=GetIncidentRiskAssessmentInput,
            output_schema=GetIncidentRiskAssessmentOutput,
            required_permission="risk:read",
            allowed_roles=ALL_ANALYST_ROLES,
            allowed_agents=INVESTIGATION_AGENTS,
            read_only=True,
            timeout_seconds=10.0,
        )
    )

    if include_extensions:
        register_sprint18_tools(registry)
        register_sprint19_tools(registry)

    return registry


def register_sprint18_tools(registry: ToolRegistry) -> None:
    """Register Sprint 18 RAG and Threat Hunting tools."""
    # 10. search_knowledge_base
    if not registry.get("search_knowledge_base"):
        registry.register(
            ToolDefinition(
                name="search_knowledge_base",
                description="Query authorized RAG knowledge base across ATT&CK, Sigma, playbooks, and intelligence.",
                permitted_purpose="Retrieve verified security reference documents with source citations.",
                input_schema=SearchKnowledgeBaseInput,
                output_schema=SearchKnowledgeBaseOutput,
                required_permission="knowledge:read",
                allowed_roles=ALL_ANALYST_ROLES,
                allowed_agents=INVESTIGATION_AGENTS,
                read_only=True,
                timeout_seconds=10.0,
            )
        )

    # 11. run_threat_hunt
    if not registry.get("run_threat_hunt"):
        registry.register(
            ToolDefinition(
                name="run_threat_hunt",
                description="Execute bounded threat hunt queries over telemetry, detections, and entities.",
                permitted_purpose="Discover anomalous authentication, process, network, or ATT&CK behavior.",
                input_schema=RunThreatHuntInput,
                output_schema=RunThreatHuntOutput,
                required_permission="hunting:execute",
                allowed_roles=ALL_ANALYST_ROLES,
                allowed_agents=INVESTIGATION_AGENTS,
                read_only=True,
                timeout_seconds=15.0,
            )
        )


def register_sprint19_tools(registry: ToolRegistry) -> None:
    """Register Sprint 19 Detection Engineering Assistant tools."""
    # 12. generate_candidate_rule
    if not registry.get("generate_candidate_rule"):
        registry.register(
            ToolDefinition(
                name="generate_candidate_rule",
                description="Generate a candidate Sigma detection rule from a structured security objective.",
                permitted_purpose="Draft new candidate detection rules conforming to platform schemas.",
                input_schema=GenerateCandidateRuleInput,
                output_schema=GenerateCandidateRuleOutput,
                required_permission="detection:write",
                allowed_roles=ALL_ANALYST_ROLES,
                allowed_agents=INVESTIGATION_AGENTS,
                read_only=True,
                timeout_seconds=15.0,
            )
        )

    # 13. validate_sigma_rule
    if not registry.get("validate_sigma_rule"):
        registry.register(
            ToolDefinition(
                name="validate_sigma_rule",
                description="Validate a Sigma rule's syntax, logsource, fields, condition, and ATT&CK tags.",
                permitted_purpose="Run static schema and quality checks on a detection rule.",
                input_schema=ValidateSigmaRuleInput,
                output_schema=ValidateSigmaRuleOutput,
                required_permission="detection:read",
                allowed_roles=ALL_ANALYST_ROLES,
                allowed_agents=INVESTIGATION_AGENTS,
                read_only=True,
                timeout_seconds=10.0,
            )
        )

    # 14. test_candidate_rule
    if not registry.get("test_candidate_rule"):
        registry.register(
            ToolDefinition(
                name="test_candidate_rule",
                description="Safely evaluate a Sigma rule against synthetic or historical test fixtures in-memory.",
                permitted_purpose="Test rule detection fidelity and false positive rates without production activation.",
                input_schema=TestCandidateRuleInput,
                output_schema=TestCandidateRuleOutput,
                required_permission="detection:test",
                allowed_roles=ALL_ANALYST_ROLES,
                allowed_agents=INVESTIGATION_AGENTS,
                read_only=True,
                timeout_seconds=15.0,
            )
        )

    # 15. explain_detection_rule
    if not registry.get("explain_detection_rule"):
        registry.register(
            ToolDefinition(
                name="explain_detection_rule",
                description="Produce an analyst-friendly explanation of a Sigma rule, its ATT&CK mappings, and blind spots.",
                permitted_purpose="Inspect detection logic and quality analysis of a Sigma rule.",
                input_schema=ExplainDetectionRuleInput,
                output_schema=ExplainDetectionRuleOutput,
                required_permission="detection:read",
                allowed_roles=ALL_ANALYST_ROLES,
                allowed_agents=INVESTIGATION_AGENTS,
                read_only=True,
                timeout_seconds=10.0,
            )
        )


# Global default registry instance (preserving baseline 9 tools for Sprint 16 test compatibility)
default_registry = create_default_tool_registry(include_extensions=False)

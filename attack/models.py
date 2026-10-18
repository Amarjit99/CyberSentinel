"""CyberSentinel AI — MITRE ATT&CK Domain Models & Schemas (Sprint 12)"""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class AttackTactic(BaseModel):
    """Authoritative MITRE ATT&CK Tactic definition."""

    id: str = Field(..., description="Canonical tactic identifier, e.g. TA0002")
    short_name: str = Field(..., description="Short normalized identifier, e.g. execution")
    name: str = Field(..., description="Display title, e.g. Execution")
    description: str = Field(default="", description="Tactic narrative and objective")


class AttackTechnique(BaseModel):
    """Authoritative MITRE ATT&CK Technique or Sub-technique definition."""

    id: str = Field(..., description="Canonical technique identifier, e.g. T1059.001")
    name: str = Field(..., description="Technique display title")
    description: str = Field(default="", description="Technical adversary behavior description")
    tactics: List[str] = Field(default_factory=list, description="Associated tactic short names")
    parent_id: Optional[str] = Field(default=None, description="Parent technique ID if sub-technique")
    is_subtechnique: bool = Field(default=False, description="Whether this is a sub-technique")
    platforms: List[str] = Field(default_factory=list, description="Applicable operating systems/platforms")
    data_sources: List[str] = Field(default_factory=list, description="Associated telemetry data sources")
    url: str = Field(default="", description="Official MITRE ATT&CK reference URL")
    is_deprecated: bool = Field(default=False, description="Whether the technique is deprecated")
    is_revoked: bool = Field(default=False, description="Whether the technique has been revoked")


class AttackTagMapping(BaseModel):
    """Resolved relationship between a rule tag and an authoritative ATT&CK entity."""

    raw_tag: str = Field(..., description="Original tag string from detection or correlation rule")
    rule_id: str = Field(..., description="Unique rule identifier")
    rule_type: str = Field(..., description="Rule origin: 'sigma' or 'correlation'")
    mapping_type: str = Field(..., description="'technique' or 'tactic'")
    technique_id: Optional[str] = Field(default=None, description="Resolved technique ID if applicable")
    technique_name: Optional[str] = Field(default=None, description="Resolved technique display name")
    tactic: Optional[str] = Field(default=None, description="Associated tactic short name")
    status: str = Field(
        ..., description="Resolution status: 'valid', 'deprecated', 'revoked', 'unresolved'"
    )
    diagnostic: Optional[str] = Field(default=None, description="Human-readable reason if not valid")
    catalog_version: str = Field(default="15.1", description="Pinned ATT&CK catalog version")


class MappingReport(BaseModel):
    """Aggregate compilation report of rule tags mapped against ATT&CK catalog."""

    catalog_version: str
    total_tags: int
    valid_mappings: int
    deprecated_mappings: int
    revoked_mappings: int
    unresolved_mappings: int
    mappings: List[AttackTagMapping]


class TacticCoverageItem(BaseModel):
    """Coverage metrics for an individual MITRE ATT&CK tactic."""

    tactic_id: str
    tactic_name: str
    short_name: str
    technique_count_catalog: int
    technique_count_covered: int
    coverage_ratio: float
    covered_technique_ids: List[str]


class AttackCoverageSummary(BaseModel):
    """Authoritative platform ATT&CK detection coverage summary."""

    catalog_version: str
    total_catalog_techniques: int
    total_rules_evaluated: int
    unique_techniques_covered: int
    overall_coverage_percentage: float
    coverage_basis: str = "active_rule_mappings"
    valid_mapping_count: int = 0
    deprecated_mapping_count: int = 0
    unresolved_mapping_count: int = 0
    tactics: List[TacticCoverageItem]


class IncidentAttackCoverage(BaseModel):
    """Scoped ATT&CK coverage analysis for a specific security incident."""

    incident_id: str
    detection_count: int
    techniques: List[AttackTechnique]
    tactics_observed: List[str]


class IncidentAttackTimelineItem(BaseModel):
    """Chronological event/detection marker on an incident ATT&CK timeline."""

    timestamp: datetime
    detection_id: str
    rule_id: str
    rule_name: str
    severity: str
    technique_id: str
    technique_name: str
    tactic: str

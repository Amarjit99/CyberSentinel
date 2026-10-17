"""CyberSentinel AI — Reporting Service Boundary

Generates technical, executive, and regulatory compliance reports.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict

from pydantic import BaseModel, Field


class ReportArtifact(BaseModel):
    """Generated report artifact metadata and content."""

    report_id: str = Field(..., description="Unique report identifier")
    incident_id: str = Field(..., description="Target incident ID")
    report_type: str = Field(
        ..., description="Report classification (executive, technical, compliance)"
    )
    summary: str = Field(..., description="Executive narrative summary")
    metrics: Dict[str, Any] = Field(
        default_factory=dict, description="MTTD, MTTR, and telemetry statistics"
    )


class BaseReportGenerator(ABC):
    """Abstract interface for report generation."""

    @abstractmethod
    def generate_incident_report(self, incident_id: str, report_type: str) -> ReportArtifact:
        """Compile verified incident timeline, findings, and evidence into report."""
        raise NotImplementedError


__all__ = ["ReportArtifact", "BaseReportGenerator"]

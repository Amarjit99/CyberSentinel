"""CyberSentinel AI — Evidence Management Service Boundary

Maintains tamper-evident evidence chains and artifact storage references.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict

from pydantic import BaseModel, Field


class EvidenceRecord(BaseModel):
    """Immutable evidence artifact linked to an incident."""

    id: str = Field(..., description="Evidence unique identifier")
    incident_id: str = Field(..., description="Linked incident ID")
    evidence_type: str = Field(..., description="Type of artifact (pcap, log_slice, memory_dump)")
    source_ref: str = Field(..., description="Storage URI or object store key")
    checksum: str = Field(..., description="Cryptographic SHA-256 hash of payload")
    provenance_json: Dict[str, Any] = Field(
        default_factory=dict, description="Chain-of-custody lineage"
    )
    created_by: str = Field(..., description="Actor or agent ID recording evidence")


class BaseEvidenceManager(ABC):
    """Abstract interface for evidence recording and verification."""

    @abstractmethod
    def record_evidence(self, record: EvidenceRecord) -> bool:
        """Store evidence metadata and verify cryptographic checksum."""
        raise NotImplementedError


__all__ = ["EvidenceRecord", "BaseEvidenceManager"]

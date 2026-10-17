"""CyberSentinel AI — Correlation Service Boundary
Performs temporal, entity-based, and graph correlation across disparate alerts.
Governing Decisions: ADR-0005, CSAI-P4-CORRELATION
"""

from abc import ABC, abstractmethod
from typing import List

from pydantic import BaseModel, Field


class CorrelationCluster(BaseModel):
    """Cluster of correlated alerts grouped into an incident candidate."""

    cluster_id: str = Field(..., description="Unique cluster ID")
    detection_ids: List[str] = Field(..., description="Correlated detection IDs")
    common_entities: List[str] = Field(..., description="Shared host/user/IP entity keys")
    confidence: float = Field(
        default=1.0, ge=0.0, le=1.0, description="Correlation confidence score"
    )


class BaseCorrelationEngine(ABC):
    """Abstract interface for event and detection correlation."""

    @abstractmethod
    def correlate(self, detection_ids: List[str]) -> List[CorrelationCluster]:
        """Group related detections into high-fidelity clusters."""
        raise NotImplementedError


from services.correlation.engine import CorrelationEngine, correlation_engine  # noqa: E402
from services.correlation.entity_extractor import EntityExtractor, ExtractedEntity, entity_extractor  # noqa: E402
from services.correlation.models import (  # noqa: E402
    CorrelationEvaluationError,
    CorrelationMatch,
    CorrelationRule,
    CorrelationRuleValidationError,
    SequenceStep,
)
from services.correlation.window import SlidingEventWindow, WindowEntry  # noqa: E402
from services.correlation.worker import StreamingCorrelationWorker  # noqa: E402

__all__ = [
    "CorrelationCluster",
    "BaseCorrelationEngine",
    "ExtractedEntity",
    "EntityExtractor",
    "entity_extractor",
    "CorrelationRule",
    "SequenceStep",
    "CorrelationMatch",
    "CorrelationRuleValidationError",
    "CorrelationEvaluationError",
    "SlidingEventWindow",
    "WindowEntry",
    "CorrelationEngine",
    "correlation_engine",
    "StreamingCorrelationWorker",
]

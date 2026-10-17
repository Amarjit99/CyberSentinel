"""CyberSentinel AI — Log Ingestion Service

Provides the connector framework, ingestion pipeline orchestrator, durable queues, and quarantine management.
"""

from services.ingestion.framework import (
    BaseConnector,
    ConnectorConfig,
    ConnectorMetrics,
    ConnectorStatus,
    ErrorClassification,
    IngestionException,
)
from services.ingestion.pipeline import (
    IngestionPipeline,
    IngestionPipelineResult,
    pipeline,
)
from services.ingestion.queue import (
    DurableEventQueue,
    QuarantineManager,
    QuarantineRecord,
    durable_queue,
    quarantine_manager,
)

__all__ = [
    "BaseConnector",
    "ConnectorConfig",
    "ConnectorMetrics",
    "ConnectorStatus",
    "ErrorClassification",
    "IngestionException",
    "IngestionPipeline",
    "IngestionPipelineResult",
    "pipeline",
    "DurableEventQueue",
    "QuarantineManager",
    "QuarantineRecord",
    "durable_queue",
    "quarantine_manager",
]

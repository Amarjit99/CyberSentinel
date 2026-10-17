"""CyberSentinel AI — Ingestion Framework Unit Tests"""

from typing import Any, Dict, List

from services.ingestion.framework import (
    BaseConnector,
    ConnectorConfig,
    ConnectorStatus,
    ErrorClassification,
    IngestionException,
)


class DummyConnector(BaseConnector):
    """Test connector implementation."""

    def supported_formats(self) -> List[str]:
        return ["dummy_format"]

    def parse_raw(self, payload: Any) -> List[Dict[str, Any]]:
        return [{"data": payload}]


def test_connector_lifecycle():
    """Verify start, stop, and health check transitions."""
    config = ConnectorConfig(
        connector_id="dummy-01",
        name="Dummy Test Connector",
        source_type="test",
        buffer_capacity=5,
    )
    conn = DummyConnector(config)
    assert conn.status == ConnectorStatus.INITIALIZED

    conn.start()
    assert conn.status == ConnectorStatus.RUNNING

    health = conn.health_check()
    assert health["healthy"] is True
    assert health["connector_id"] == "dummy-01"
    assert health["buffer_usage"] == 0

    conn.stop()
    assert conn.status == ConnectorStatus.STOPPED


def test_connector_backpressure_and_flushing():
    """Verify bounded buffer triggers backpressure when capacity is reached."""
    config = ConnectorConfig(
        connector_id="dummy-02",
        name="Backpressure Test",
        source_type="test",
        buffer_capacity=3,
        batch_size=2,
    )
    conn = DummyConnector(config)
    conn.start()

    assert conn.buffer_event({"id": 1}) is True
    assert conn.buffer_event({"id": 2}) is True
    assert conn.buffer_event({"id": 3}) is True

    # 4th event should fail due to full buffer
    assert conn.buffer_event({"id": 4}) is False
    assert conn.status == ConnectorStatus.DEGRADED

    # Drain batch of 2
    batch = conn.flush_batch(max_items=2)
    assert len(batch) == 2
    assert batch[0]["id"] == 1
    assert batch[1]["id"] == 2
    assert conn.metrics.buffer_usage == 1
    assert conn.status == ConnectorStatus.RUNNING


def test_error_classification_retryability():
    """Verify transient errors are retryable while permanent errors are not."""
    transient = IngestionException("Connection reset", classification=ErrorClassification.TRANSIENT)
    permanent = IngestionException(
        "Invalid JSON syntax", classification=ErrorClassification.PERMANENT
    )

    assert transient.is_retryable is True
    assert permanent.is_retryable is False

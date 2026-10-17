"""CyberSentinel AI — Normalization Engine Unit Tests"""

from datetime import timezone

from services.normalization.engine import NormalizationEngine


def test_normalization_engine_success():
    """Verify raw record normalizes into validated CanonicalEvent."""
    engine = NormalizationEngine()
    record = {
        "timestamp": "2026-10-16T12:00:00+02:00",
        "source_type": "windows",
        "source_name": "sysmon",
        "event_type": "process_creation",
        "hostname": "SERVER-01",
        "username": "admin",
        "severity": "high",
        "raw_record": {"id": 100},
    }
    result = engine.normalize(record, connector_id="win-conn-01")
    assert result.success is True
    assert result.event is not None
    assert result.is_quarantined is False
    assert result.event.source_type == "windows"
    assert result.event.hostname == "SERVER-01"
    assert result.event.severity.value == "high"

    # Timestamp must be normalized to UTC (12:00+02:00 -> 10:00 UTC)
    assert result.event.timestamp.tzinfo == timezone.utc
    assert result.event.timestamp.hour == 10
    assert "s3://telemetry-lake/windows/" in result.event.raw_ref
    assert len(result.raw_hash) == 64


def test_normalization_engine_missing_critical_fields_quarantines():
    """Verify invalid record missing source_name and event_type is quarantined safely."""
    engine = NormalizationEngine()
    invalid_record = {
        # Missing source_name and event_type
        "timestamp": "invalid_date",
        "source_type": "windows",
    }
    result = engine.normalize(invalid_record)
    assert result.success is False
    assert result.event is None
    assert result.is_quarantined is True
    assert "Canonical normalization error" in str(result.error)
    assert len(result.raw_hash) == 64


def test_normalization_batch():
    """Verify batch normalization across multiple items."""
    engine = NormalizationEngine()
    batch = [
        {
            "timestamp": "2026-10-16T12:00:00Z",
            "source_type": "network",
            "source_name": "zeek",
            "event_type": "conn",
        },
        {
            "timestamp": "2026-10-16T12:01:00Z",
            "source_type": "cloud",
            "source_name": "aws",
            "event_type": "iam",
        },
    ]
    results = engine.normalize_batch(batch)
    assert len(results) == 2
    assert results[0].success is True
    assert results[1].success is True

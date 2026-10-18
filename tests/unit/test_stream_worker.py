"""Unit tests for continuous stream ingestion worker."""

from datetime import datetime, timezone

from services.detection.engine import SigmaDetectionEngine
from services.ingestion.stream_worker import StreamIngestionWorker


def test_stream_worker_basic_batch():
    worker = StreamIngestionWorker()
    raw_events = [
        {
            "event_id": "evt-stream-1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_type": "windows",
            "source_name": "sysmon",
            "event_type": "process_creation",
            "hostname": "workstation-01",
            "process_name": "calc.exe",
            "command_line": "calc.exe",
            "raw_record": {"command": "calc.exe"},
        },
        {
            "event_id": "evt-stream-2",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_type": "windows",
            "source_name": "sysmon",
            "event_type": "process_creation",
            "hostname": "workstation-02",
            "process_name": "notepad.exe",
            "command_line": "notepad.exe",
            "raw_record": {"command": "notepad.exe"},
        },
    ]

    result = worker.process_stream_batch(raw_events, connector_id="test-connector")
    assert result.events_received == 2
    assert result.events_ingested == 2
    assert result.events_quarantined == 0
    assert result.processing_time_ms >= 0


def test_stream_worker_with_detection():
    detection_engine = SigmaDetectionEngine()
    rule_yaml = """
title: Suspicious Cmd Whoami
id: 88888888-4444-4444-a444-121212121212
status: test
description: Detects whoami execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        process_name: 'whoami.exe'
    condition: selection
level: high
"""
    detection_engine.load_rule(rule_yaml, source_name="test_whoami.yml")
    worker = StreamIngestionWorker(detection_engine=detection_engine)

    raw_events = [
        {
            "event_id": "evt-whoami-1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_type": "windows",
            "source_name": "sysmon",
            "event_type": "process_creation",
            "hostname": "finance-pc",
            "process_name": "whoami.exe",
            "command_line": "whoami.exe /all",
            "raw_record": {"command": "whoami.exe /all"},
        }
    ]

    result = worker.process_stream_batch(raw_events, connector_id="stream-edr")
    assert result.events_received == 1
    assert result.events_ingested == 1
    assert result.detections_matched == 1
    assert len(result.detection_ids) == 1

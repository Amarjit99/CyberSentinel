"""Unit Tests for CanonicalEvent Pydantic v2 Schema
Traceability: TEST-FR-003, TEST-FR-004, ADR-0005
"""

import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from schemas.canonical_event import CanonicalEvent
from schemas.enums import EventSeverityEnum


def test_valid_canonical_event_parses_and_serializes():
    """Verify that a compliant event parses correctly and produces valid JSON."""
    raw_payload = {
        "timestamp": "2026-10-16T12:00:00Z",
        "source_type": "windows",
        "source_name": "sysmon",
        "event_type": "process_creation",
        "host_id": "asset-ws-001",
        "hostname": "WORKSTATION-01",
        "user_id": "S-1-5-21-123456789-500",
        "username": "sec_analyst",
        "src_ip": "10.0.1.15",
        "dst_ip": "192.168.1.100",
        "src_port": 49152,
        "dst_port": 443,
        "process_name": "powershell.exe",
        "process_id": 4820,
        "parent_process": "explorer.exe",
        "command_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass",
        "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "domain": "internal.corp",
        "url": "https://internal.corp/api/telemetry",
        "severity": "medium",
        "raw_ref": "s3://raw-telemetry/2026/10/16/event-001.json",
        "raw_event": {"OriginalEventId": 1, "Channel": "Microsoft-Windows-Sysmon/Operational"},
        "entities": {"department": "SecurityOperations"},
    }

    event = CanonicalEvent(**raw_payload)

    assert event.source_type == "windows"
    assert event.source_name == "sysmon"
    assert event.event_type == "process_creation"
    assert str(event.src_ip) == "10.0.1.15"
    assert str(event.dst_ip) == "192.168.1.100"
    assert event.src_port == 49152
    assert event.dst_port == 443
    assert event.severity == EventSeverityEnum.MEDIUM
    assert event.schema_version == "1.0.0"

    # Verify JSON serialization
    serialized = event.model_dump_json()
    data = json.loads(serialized)
    assert data["hostname"] == "WORKSTATION-01"
    assert data["process_id"] == 4820


def test_timestamp_normalized_to_utc():
    """Verify that non-UTC timezone-aware timestamps are normalized to UTC."""
    event = CanonicalEvent(
        timestamp="2026-10-16T17:30:00+05:30",  # UTC 12:00:00
        source_type="linux",
        source_name="auditd",
        event_type="execve",
    )

    assert event.timestamp.tzinfo == timezone.utc
    assert event.timestamp.hour == 12
    assert event.timestamp.minute == 0


def test_missing_required_fields_raises_validation_error():
    """Missing required identifiers (timestamp, source_type, source_name, event_type) must fail."""
    with pytest.raises(ValidationError) as exc_info:
        CanonicalEvent(source_type="windows")  # Missing timestamp, source_name, event_type

    errors = exc_info.value.errors()
    missing_fields = {e["loc"][0] for e in errors}
    assert "timestamp" in missing_fields
    assert "source_name" in missing_fields
    assert "event_type" in missing_fields


def test_invalid_types_and_ranges_fail():
    """Invalid IPs, invalid ports, and malformed hashes must be rejected."""
    # Invalid port > 65535
    with pytest.raises(ValidationError):
        CanonicalEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="network",
            source_name="suricata",
            event_type="flow",
            dst_port=70000,  # Invalid
        )

    # Invalid IP address
    with pytest.raises(ValidationError):
        CanonicalEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="network",
            source_name="suricata",
            event_type="flow",
            src_ip="999.999.999.999",  # Invalid IP
        )

    # Invalid SHA-256 hash (less than 64 characters)
    with pytest.raises(ValidationError):
        CanonicalEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="windows",
            source_name="sysmon",
            event_type="process_creation",
            hash_sha256="not_a_valid_hash",
        )


def test_unknown_fields_are_forbidden():
    """Per ADR-0005, unknown top-level fields are rejected to prevent parameter injection."""
    with pytest.raises(ValidationError) as exc_info:
        CanonicalEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="windows",
            source_name="sysmon",
            event_type="process_creation",
            unauthorized_field="malicious_payload",
        )

    err = exc_info.value.errors()[0]
    assert err["type"] == "extra_forbidden"
    assert "unauthorized_field" in err["loc"]


def test_schema_version_incompatibility_fails():
    """Unsupported major schema version must fail."""
    with pytest.raises(ValidationError):
        CanonicalEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="windows",
            source_name="sysmon",
            event_type="process_creation",
            schema_version="2.0.0",  # Incompatible with 1.x
        )


def test_sensitive_value_redaction_pipeline():
    """Verify that to_redacted_dict masks credentials and tokens."""
    event = CanonicalEvent(
        timestamp=datetime.now(timezone.utc),
        source_type="windows",
        source_name="sysmon",
        event_type="process_creation",
        command_line="login.exe --user admin --password SecretPassword123! --token ghp_987654321",
        raw_event={
            "User": "admin",
            "password": "CleartextPassword!",
            "api_key": "secret_key_12345",
        },
    )

    redacted = event.to_redacted_dict()
    assert "SecretPassword123!" not in redacted["command_line"]
    assert "ghp_987654321" not in redacted["command_line"]
    assert "CleartextPassword!" not in str(redacted["raw_event"])
    assert "secret_key_12345" not in str(redacted["raw_event"])
    assert "********" in redacted["command_line"]

"""Tests for Entity Extraction from CanonicalEvent."""

import uuid
from datetime import datetime, timezone

from schemas.canonical_event import CanonicalEvent
from schemas.enums import EventSeverityEnum
from services.correlation.entity_extractor import entity_extractor


def create_sample_event(
    hostname: str = "victim-pc",
    username: str = "john_doe",
    src_ip: str = "192.168.1.50",
    dst_ip: str = "10.0.0.1",
    process_name: str = "powershell.exe",
    sha256: str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    domain: str = "malicious.example.com",
) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        source_type="windows",
        source_name="Microsoft-Windows-Sysmon",
        event_type="process_creation",
        severity=EventSeverityEnum.HIGH,
        hostname=hostname,
        username=username,
        src_ip=src_ip,
        dst_ip=dst_ip,
        process_name=process_name,
        hash_sha256=sha256,
        domain=domain,
    )


def test_extract_all_entities():
    event = create_sample_event()
    entities = entity_extractor.extract_from_event(event)

    types = {e.entity_type for e in entities}
    assert "host" in types
    assert "user" in types
    assert "ip" in types
    assert "process" in types
    assert "file_hash" in types
    assert "domain" in types

    # Check normalization
    user_ents = [e for e in entities if e.entity_type == "user"]
    assert any(e.entity_key == "john_doe" for e in user_ents)

    host_ents = [e for e in entities if e.entity_type == "host"]
    assert any(e.entity_key == "victim-pc" for e in host_ents)

    hash_ents = [e for e in entities if e.entity_type == "file_hash"]
    assert any(e.entity_key.startswith("e3b0c442") for e in hash_ents)


def test_extract_key_for_grouping():
    event = create_sample_event(hostname="WORKSTATION-99", username="Alice")

    host_key = entity_extractor.get_group_key(event, "hostname")
    assert host_key == "workstation-99"

    user_key = entity_extractor.get_group_key(event, "username")
    assert user_key == "alice"

    ip_key = entity_extractor.get_group_key(event, "src_ip")
    assert ip_key == "192.168.1.50"


def test_extract_key_missing_returns_none():
    event = CanonicalEvent(
        event_id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        source_type="network",
        source_name="firewall",
        event_type="network_traffic",
        severity=EventSeverityEnum.LOW,
    )
    assert entity_extractor.get_group_key(event, "hostname") is None

    assert entity_extractor.get_group_key(event, "username") is None
    assert entity_extractor.get_group_key(event, "hash_sha256") is None

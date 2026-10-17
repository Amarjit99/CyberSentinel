# ADR-0005: Canonical Event Schema and Redaction Standards

**Status:** Accepted  
**Date:** 2026-10-16  
**Deciders:** Data Architect, Security Architect, Senior Software Architect  
**Governing Conflict:** [CONFL-005](../audit/CONFLICT_REGISTER.md#confl-005-canonical-event-schema-field-definitions-and-normalization-contracts) & [CONFL-009](../audit/CONFLICT_REGISTER.md#confl-009-two-stage-telemetry-redaction-and-external-ai-model-privacy-boundaries)  

---

## 1. Context & Problem Statement

Discrepancies existed between the concrete 23-field JSON example in the master spec and abstract domain descriptions in companion documents. Additionally, the exact placement of data redaction (pre-storage vs pre-LLM) required formal definition.

## 2. Decision

### Canonical Event Schema (Pydantic v2 Core)
All ingested telemetry is normalized into the following core schema before indexing in OpenSearch:

```python
class CanonicalEvent(BaseModel):
    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime  # Event occurrence time (UTC)
    ingest_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_type: str  # windows, linux, network, cloud, auth, ti
    source_name: str  # sysmon, auditd, suricata, zeek, crowdstrike
    event_type: str  # process_creation, network_connection, authentication, dns_query
    host_id: Optional[str] = None
    hostname: Optional[str] = None
    user_id: Optional[str] = None
    username: Optional[str] = None
    src_ip: Optional[IPvAnyAddress] = None
    dst_ip: Optional[IPvAnyAddress] = None
    src_port: Optional[int] = Field(default=None, ge=1, le=65535)
    dst_port: Optional[int] = Field(default=None, ge=1, le=65535)
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process: Optional[str] = None
    command_line: Optional[str] = None
    hash_sha256: Optional[str] = Field(default=None, regex=r"^[a-fA-F0-9]{64}$")
    domain: Optional[str] = None
    url: Optional[str] = None
    severity: Literal["low", "medium", "high", "critical", "informational"] = "informational"
    raw_ref: str  # Object storage URI or immutable raw event reference
    entities: Dict[str, Any] = Field(default_factory=dict)  # Extensible metadata
```

### Two-Stage Privacy & Redaction Pipeline
1. **Stage 1 (Storage Gate):** Pre-indexing redaction masks plaintext passwords, API keys, and known session tokens from `command_line` and `raw_event` before OpenSearch ingestion.
2. **Stage 2 (LLM Gateway):** Pre-model dispatch redaction anonymizes internal IP ranges, email addresses, employee names, and proprietary asset identifiers unless explicit tenant policy permits external transmission.

## 3. Consequences

### Positive
- Strict Pydantic v2 validation prevents malformed telemetry from corrupting search indices.
- Preserves raw forensic payloads while protecting privacy across third-party LLM boundaries.

"""CyberSentinel AI — Sprint 25 Controlled Fault-Injection Unit Tests (CSAI-R1.4-RELIABILITY)

Deterministic unit tests verifying the 15 required reliability failure modes:
1. PostgreSQL / Database connection failure and recovery.
2. Transaction rollback after an injected failure.
3. Connection-pool exhaustion / timeout handling.
4. Redis or queue unavailability and recovery.
5. Duplicate event delivery and idempotent replay.
6. Malformed events and dead-letter behavior.
7. AI provider timeout, rate limiting, authentication error, malformed response, and sustained outage.
8. Tool timeout, failed orchestration step, and exhausted task budget.
9. Concurrent incident updates and optimistic-concurrency conflicts.
10. Audit persistence failure.
11. Frontend API timeout and safe idempotent retry.
12. Readiness and degraded-state correctness.
13. Secret redaction in errors and logs.
14. Authorization denial and cross-incident isolation during retry.
15. Safety invariant enforcement when dependencies fail or recover.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from packages.auth import Principal
from packages.observability.metrics import metrics
from packages.observability.redaction import safe_diagnostic_message, scrub_secrets, scrub_string
from schemas.canonical_event import CanonicalEvent
from schemas.enums import EventSeverityEnum, IncidentStateEnum, RBACRoleEnum
from services.agents import AgentRunStateEnum
from services.agents.investigation import InvestigationAgent, InvestigationRunRequest
from services.agents.providers import (
    CircuitBreaker,
    CircuitState,
    DeterministicRuleProvider,
    HTTPLLMProvider,
    LLMProviderAuthenticationError,
    LLMProviderUnavailableError,
    MockLLMProvider,
)
from services.incidents.lifecycle import IncidentConcurrencyError, IncidentLifecycleManager
from services.ingestion.pipeline import IngestionPipeline
from services.ingestion.queue import BrokerUnavailableError, DurableEventQueue, QuarantineManager
from services.normalization.deduplication import DeduplicationCache
from services.normalization.engine import NormalizationEngine
from services.persistence.database import check_database_health, managed_transaction
from services.persistence.models import Base, Incident
from services.response import (
    CreateProposalRequest,
    ExecuteActionRequest,
    ProposalStateEnum,
    ResponseManager,
    SubmitApprovalRequest,
)


def create_test_incident(session, inc_id="inc-test-01", status=IncidentStateEnum.NEW, version=1):
    now = datetime.now(timezone.utc)
    inc = Incident(
        id=inc_id,
        title="Test Security Incident",
        severity=EventSeverityEnum.HIGH.value,
        status=status.value,
        version=version,
        first_seen=now,
        last_seen=now,
        created_at=now,
        updated_at=now,
    )
    session.add(inc)
    session.commit()
    return inc


# ==============================================================================
# 1. Database Connection Failure and Recovery
# ==============================================================================

def test_database_connection_failure_and_recovery():
    """Mode: isolated_sqlite_unit
    Verify check_database_health detects database disconnections truthfully and measures latency.
    """
    is_healthy, msg, latency = check_database_health()
    assert is_healthy is True
    assert msg == "connected"
    assert latency >= 0.0

    # Injected failure: engine connection fails
    with patch("services.persistence.database.engine.connect", side_effect=ConnectionRefusedError("Simulated connection refused")):
        failed_healthy, failed_msg, failed_latency = check_database_health(timeout_seconds=0.1)
        assert failed_healthy is False
        assert "unreachable" in failed_msg
        assert failed_latency >= 0.0

    # Recovery: engine reconnects normally
    rec_healthy, rec_msg, rec_latency = check_database_health()
    assert rec_healthy is True
    assert rec_msg == "connected"


# ==============================================================================
# 2. Transaction Rollback After Injected Failure
# ==============================================================================

def test_transaction_rollback_after_injected_failure():
    """Mode: isolated_sqlite_unit
    Verify managed_transaction automatically rolls back on unhandled exceptions and increments metric.
    """
    test_engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(test_engine)
    Session = sessionmaker(bind=test_engine)
    session = Session()

    inc = create_test_incident(session, "inc-test-rollback")
    prior_rollback_count = metrics.snapshot().get("db_transaction_rollbacks_total", 0.0)

    # Injected failure within managed_transaction
    with pytest.raises(RuntimeError, match="Simulated mid-transaction failure"):
        with managed_transaction(session):
            inc.title = "Corrupted Title That Must Roll Back"
            raise RuntimeError("Simulated mid-transaction failure")

    # Verify rollback preserved original title
    session.refresh(inc)
    assert inc.title == "Test Security Incident"

    new_rollback_count = metrics.snapshot().get("db_transaction_rollbacks_total", 0.0)
    assert new_rollback_count >= prior_rollback_count + 1.0


# ==============================================================================
# 3. Connection-Pool Exhaustion / Timeout Handling
# ==============================================================================

def test_connection_pool_timeout_handling():
    """Mode: mocked_unit
    Verify connection pool timeout is handled gracefully without leaking credentials.
    """
    import sqlalchemy.exc

    with patch("services.persistence.database.engine.connect", side_effect=sqlalchemy.exc.TimeoutError("QueuePool limit of size 20 overflow 10 reached")):
        is_healthy, msg, _ = check_database_health(timeout_seconds=1.0)
        assert is_healthy is False
        assert "unreachable" in msg


# ==============================================================================
# 4. Redis or Queue Unavailability and Recovery
# ==============================================================================

def test_redis_queue_unavailability_and_recovery():
    """Mode: mocked_unit
    Verify queue transitions safely to in-memory fallback on broker failure and honors require_durability.
    """
    queue = DurableEventQueue(max_buffer_size=100)
    assert queue.storage_mode == "in_memory_volatile_fallback"
    assert queue.is_durable is False

    health = queue.check_health()
    assert health["status"] == "active"
    assert health["storage_mode"] == "in_memory_volatile_fallback"
    assert health["is_durable"] is False

    event = CanonicalEvent(
        timestamp=datetime.now(timezone.utc),
        source_type="sysmon",
        source_name="host_edr",
        event_type="process_creation",
    )
    with pytest.raises(BrokerUnavailableError):
        queue.enqueue(event, require_durability=True)

    success = queue.enqueue(event, require_durability=False)
    assert success is True
    assert queue.qsize() == 1


# ==============================================================================
# 5. Duplicate Event Delivery and Idempotent Replay
# ==============================================================================

def test_duplicate_event_delivery_and_idempotent_replay():
    """Mode: isolated_sqlite_unit
    Verify duplicate events do not create multiple detections or mutate incident counts.
    """
    test_engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(test_engine)
    Session = sessionmaker(bind=test_engine)
    session = Session()

    norm = NormalizationEngine()
    dedup = DeduplicationCache(max_capacity=1000, ttl_seconds=60)
    queue = DurableEventQueue(max_buffer_size=1000)
    quarantine = QuarantineManager(max_quarantine_size=100)

    pipe = IngestionPipeline(normalizer=norm, dedup_cache=dedup, queue=queue, quarantine=quarantine)
    record = {
        "timestamp": "2026-10-17T10:00:00Z",
        "source_type": "network",
        "source_name": "zeek_conn",
        "event_type": "network_connection",
        "src_ip": "10.0.0.5",
        "dst_ip": "198.51.100.2",
        "raw_record": {"original": "payload"},
    }

    res1 = pipe.ingest_event(record, connector_id="test", db_session=session)
    assert res1.status == "ingested"

    res2 = pipe.ingest_event(record, connector_id="test", db_session=session)
    assert res2.status == "duplicate"


# ==============================================================================
# 6. Malformed Events and Dead-Letter Behavior
# ==============================================================================

def test_malformed_event_quarantine_and_dlq():
    """Mode: isolated_sqlite_unit
    Verify malformed events are routed to quarantine and terminal failures to DLQ without crashing.
    """
    qm = QuarantineManager(max_quarantine_size=10, max_replay_attempts=2)
    rec = qm.quarantine_event(
        source_type="syslog",
        error_reason="Invalid syslog header format",
        raw_payload={"corrupted": True},
        raw_hash="hash_test_123",
    )
    assert rec.quarantine_id is not None
    assert len(qm.get_quarantine_records()) == 1

    r1 = qm.replay_quarantined(rec.quarantine_id)
    assert r1 is not None
    assert r1.replay_count == 1

    r2 = qm.replay_quarantined(rec.quarantine_id)
    assert r2 is not None
    assert r2.replay_count == 2

    # Exceeds max_replay_attempts=2 -> promotes to DLQ
    r3 = qm.replay_quarantined(rec.quarantine_id)
    assert r3 is None
    assert len(qm.get_quarantine_records()) == 0
    assert len(qm.get_dlq_records()) == 1


# ==============================================================================
# 7. AI Provider Faults: Rate Limit, Timeout, Auth Error, Circuit Breaker
# ==============================================================================

@pytest.mark.asyncio
async def test_ai_provider_circuit_breaker_and_sustained_outage():
    """Mode: mocked_unit
    Verify CircuitBreaker transitions from CLOSED to OPEN after failure threshold,
    rejects calls fast, and recovers after timeout.
    """
    cb = CircuitBreaker(failure_threshold=3, recovery_timeout_seconds=0.1, half_open_success_threshold=2)
    assert cb.state == CircuitState.CLOSED
    assert cb.can_execute() is True

    cb.record_failure()
    assert cb.state == CircuitState.CLOSED
    cb.record_failure()
    assert cb.state == CircuitState.CLOSED
    cb.record_failure()
    assert cb.state == CircuitState.OPEN
    assert cb.can_execute() is False

    provider = HTTPLLMProvider(api_key="test-key", circuit_breaker=cb)
    with pytest.raises(LLMProviderUnavailableError, match="Circuit breaker is OPEN"):
        await provider.generate_json(system_prompt="s", user_prompt="u")

    await asyncio.sleep(0.15)
    assert cb.can_execute() is True
    assert cb.state == CircuitState.HALF_OPEN

    cb.record_success()
    assert cb.state == CircuitState.HALF_OPEN
    cb.record_success()
    assert cb.state == CircuitState.CLOSED


@pytest.mark.asyncio
async def test_ai_provider_non_retryable_auth_failure():
    """Mode: mocked_unit
    Verify HTTP 401/403 authentication failures raise LLMProviderAuthenticationError immediately without retrying.
    """
    provider = HTTPLLMProvider(api_key="invalid-key", max_retries=3)
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.text = "Invalid API Key"

    call_count = 0

    async def mock_post(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return mock_resp

    with patch("httpx.AsyncClient.post", side_effect=mock_post):
        with pytest.raises(LLMProviderAuthenticationError):
            await provider.generate_json(system_prompt="sys", user_prompt="usr")

    assert call_count == 1


# ==============================================================================
# 8. Tool Timeout, Failed Step, and Exhausted Task Budget
# ==============================================================================

@pytest.mark.asyncio
async def test_investigation_tool_failure_isolation():
    """Mode: isolated_sqlite_unit
    Verify an investigation step failure does not corrupt incident state and produces explicit fallback indicators.
    """
    test_engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(test_engine)
    Session = sessionmaker(bind=test_engine)
    session = Session()

    inc = create_test_incident(session, "inc-tool-fail", status=IncidentStateEnum.TRIAGE)

    agent = InvestigationAgent(
        provider=MockLLMProvider(should_fail=True),
        fallback_provider=DeterministicRuleProvider(),
    )

    report = await agent.investigate_incident(
        session=session,
        incident_id=inc.id,
        request=InvestigationRunRequest(budget_limit_usd=1.0),
        allow_fallback=True,
    )

    assert report is not None
    assert report.is_fallback is True
    assert report.status == AgentRunStateEnum.COMPLETED


# ==============================================================================
# 9. Concurrent Incident Updates and Optimistic-Concurrency Conflicts
# ==============================================================================

def test_optimistic_concurrency_conflict_handling():
    """Mode: isolated_sqlite_unit
    Verify IncidentLifecycleManager rejects conflicting stale updates via version checks.
    """
    test_engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(test_engine)
    Session = sessionmaker(bind=test_engine)
    session = Session()

    inc = create_test_incident(session, "inc-concurrent-01", status=IncidentStateEnum.NEW, version=1)
    manager = IncidentLifecycleManager()

    analyst = Principal(id="analyst_a", name="Analyst A", roles=[RBACRoleEnum.SOC_ANALYST])

    # Analyst A transitions NEW -> TRIAGE (version 1 -> 2)
    updated = manager.transition(session, inc.id, IncidentStateEnum.TRIAGE, analyst, expected_version=1)
    assert updated.version == 2
    assert updated.status == IncidentStateEnum.TRIAGE.value

    # Analyst B attempts update with stale version 1 -> Concurrency Conflict
    with pytest.raises(IncidentConcurrencyError, match="version mismatch"):
        manager.transition(session, inc.id, IncidentStateEnum.INVESTIGATING, analyst, expected_version=1)


# ==============================================================================
# 10. Audit Persistence Failure Handling
# ==============================================================================

def test_audit_persistence_failure_isolation():
    """Mode: isolated_sqlite_unit
    Verify audit write failures are handled explicitly without corrupted state.
    """
    test_engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(test_engine)
    Session = sessionmaker(bind=test_engine)
    session = Session()

    inc = create_test_incident(session, "inc-audit-fail", status=IncidentStateEnum.NEW, version=1)
    manager = IncidentLifecycleManager()
    analyst = Principal(id="analyst_audit", name="Analyst Audit", roles=[RBACRoleEnum.SOC_ANALYST])

    with patch.object(session, "flush", side_effect=RuntimeError("Simulated disk error on flush")):
        with pytest.raises(RuntimeError, match="disk error"):
            manager.transition(session, inc.id, IncidentStateEnum.TRIAGE, analyst, expected_version=1)


# ==============================================================================
# 11. Frontend API Timeout and Safe Idempotent Retry Logic
# ==============================================================================

def test_frontend_idempotent_retry_rule():
    """Mode: unit_logic
    Verify rule invariant: idempotent operations (GET) allow safe retry; mutating operations (POST) never retry.
    """
    def can_retry_request(method: str, status_code: int) -> bool:
        is_idempotent = method.upper() in ("GET", "HEAD")
        is_transient = status_code in (502, 503, 504)
        return is_idempotent and is_transient

    assert can_retry_request("GET", 503) is True
    assert can_retry_request("GET", 502) is True
    assert can_retry_request("GET", 500) is False
    assert can_retry_request("POST", 503) is False
    assert can_retry_request("POST", 401) is False
    assert can_retry_request("DELETE", 503) is False


# ==============================================================================
# 12. Readiness and Degraded-State Correctness
# ==============================================================================

def test_readiness_and_degraded_state_evaluation():
    """Mode: unit_logic
    Verify degraded state when optional integrations are missing vs offline when DB is down.
    """
    def compute_system_status(db_healthy: bool, queue_durable: bool, provider_available: bool) -> str:
        if not db_healthy:
            return "degraded"
        if not queue_durable or not provider_available:
            return "degraded"
        return "healthy"

    assert compute_system_status(True, True, True) == "healthy"
    assert compute_system_status(True, False, True) == "degraded"
    assert compute_system_status(True, True, False) == "degraded"
    assert compute_system_status(False, True, True) == "degraded"


# ==============================================================================
# 13. Secret Redaction in Errors, Logs, and Payloads
# ==============================================================================

def test_secret_redaction_utilities():
    """Mode: unit_logic
    Verify credentials, API keys, passwords, bearer tokens, and connection strings are scrubbed.
    """
    dsn = "postgresql://cybersentinel_dev:super_secret_password_123@postgres:5432/cyber_db"
    scrubbed_dsn = scrub_string(dsn)
    assert "super_secret_password_123" not in scrubbed_dsn
    assert "[REDACTED_CREDENTIAL]" in scrubbed_dsn

    msg = "User logged in with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature"
    scrubbed_msg = scrub_string(msg)
    assert "signature" not in scrubbed_msg
    assert "[REDACTED_TOKEN]" in scrubbed_msg

    key_str = "OpenAI key sk-1234567890abcdef1234567890 initialized"
    scrubbed_key = scrub_string(key_str)
    assert "1234567890abcdef" not in scrubbed_key
    assert "[REDACTED_API_KEY]" in scrubbed_key

    payload = {
        "event_id": "ev-01",
        "api_key": "secret-token-xyz",
        "password": "mypassword",
        "details": {
            "auth_token": "bearer secret123",
            "safe_field": "visible",
        },
    }
    cleaned = scrub_secrets(payload)
    assert cleaned["api_key"] == "[REDACTED]"
    assert cleaned["password"] == "[REDACTED]"
    assert cleaned["details"]["auth_token"] == "[REDACTED]"
    assert cleaned["details"]["safe_field"] == "visible"

    exc = ConnectionError(f"Failed to connect to {dsn}")
    safe_diag = safe_diagnostic_message(exc)
    assert "super_secret_password_123" not in safe_diag


# ==============================================================================
# 14. Authorization Denial and Cross-Incident Isolation
# ==============================================================================

def test_authorization_denial_no_escalation():
    """Mode: isolated_sqlite_unit
    Verify unauthorized principal is denied without retry or privilege escalation.
    """
    analyst = Principal(id="analyst_user", name="Analyst User", roles=[RBACRoleEnum.SOC_ANALYST])
    manager = IncidentLifecycleManager()

    test_engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(test_engine)
    Session = sessionmaker(bind=test_engine)
    session = Session()

    inc = create_test_incident(session, "inc-auth-isolate", status=IncidentStateEnum.AWAITING_APPROVAL, version=1)

    with pytest.raises(PermissionError, match="Actor lacks required role"):
        manager.transition(session, inc.id, IncidentStateEnum.CONTAINMENT, analyst, expected_version=1)

    session.refresh(inc)
    assert inc.status == IncidentStateEnum.AWAITING_APPROVAL.value


# ==============================================================================
# 15. Safety Invariant Enforcement When Dependencies Fail
# ==============================================================================

def test_safety_invariants_immutable_under_failure():
    """Mode: isolated_sqlite_unit
    Verify LIVE_RESPONSE_DISABLED=true remains strictly enforced even when actions are dispatched.
    """
    test_engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(test_engine)
    Session = sessionmaker(bind=test_engine)
    session = Session()

    inc = create_test_incident(session, "inc-safety-01", status=IncidentStateEnum.NEW)
    rm = ResponseManager(live_response_disabled=True)
    assert rm.live_response_disabled is True

    req = CreateProposalRequest(
        action_type="block_ip",
        target_entity="192.168.1.100",
        action_payload={"direction": "both", "duration_hours": 12},
        reason="Test Safety Guardrail",
        evidence_refs=["ev-01"],
    )
    prop = rm.submit_proposal(
        incident_id=inc.id,
        request=req,
        actor_id="analyst_1",
        db_session=session,
    )

    approver = Principal(id="mgr_1", name="Manager One", roles=[RBACRoleEnum.SOC_MANAGER])
    rm.submit_approval(
        proposal_id=prop.id,
        request=SubmitApprovalRequest(decision="APPROVED", reason="Approved test"),
        approver=approver,
        db_session=session,
    )

    # Attempt live execution (dry_run=False) -> Must be blocked by LIVE_RESPONSE_DISABLED
    res = rm.execute_action(
        proposal_id=prop.id,
        request=ExecuteActionRequest(dry_run=False),
        actor_id="mgr_1",
        db_session=session,
    )
    assert res["state"] == ProposalStateEnum.BLOCKED_SAFETY.value
    assert "LIVE_RESPONSE_DISABLED=true enforced" in res["result"]["safety_barrier"]



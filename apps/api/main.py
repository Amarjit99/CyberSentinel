"""CyberSentinel AI — FastAPI API Application Entry Point
Phase 1 Foundation: Health, Readiness, Event Ingestion & Standardized Error Handling
"""

import json
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException

from attack import attack_catalog, attack_mapping_service
from packages.auth import Principal, require_roles, revoke_access_token, verify_access_token
from packages.ingestion_auth import source_auth_required, verify_source_signature
from packages.observability.metrics import metrics
from packages.rate_limit import RateLimitMiddleware
from schemas.api_contracts import (
    ErrorDetail,
    ErrorEnvelope,
    EventIngestRequest,
    EventIngestResponse,
    HealthResponse,
    ReadinessResponse,
)
from schemas.enums import ErrorCodeEnum, IncidentStateEnum, RBACRoleEnum
from services.agents import (
    InvestigationContinuationRequest,
    InvestigationPlan,
    InvestigationReviewRequest,
    InvestigationRunRequest,
    OrchestrationExecutionResult,
    OrchestrationPlanRequest,
    ToolAuthorizationError,
    ToolDisabledError,
    ToolExecutionLimitError,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolMetadataDTO,
    ToolNotFoundError,
    ToolValidationError,
    TriageAgent,
    default_registry,
    default_tool_executor,
    orchestrator,
)
from services.benchmark import (
    BaselineComparisonResult,
    BenchmarkDataset,
    BenchmarkExecutionModeEnum,
    BenchmarkRunResult,
    default_baseline_comparator,
    default_benchmark_runner,
    default_ground_truth_repo,
)
from services.correlation.engine import correlation_engine
from services.detection import (
    AdHocExplainRequest,
    AdHocValidateRequest,
    CandidateReviewRequest,
    CandidateRuleResponse,
    RuleExplanationResponse,
    RuleGenerationRequest,
    RuleTestRequest,
    RuleTestResult,
    RuleValidationReport,
    detection_assistant,
)
from services.detection.engine import detection_engine
from services.hunting import (
    HuntJobRequest,
    HuntJobStatus,
    hunting_service,
)
from services.incidents.lifecycle import (
    IncidentConcurrencyError,
    InvalidIncidentTransitionError,
    lifecycle_manager,
)
from services.incidents.manager import incident_manager
from services.ingestion.pipeline import pipeline
from services.ingestion.queue import durable_queue, quarantine_manager
from services.ingestion.stream_worker import StreamBatchResult, StreamIngestionWorker
from services.notifications import NotificationPayload, get_notification_dispatcher
from services.persistence.database import SessionLocal, check_database_health, get_db
from services.persistence.models import (
    AgentRun,
    AnalystNotification,
    AuditEvent,
    Detection,
    DetectionEvent,
    EventMetadata,
    Evidence,
    EvidenceRelation,
    Incident,
    IncidentDetection,
    IncidentEntity,
    IncidentNote,
    IncidentRiskAssessmentModel,
    IncidentTriageAssessmentModel,
    ResponseAction,
    ResponseProposal,
    RiskScoringPolicyModel,
    ThreatIndicator,
    ThreatSource,
)
from services.rag import (
    RAGIndexStatus,
    RAGQueryRequest,
    RAGQueryResponse,
    rag_engine,
)
from services.response import (
    ActionExecutionBlockedError,
    ApprovalViolationError,
    CreateProposalRequest,
    ExecuteActionRequest,
    PlaybookGenerator,
    ProposalExpiredError,
    ProposalNotFoundError,
    ProposalPolicyViolationError,
    ResponseManager,
    SubmitApprovalRequest,
    list_action_catalogue,
)
from services.risk import DeterministicRiskEngine
from services.risk.models import RiskScoringPolicy
from services.threat_intel import JsonFeedParser, Stix21FeedParser, ThreatIntelService

logger = logging.getLogger("cybersentinel.api")

DETECTION_STATUS_TRANSITIONS: dict[str, set[str]] = {
    "open": {"acknowledged", "assigned", "suppressed", "closed"},
    "acknowledged": {"assigned", "escalated", "suppressed", "closed", "open"},
    "assigned": {"acknowledged", "escalated", "suppressed", "closed", "open"},
    "escalated": {"assigned", "suppressed", "closed", "open"},
    "suppressed": {"open", "closed"},
    "closed": {"open"},
}


def _risk_policy_from_record(record: RiskScoringPolicyModel) -> RiskScoringPolicy:
    return RiskScoringPolicy(
        version=record.version,
        weights=record.weights_json,
        band_thresholds=record.band_thresholds_json,
        stale_intel_discount=record.stale_intel_discount,
        missing_intel_baseline=record.missing_intel_baseline,
    )


def _persist_initial_risk_policy(db: Session) -> RiskScoringPolicy:
    record = db.execute(
        select(RiskScoringPolicyModel)
        .where(RiskScoringPolicyModel.active.is_(True))
        .order_by(RiskScoringPolicyModel.created_at.desc())
    ).scalars().first()
    if record:
        return _risk_policy_from_record(record)
    policy = risk_engine.policy
    db.add(
        RiskScoringPolicyModel(
            version=policy.version,
            weights_json=policy.weights,
            band_thresholds_json=policy.band_thresholds,
            stale_intel_discount=policy.stale_intel_discount,
            missing_intel_baseline=policy.missing_intel_baseline,
            active=True,
            created_by="system:bootstrap",
            change_reason="Initial persisted risk policy",
        )
    )
    db.commit()
    return policy


class DetectionLifecycleRequest(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = Field(default=None, max_length=128)
    analyst_notes: Optional[str] = Field(default=None, max_length=4000)
    reason: Optional[str] = Field(default=None, max_length=512)


class ThreatSourceUpdateRequest(BaseModel):
    reliability: Optional[str] = Field(default=None, pattern="^(A|B|C|unknown)$")
    description: Optional[str] = Field(default=None, max_length=255)
    endpoint_url: Optional[str] = Field(default=None, max_length=512)
    enabled: Optional[bool] = None
    polling_interval_minutes: Optional[int] = Field(default=None, ge=5, le=10080)


class RiskPolicyUpdateRequest(RiskScoringPolicy):
    change_reason: str = Field(..., min_length=1, max_length=512)


response_manager = ResponseManager(live_response_disabled=True)
playbook_generator = PlaybookGenerator()
risk_engine = DeterministicRiskEngine(attack_mapping_service=attack_mapping_service)
triage_agent = TriageAgent(
    attack_mapping_service=attack_mapping_service,
    risk_engine=risk_engine,
)
stream_worker = StreamIngestionWorker(
    ingest_pipeline=pipeline,
    detection_engine=detection_engine,
    correlation_engine=correlation_engine,
)



@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager for startup and shutdown hooks."""
    from pathlib import Path

    from services.persistence.database import init_db

    init_db()
    with SessionLocal() as db:
        risk_engine.policy = _persist_initial_risk_policy(db)

    sigma_dir = Path("rules/sigma")
    if sigma_dir.exists():
        detection_engine.load_rules_from_directory(str(sigma_dir))

    corr_dir = Path("rules/correlation")
    if corr_dir.exists():
        correlation_engine.load_rules_from_directory(str(corr_dir))

    yield


app = FastAPI(
    title="CyberSentinel AI Platform API",
    description="Agentic Security Operations & Threat Investigation Platform API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


@app.post("/api/v1/auth/revoke", tags=["Authentication"], summary="Revoke Current Access Token")
async def revoke_current_access_token(authorization: Optional[str] = Header(default=None)):
    """Revoke the caller's signed bearer token until its expiration."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide a valid bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization[7:].strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Empty bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    verify_access_token(token)
    revoke_access_token(token)
    return {"revoked": True}

# CORS middleware (restrictive local default)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:3000", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitMiddleware)


@app.middleware("http")
async def add_correlation_id_and_timer(request: Request, call_next):
    """Assigns or preserves X-Request-ID and measures request latency."""
    request_id = request.headers.get("X-Request-ID", str(uuid4()))
    request.state.request_id = request_id
    start_time = time.perf_counter()

    try:
        response = await call_next(request)
    except Exception:
        metrics.inc_counter("http_requests_total")
        metrics.inc_counter("http_server_errors_total")
        logger.exception(
            "HTTP request failed",
            extra={
                "correlation_id": request_id,
                "http_method": request.method,
                "http_path": request.url.path,
            },
        )
        raise

    process_time = time.perf_counter() - start_time
    metrics.inc_counter("http_requests_total")
    metrics.inc_counter(f"http_responses_{response.status_code}_total")
    metrics.record_latency(process_time)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Response-Time-Sec"] = f"{process_time:.4f}"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    logger.info(
        "HTTP request completed",
        extra={
            "correlation_id": request_id,
            "http_method": request.method,
            "http_path": request.url.path,
            "http_status": response.status_code,
            "duration_ms": round(process_time * 1000, 3),
        },
    )
    return response


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Converts validation errors into the standardized ErrorEnvelope without leaking internals."""
    request_id = getattr(request.state, "request_id", str(uuid4()))
    details = []
    for err in exc.errors():
        loc = " -> ".join(str(item) for item in err.get("loc", []))
        msg = err.get("msg", "Validation error")
        details.append(ErrorDetail(field=loc, issue=msg))

    envelope = ErrorEnvelope(
        error_code=ErrorCodeEnum.VALIDATION_ERROR,
        message="Request payload failed validation schema constraints.",
        request_id=request_id,
        timestamp=datetime.now(timezone.utc),
        details=details,
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=envelope.model_dump(mode="json"),
        headers={"X-Request-ID": request_id},
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    # Unwrap any underlying 413 HTTPException from streaming TaskGroup
    if exc.status_code == 400 and exc.__cause__:
        cause = exc.__cause__
        sub_exc = None
        if hasattr(cause, "exceptions"):
            for sub in getattr(cause, "exceptions", []):
                if isinstance(sub, StarletteHTTPException):
                    sub_exc = sub
                    break
        elif isinstance(cause, StarletteHTTPException):
            sub_exc = cause
        if sub_exc and sub_exc.status_code == 413:
            exc = sub_exc

    request_id = getattr(request.state, "request_id", str(uuid4()))
    if exc.status_code in (400, 413):
        error_code = ErrorCodeEnum.INVALID_SCHEMA
    elif exc.status_code == 429:
        error_code = ErrorCodeEnum.RATE_LIMIT_EXCEEDED
    else:
        error_code = ErrorCodeEnum.INTERNAL_ERROR

    envelope = ErrorEnvelope(
        error_code=error_code,
        message=str(exc.detail),
        request_id=request_id,
        timestamp=datetime.now(timezone.utc),
    )
    headers = {"X-Request-ID": request_id}
    if exc.headers:
        headers.update(exc.headers)
    return JSONResponse(
        status_code=exc.status_code,
        content=envelope.model_dump(mode="json"),
        headers=headers,
    )


@app.get("/health", response_model=HealthResponse, tags=["Observability"])
async def health_check():
    """Liveness & health probe returning truthful degraded states for dependencies."""
    is_healthy, _db_msg, _latency = check_database_health(timeout_seconds=2.0)
    db_state = "connected" if is_healthy else "unreachable"

    queue_health = durable_queue.check_health()
    queue_mode = queue_health.get("storage_mode", "in_memory_volatile_fallback")

    provider_info = triage_agent.provider.check_availability()
    provider_state = "available" if provider_info.is_available else "degraded"

    # Truthful status:
    # - If required dependency (database) is unreachable: degraded
    # - If optional integrations (Redis Streams queue, external LLM) are not fully active: degraded
    # - If all dependencies verified active: healthy
    if db_state != "connected":
        overall_status = "degraded"
    elif not queue_health.get("is_durable", False) or not provider_info.is_available:
        overall_status = "degraded"
    else:
        overall_status = "healthy"

    return HealthResponse(
        status=overall_status,
        timestamp=datetime.now(timezone.utc),
        version="1.0.0",
        checks={
            "database": db_state,
            "ingestion": "active",
            "queue": queue_mode,
            "ai_provider": provider_state,
        },
    )


@app.get("/ready", response_model=ReadinessResponse, tags=["Observability"])
async def readiness_check(response: Response):
    """Readiness probe indicating if service is prepared to ingest traffic and serve requests."""
    is_healthy, _db_msg, _latency = check_database_health(timeout_seconds=2.0)
    db_ready = is_healthy

    queue_health = durable_queue.check_health()
    queue_durable = queue_health.get("is_durable", False)

    provider_info = triage_agent.provider.check_availability()

    is_ready = db_ready
    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return ReadinessResponse(
        ready=is_ready,
        timestamp=datetime.now(timezone.utc),
        dependencies={
            "database": db_ready,
            "queue_durable": queue_durable,
            "ai_provider": provider_info.is_available,
        },
    )


@app.post(
    "/api/v1/events",
    response_model=EventIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["Telemetry Ingestion"],
)
async def ingest_events(
    request: Request,
    payload: EventIngestRequest,
    x_request_id: str | None = Header(default=None),
    x_source_id: str | None = Header(default=None),
    x_source_timestamp: str | None = Header(default=None),
    x_source_signature: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    """Deterministic telemetry event ingestion endpoint (TEST-FR-001, TEST-FR-003).
    Validates batch canonical events, assigns correlation ID, deduplicates, and enqueues.
    """
    if source_auth_required():
        body = await request.body()
        if not verify_source_signature(
            body,
            x_source_id,
            x_source_timestamp,
            x_source_signature,
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authenticated source signature required.",
            )
        if x_source_id != payload.client_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Source identity does not match client_id.",
            )

    correlation_id = x_request_id or str(uuid4())
    accepted_ids = []
    quarantined_count = 0

    for event in payload.events:
        res = pipeline.ingest_event(
            record=event.model_dump(mode="json"),
            connector_id=payload.client_id or "direct-api",
            db_session=db,
        )
        if res.status in ("ingested", "duplicate"):
            accepted_ids.append(event.event_id)
        else:
            quarantined_count += 1

    return EventIngestResponse(
        accepted_count=len(accepted_ids),
        quarantined_count=quarantined_count,
        event_ids=accepted_ids,
        correlation_id=correlation_id,
        timestamp=datetime.now(timezone.utc),
    )


class StreamIngestRequest(BaseModel):
    client_id: Optional[str] = "stream-client"
    auto_correlate: bool = True
    events: list[dict[str, Any]]


@app.post(
    "/api/v1/ingest/stream",
    response_model=StreamBatchResult,
    tags=["Telemetry Ingestion"],
    summary="Real-Time Streaming Telemetry Ingestion & Evaluation",
)
async def ingest_stream(
    payload: StreamIngestRequest,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Ingest a streaming batch of raw telemetry events with real-time detection and correlation."""
    return stream_worker.process_stream_batch(
        raw_events=payload.events,
        connector_id=payload.client_id or "stream-api",
        db_session=db,
        auto_correlate=payload.auto_correlate,
    )


@app.get(
    "/api/v1/events/quarantine",
    tags=["Telemetry Ingestion"],
    summary="List Quarantined Events",
)
async def list_quarantine_events(
    limit: int = 50,
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.ADMIN,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.SOC_MANAGER,
            ]
        )
    ),
):
    """Protected operator endpoint to view malformed or unprocessable telemetry."""
    records = quarantine_manager.get_quarantine_records(limit=min(limit, 200))
    return {
        "count": len(records),
        "records": records,
        "operator_id": operator.id,
    }


class EvidenceCreateRequest(BaseModel):
    evidence_type: str = Field(..., min_length=1, max_length=64)
    source_ref: str = Field(..., min_length=1, max_length=255)
    checksum: str = Field(..., min_length=1, max_length=64)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    classification: str = Field(default="internal", min_length=1, max_length=32)
    conflict_group: Optional[str] = Field(default=None, min_length=1, max_length=64)
    conflict_status: str = Field(default="unreviewed", min_length=1, max_length=32)
    related_evidence_ids: list[str] = Field(default_factory=list, max_length=20)
    relation_type: str = Field(default="supports", min_length=1, max_length=64)
    collected_at: Optional[datetime] = None


@app.post(
    "/api/v1/incidents/{incident_id}/evidence",
    status_code=status.HTTP_201_CREATED,
    tags=["Evidence"],
    summary="Collect Immutable Evidence Reference",
)
async def create_incident_evidence(
    incident_id: str,
    payload: EvidenceCreateRequest,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Append an evidence reference; evidence has no mutation or deletion API."""
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    evidence = Evidence(
        incident_id=incident_id,
        evidence_type=payload.evidence_type,
        source_ref=payload.source_ref,
        checksum=payload.checksum,
        provenance_json=payload.provenance,
        classification=payload.classification,
        conflict_group=payload.conflict_group,
        conflict_status=payload.conflict_status,
        collected_at=payload.collected_at or datetime.now(timezone.utc),
        created_by=operator.id,
    )
    db.add(evidence)
    db.flush()
    if payload.related_evidence_ids:
        related = db.execute(
            select(Evidence).where(
                Evidence.incident_id == incident_id,
                Evidence.id.in_(payload.related_evidence_ids),
            )
        ).scalars().all()
        related_by_id = {item.id: item for item in related}
        missing_ids = sorted(set(payload.related_evidence_ids) - set(related_by_id))
        if missing_ids:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Related evidence must belong to the same incident",
            )
        for related_id in dict.fromkeys(payload.related_evidence_ids):
            db.add(
                EvidenceRelation(
                    incident_id=incident_id,
                    from_evidence_id=evidence.id,
                    to_evidence_id=related_id,
                    relation_type=payload.relation_type,
                    created_by=operator.id,
                )
            )
    db.add(
        AuditEvent(
            id=str(uuid4()),
            actor_type="user",
            actor_id=operator.id,
            action="evidence:collect",
            object_type="evidence",
            object_id=evidence.id,
            outcome="success",
            occurred_at=datetime.now(timezone.utc),
            metadata_redacted={
                "incident_id": incident_id,
                "evidence_type": payload.evidence_type,
                "classification": payload.classification,
            },
        )
    )
    db.commit()
    db.refresh(evidence)
    return {
        "id": evidence.id,
        "incident_id": evidence.incident_id,
        "evidence_type": evidence.evidence_type,
        "source_ref": evidence.source_ref,
        "checksum": evidence.checksum,
        "provenance": evidence.provenance_json,
        "classification": evidence.classification,
        "conflict_group": evidence.conflict_group,
        "conflict_status": evidence.conflict_status,
        "relationships": [
            {
                "id": relation.id,
                "evidence_id": relation.to_evidence_id,
                "relation_type": relation.relation_type,
            }
            for relation in evidence.outgoing_relations
        ],
        "collected_at": evidence.collected_at.isoformat(),
        "created_by": evidence.created_by,
        "immutable": True,
    }


@app.get(
    "/api/v1/incidents/{incident_id}/evidence/completeness",
    tags=["Evidence"],
    summary="Get Evidence Completeness",
)
async def get_evidence_completeness(
    incident_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.VIEWER,
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Summarize evidence coverage without exposing raw evidence contents."""
    if not db.get(Incident, incident_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    evidence_items = db.execute(
        select(Evidence).where(Evidence.incident_id == incident_id)
    ).scalars().all()
    relation_count = len(
        db.execute(
            select(EvidenceRelation).where(EvidenceRelation.incident_id == incident_id)
        ).scalars().all()
    )
    conflict_items = [
        item
        for item in evidence_items
        if item.conflict_group is not None
        and item.conflict_status in {"open", "unreviewed"}
    ]
    return {
        "incident_id": incident_id,
        "status": "complete" if evidence_items else "unknown",
        "evidence_count": len(evidence_items),
        "relationship_count": relation_count,
        "open_conflict_count": len(conflict_items),
        "missing_evidence": not evidence_items,
        "operator_id": operator.id,
    }


@app.get(
    "/api/v1/evidence/{evidence_id}",
    tags=["Evidence"],
    summary="Get Evidence Reference",
)
async def get_evidence(
    evidence_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.VIEWER,
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve metadata and provenance without exposing raw evidence contents."""
    evidence = db.get(Evidence, evidence_id)
    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")
    return {
        "id": evidence.id,
        "incident_id": evidence.incident_id,
        "evidence_type": evidence.evidence_type,
        "source_ref": evidence.source_ref,
        "checksum": evidence.checksum,
        "provenance": evidence.provenance_json,
        "classification": evidence.classification,
        "conflict_group": evidence.conflict_group,
        "conflict_status": evidence.conflict_status,
        "relationships": [
            {
                "id": relation.id,
                "evidence_id": relation.to_evidence_id,
                "relation_type": relation.relation_type,
            }
            for relation in evidence.outgoing_relations
        ],
        "collected_at": evidence.collected_at.isoformat(),
        "created_by": evidence.created_by,
        "immutable": True,
    }


@app.post(
    "/api/v1/events/quarantine/{quarantine_id}/replay",
    tags=["Telemetry Ingestion"],
    summary="Replay Quarantined Event",
)
async def replay_quarantined_event(
    quarantine_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.ADMIN,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.SOC_MANAGER,
            ]
        )
    ),
):
    """Protected operator endpoint to re-inject a quarantined event back into the pipeline."""
    result = pipeline.replay_quarantined_event(quarantine_id, db_session=db)
    outcome = "success" if result.status == "ingested" else "failed"

    # Audit logging of operator replay action (Requirement 2.F)
    try:
        audit_record = AuditEvent(
            id=str(uuid4()),
            actor_type="user",
            actor_id=operator.id,
            action="quarantine:replay",
            object_type="quarantine_record",
            object_id=quarantine_id,
            outcome=outcome,
            occurred_at=datetime.now(timezone.utc),
            metadata_redacted={
                "status": result.status,
                "raw_hash": result.raw_hash,
                "error": result.error,
            },
        )
        db.add(audit_record)
        db.commit()
    except Exception:
        db.rollback()

    if result.status == "error":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=result.error or "Quarantine record not found or max replays exceeded",
        )
    return {
        "status": result.status,
        "event_id": result.event_id,
        "raw_hash": result.raw_hash,
        "operator_id": operator.id,
    }


@app.get(
    "/api/v1/events/metrics",
    tags=["Observability"],
    summary="Ingestion Pipeline Metrics",
)
async def get_ingestion_metrics():
    """Retrieve operational telemetry metrics for log ingestion."""
    snapshot = metrics.snapshot()
    snapshot.update(
        {
            "queue_depth": float(durable_queue.qsize()),
            "queue_storage_mode": durable_queue.storage_mode,
            "quarantine_depth": float(len(quarantine_manager.get_quarantine_records(limit=5000))),
            "dead_letter_depth": float(len(quarantine_manager.get_dlq_records(limit=5000))),
        }
    )
    return snapshot


@app.get(
    "/api/v1/events/search",
    tags=["Event Exploration"],
    summary="Search Canonical Event Metadata",
)
async def search_events(
    q: Optional[str] = Query(None, min_length=1, max_length=128),
    source_id: Optional[str] = Query(None, max_length=64),
    event_type: Optional[str] = Query(None, max_length=128),
    hostname: Optional[str] = Query(None, max_length=255),
    username: Optional[str] = Query(None, max_length=255),
    src_ip: Optional[str] = Query(None, max_length=64),
    dst_ip: Optional[str] = Query(None, max_length=64),
    severity: Optional[str] = Query(None, max_length=32),
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0, le=10000),
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Search bounded, redacted event metadata with indexed canonical filters."""
    if start_time and end_time and start_time > end_time:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="start_time must be earlier than or equal to end_time",
        )
    if q and len(q.strip()) < 2:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="q must contain at least two non-whitespace characters",
        )

    query = select(EventMetadata)
    if source_id:
        query = query.where(EventMetadata.source_id == source_id)
    if event_type:
        query = query.where(EventMetadata.event_type == event_type)
    if hostname:
        query = query.where(EventMetadata.hostname == hostname)
    if username:
        query = query.where(EventMetadata.username == username)
    if src_ip:
        query = query.where(EventMetadata.src_ip == src_ip)
    if dst_ip:
        query = query.where(EventMetadata.dst_ip == dst_ip)
    if severity:
        query = query.where(EventMetadata.severity == severity.lower())
    if start_time:
        query = query.where(EventMetadata.event_time >= start_time)
    if end_time:
        query = query.where(EventMetadata.event_time <= end_time)
    if q:
        term = f"%{q.strip()}%"
        query = query.where(
            EventMetadata.id.like(term)
            | EventMetadata.source_id.like(term)
            | EventMetadata.event_type.like(term)
            | EventMetadata.hostname.like(term)
            | EventMetadata.username.like(term)
            | EventMetadata.src_ip.like(term)
            | EventMetadata.dst_ip.like(term)
        )

    events = db.execute(
        query.order_by(EventMetadata.event_time.desc()).offset(offset).limit(limit)
    ).scalars().all()
    audit = AuditEvent(
        id=str(uuid4()),
        actor_type="user",
        actor_id=operator.id,
        action="events:search",
        object_type="event_metadata",
        object_id="search",
        outcome="success",
        occurred_at=datetime.now(timezone.utc),
        metadata_redacted={
            "filter_names": sorted(
                key for key, value in {
                    "q": q,
                    "source_id": source_id,
                    "event_type": event_type,
                    "hostname": hostname,
                    "username": username,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "severity": severity,
                    "start_time": start_time.isoformat() if start_time else None,
                    "end_time": end_time.isoformat() if end_time else None,
                }.items()
                if value is not None
            ),
            "limit": limit,
            "offset": offset,
            "result_count": len(events),
        },
    )
    db.add(audit)
    db.commit()
    return {
        "count": len(events),
        "limit": limit,
        "offset": offset,
        "filters_applied": {
            "source_id": source_id,
            "event_type": event_type,
            "hostname": hostname,
            "username": username,
            "severity": severity.lower() if severity else None,
            "start_time": start_time.isoformat() if start_time else None,
            "end_time": end_time.isoformat() if end_time else None,
        },
        "events": [
            {
                "event_id": event.id,
                "event_time": event.event_time.isoformat(),
                "received_at": event.received_at.isoformat(),
                "source_id": event.source_id,
                "event_type": event.event_type,
                "hostname": event.hostname,
                "username": event.username,
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "severity": event.severity,
                "schema_version": event.schema_version,
                "raw_ref": event.raw_ref,
                "checksum": event.checksum,
                "classification": event.classification,
            }
            for event in events
        ],
    }


@app.get(
    "/api/v1/events/export",
    tags=["Event Exploration"],
    summary="Export Canonical Event Metadata (CSV or JSONL)",
)
async def export_events(
    format: str = Query("jsonl", pattern="^(jsonl|csv)$"),
    source_id: Optional[str] = Query(None, max_length=64),
    event_type: Optional[str] = Query(None, max_length=128),
    hostname: Optional[str] = Query(None, max_length=255),
    severity: Optional[str] = Query(None, max_length=32),
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None),
    limit: int = Query(500, ge=1, le=500),
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Export filtered events as downloadable JSONL or CSV file."""
    query = select(EventMetadata)
    if source_id:
        query = query.where(EventMetadata.source_id == source_id)
    if event_type:
        query = query.where(EventMetadata.event_type == event_type)
    if hostname:
        query = query.where(EventMetadata.hostname == hostname)
    if severity:
        query = query.where(EventMetadata.severity == severity.lower())
    if start_time:
        query = query.where(EventMetadata.event_time >= start_time)
    if end_time:
        query = query.where(EventMetadata.event_time <= end_time)

    records = db.execute(query.order_by(EventMetadata.event_time.desc()).limit(limit)).scalars().all()

    if format == "csv":
        import csv
        import io
        from fastapi.responses import Response

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["id", "event_time", "source_id", "event_type", "hostname", "username", "severity", "src_ip", "dst_ip"])
        for r in records:
            writer.writerow([r.id, r.event_time.isoformat() if r.event_time else "", r.source_id, r.event_type, r.hostname, r.username, r.severity, r.src_ip, r.dst_ip])
        return Response(content=output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=events_export.csv"})

    from fastapi.responses import Response
    lines = [json.dumps({"id": r.id, "event_time": r.event_time.isoformat() if r.event_time else "", "source_id": r.source_id, "event_type": r.event_type, "hostname": r.hostname, "username": r.username, "severity": r.severity, "src_ip": r.src_ip, "dst_ip": r.dst_ip}) for r in records]
    return Response(content="\n".join(lines), media_type="application/x-ndjson", headers={"Content-Disposition": "attachment; filename=events_export.jsonl"})


class WebhookTestRequest(BaseModel):
    channel: str = Field(default="generic_webhook", description="generic_webhook, slack, pagerduty")
    title: str = Field(default="Test Alert Notification")
    message: str = Field(default="CyberSentinel AI test notification dispatch.")
    severity: str = Field(default="medium")


@app.post(
    "/api/v1/notifications/webhook/test",
    tags=["Observability"],
    summary="Test Outbound Webhook Dispatch",
)
async def test_webhook_dispatch(
    body: WebhookTestRequest,
    operator: Principal = Depends(
        require_roles([RBACRoleEnum.ADMIN, RBACRoleEnum.SECURITY_ENGINEER])
    ),
):
    """Test outbound webhook connectivity and payload formatting."""
    dispatcher = get_notification_dispatcher()
    payload = NotificationPayload(
        event_type="test_notification",
        title=body.title,
        message=body.message,
        severity=body.severity,
        metadata={"dispatched_by": operator.id},
    )
    records = await dispatcher.dispatch(payload)
    return {
        "status": "dispatched",
        "deliveries": [r.model_dump() for r in records],
        "configured_channels": {
            "generic_webhook": bool(dispatcher.webhook_url),
            "slack": bool(dispatcher.slack_webhook_url),
            "pagerduty": bool(dispatcher.pagerduty_routing_key),
        },
    }


@app.get(
    "/api/v1/rules",
    tags=["Detection Engineering"],
    summary="List Active Sigma Detection Rules",
)
async def list_active_rules(
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve all active compiled Sigma detection rules."""
    rules = detection_engine.get_active_rules()
    return {
        "count": len(rules),
        "rules": [
            {
                "id": r.id,
                "title": r.title,
                "status": r.status,
                "severity": r.severity.value,
                "tags": r.tags,
                "mitre_attack_ids": r.mitre_attack_ids,
                "content_hash": r.content_hash,
            }
            for r in rules
        ],
    }


@app.post(
    "/api/v1/rules/reload",
    tags=["Detection Engineering"],
    summary="Reload Sigma Rules from Disk",
)
async def reload_rules(
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.ADMIN,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SECURITY_ENGINEER,
            ]
        )
    ),
):
    """Privileged operator endpoint to reload and recompile Sigma detection rules."""
    count = detection_engine.load_rules_from_directory("rules/sigma")
    try:
        audit = AuditEvent(
            id=str(uuid4()),
            actor_type="user",
            actor_id=operator.id,
            action="rules:reload",
            object_type="rule_registry",
            object_id="rules/sigma",
            outcome="success",
            occurred_at=datetime.now(timezone.utc),
            metadata_redacted={"reloaded_count": count},
        )
        db.add(audit)
        db.commit()
    except Exception:
        db.rollback()

    return {"status": "reloaded", "active_rule_count": count}


@app.get(
    "/api/v1/detections",
    tags=["Detection Engineering"],
    summary="List Detections",
)
async def list_detections(
    severity: Optional[str] = None,
    rule_id: Optional[str] = None,
    status_filter: Optional[str] = Query(default=None, alias="status"),
    assigned_to: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Query persisted detection alerts with filtering and pagination."""
    query = select(Detection)
    if severity:
        query = query.where(Detection.severity == severity.lower())
    if rule_id:
        query = query.where(Detection.rule_id == rule_id)
    if status_filter:
        query = query.where(Detection.status == status_filter.lower())
    if assigned_to:
        query = query.where(Detection.assigned_to == assigned_to)
    query = query.order_by(Detection.created_at.desc()).offset(offset).limit(min(limit, 100))
    detections = db.execute(query).scalars().all()

    return {
        "count": len(detections),
        "detections": [
            {
                "id": d.id,
                "rule_id": d.rule_id,
                "rule_version": d.rule_version,
                "severity": d.severity,
                "status": d.status,
                "assigned_to": d.assigned_to,
                "analyst_notes": d.analyst_notes,
                "first_seen": d.first_seen.isoformat(),
                "last_seen": d.last_seen.isoformat(),
                "created_at": d.created_at.isoformat(),
            }
            for d in detections
        ],
    }


@app.get(
    "/api/v1/detections/{detection_id}",
    tags=["Detection Engineering"],
    summary="Get Detection Details",
)
async def get_detection(
    detection_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve detailed detection alert record including matched event associations."""
    detection = db.get(Detection, detection_id)
    if not detection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection '{detection_id}' not found",
        )

    events_query = select(DetectionEvent).where(DetectionEvent.detection_id == detection_id)
    det_events = db.execute(events_query).scalars().all()

    return {
        "id": detection.id,
        "rule_id": detection.rule_id,
        "rule_version": detection.rule_version,
        "severity": detection.severity,
        "status": detection.status,
        "assigned_to": detection.assigned_to,
        "analyst_notes": detection.analyst_notes,
        "status_reason": detection.status_reason,
        "status_updated_at": detection.status_updated_at.isoformat()
        if detection.status_updated_at
        else None,
        "status_updated_by": detection.status_updated_by,
        "first_seen": detection.first_seen.isoformat(),
        "last_seen": detection.last_seen.isoformat(),
        "created_at": detection.created_at.isoformat(),
        "matched_events": [
            {"event_id": de.event_id, "relation_type": de.relation_type}
            for de in det_events
        ],
    }


@app.patch(
    "/api/v1/detections/{detection_id}/lifecycle",
    tags=["Detection Engineering"],
    summary="Update Detection Alert Lifecycle",
)
async def update_detection_lifecycle(
    detection_id: str,
    request: DetectionLifecycleRequest,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Apply an audited, explicitly allowed alert transition or assignment update."""
    detection = db.get(Detection, detection_id)
    if not detection:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Detection not found")

    next_status = request.status.lower().strip() if request.status else detection.status
    previous_status = detection.status
    if next_status not in DETECTION_STATUS_TRANSITIONS:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid detection status")
    if next_status != detection.status and next_status not in DETECTION_STATUS_TRANSITIONS.get(
        detection.status, set()
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Invalid detection transition: {detection.status} -> {next_status}",
        )
    if request.status is None and request.assigned_to is None and request.analyst_notes is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="At least one lifecycle field is required",
        )

    changed = {
        "status": {"from": detection.status, "to": next_status},
        "assigned_to": {"from": detection.assigned_to, "to": request.assigned_to}
        if request.assigned_to is not None
        else None,
        "analyst_notes_updated": request.analyst_notes is not None,
        "reason": request.reason,
    }
    if request.status is not None:
        detection.status = next_status
    if request.assigned_to is not None:
        detection.assigned_to = request.assigned_to.strip() or None
    if request.analyst_notes is not None:
        detection.analyst_notes = request.analyst_notes
    if request.status is not None:
        detection.status_reason = request.reason
        detection.status_updated_at = datetime.now(timezone.utc)
        detection.status_updated_by = operator.id

    if request.assigned_to is not None and detection.assigned_to:
        db.add(
            AnalystNotification(
                recipient_id=detection.assigned_to,
                notification_type="alert_assignment",
                title="Alert assigned to you",
                message=f"Detection {detection.id} was assigned to you by {operator.id}.",
                detection_id=detection.id,
            )
        )
        try:
            get_notification_dispatcher().dispatch_sync(
                NotificationPayload(
                    event_type="alert_assignment",
                    title="Alert assigned",
                    message=f"Detection {detection.id} assigned to {detection.assigned_to} by {operator.id}",
                    severity=detection.severity or "medium",
                    detection_id=detection.id,
                    recipient_id=detection.assigned_to,
                )
            )
        except Exception:
            pass

    if request.status is not None and detection.assigned_to and next_status != previous_status:
        db.add(
            AnalystNotification(
                recipient_id=detection.assigned_to,
                notification_type="alert_status",
                title="Assigned alert status changed",
                message=f"Detection {detection.id} moved to {next_status}.",
                detection_id=detection.id,
            )
        )
        try:
            get_notification_dispatcher().dispatch_sync(
                NotificationPayload(
                    event_type="alert_status",
                    title="Assigned alert status changed",
                    message=f"Detection {detection.id} moved to {next_status} by {operator.id}",
                    severity=detection.severity or "medium",
                    detection_id=detection.id,
                    recipient_id=detection.assigned_to,
                )
            )
        except Exception:
            pass

    db.add(
        AuditEvent(
            id=str(uuid4()),
            actor_type="user",
            actor_id=operator.id,
            action="detection:lifecycle_update",
            object_type="detection",
            object_id=detection_id,
            outcome="success",
            occurred_at=datetime.now(timezone.utc),
            metadata_redacted=changed,
        )
    )
    db.commit()
    db.refresh(detection)
    return {
        "id": detection.id,
        "status": detection.status,
        "assigned_to": detection.assigned_to,
        "analyst_notes": detection.analyst_notes,
        "status_reason": detection.status_reason,
        "status_updated_at": detection.status_updated_at.isoformat()
        if detection.status_updated_at
        else None,
        "status_updated_by": detection.status_updated_by,
    }


@app.get(
    "/api/v1/notifications",
    tags=["Alert Management"],
    summary="List Analyst Notifications",
)
async def list_notifications(
    unread_only: bool = Query(False),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    query = select(AnalystNotification).where(
        AnalystNotification.recipient_id == operator.id
    )
    if unread_only:
        query = query.where(AnalystNotification.read.is_(False))
    notifications = db.execute(
        query.order_by(AnalystNotification.created_at.desc()).limit(limit)
    ).scalars().all()
    unread_count = db.execute(
        select(AnalystNotification.id)
        .where(
            AnalystNotification.recipient_id == operator.id,
            AnalystNotification.read.is_(False),
        )
    ).scalars().all()
    return {
        "count": len(notifications),
        "unread_count": len(unread_count),
        "notifications": [
            {
                "id": notification.id,
                "type": notification.notification_type,
                "title": notification.title,
                "message": notification.message,
                "detection_id": notification.detection_id,
                "read": notification.read,
                "created_at": notification.created_at.isoformat(),
            }
            for notification in notifications
        ],
    }


@app.patch(
    "/api/v1/notifications/{notification_id}/read",
    tags=["Alert Management"],
    summary="Mark Analyst Notification Read",
)
async def mark_notification_read(
    notification_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    notification = db.execute(
        select(AnalystNotification).where(
            AnalystNotification.id == notification_id,
            AnalystNotification.recipient_id == operator.id,
        )
    ).scalar_one_or_none()
    if notification is None:
        raise HTTPException(status_code=404, detail="Notification not found")
    notification.read = True
    db.commit()
    return {"id": notification.id, "read": notification.read}


# ==============================================================================
# Phase 4 Correlation & Incident Case Management Endpoints
# ==============================================================================


class IncidentTransitionRequest(BaseModel):
    to_state: IncidentStateEnum
    reason: Optional[str] = None
    version: int = Field(..., description="Expected current version for optimistic concurrency control")


class IncidentNoteRequest(BaseModel):
    note: str = Field(..., min_length=1, max_length=5000)


class IncidentMergeRequest(BaseModel):
    target_incident_id: str = Field(..., min_length=1, max_length=64)
    source_version: int = Field(..., ge=1)
    target_version: int = Field(..., ge=1)
    reason: str = Field(..., min_length=1, max_length=1000)


class IncidentSplitRequest(BaseModel):
    detection_ids: List[str] = Field(..., min_length=1, max_length=100)
    evidence_ids: List[str] = Field(default_factory=list, max_length=100)
    source_version: int = Field(..., ge=1)
    title: str = Field(..., min_length=1, max_length=255)
    reason: str = Field(..., min_length=1, max_length=1000)


@app.get(
    "/api/v1/correlation/rules",
    tags=["Correlation Engine"],
    summary="List Loaded Correlation Rules",
)
async def list_correlation_rules(
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve all loaded stateful correlation rules."""
    rules = correlation_engine.list_rules()
    return {
        "rules_count": len(rules),
        "rules": [
            {
                "id": str(r.id),
                "name": r.name,
                "description": r.description,
                "severity": r.severity.value,
                "group_by": r.group_by,
                "window_seconds": r.window_seconds,
                "threshold": r.threshold,
                "is_sequence": r.sequence is not None,
                "enabled": r.enabled,
                "tags": r.tags or [],
            }
            for r in rules
        ],
    }


@app.post(
    "/api/v1/correlation/rules/reload",
    tags=["Correlation Engine"],
    summary="Hot-Reload Correlation Rules",
)
async def reload_correlation_rules(
    operator: Principal = Depends(
        require_roles([RBACRoleEnum.DETECTION_ENGINEER, RBACRoleEnum.ADMIN])
    ),
):
    """Hot-reload all correlation rules from the rules/correlation directory."""
    from pathlib import Path

    corr_dir = Path("rules/correlation")
    if not corr_dir.exists():
        return {"status": "skipped", "reason": "rules/correlation directory not found"}

    reloaded_count = correlation_engine.load_rules_from_directory(str(corr_dir))
    return {
        "status": "success",
        "rules_reloaded": reloaded_count,
        "active_rules": len(correlation_engine.list_rules()),
    }


@app.get(
    "/api/v1/incidents",
    tags=["Incident Management"],
    summary="List Security Incidents",
)
async def list_incidents(
    status_filter: Optional[str] = Query(None, alias="status"),
    severity_filter: Optional[str] = Query(None, alias="severity"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """List security incidents with filtering by status, severity, and pagination."""
    query = select(Incident)
    if status_filter:
        query = query.where(Incident.status == status_filter.upper())
    if severity_filter:
        query = query.where(Incident.severity == severity_filter.upper())

    query = query.order_by(Incident.created_at.desc()).limit(limit).offset(offset)
    incidents = db.execute(query).scalars().all()

    return {
        "count": len(incidents),
        "limit": limit,
        "offset": offset,
        "incidents": [
            {
                "id": inc.id,
                "title": inc.title,
                "severity": inc.severity,
                "status": inc.status,
                "owner_id": inc.owner_id,
                "first_seen": inc.first_seen.isoformat(),
                "last_seen": inc.last_seen.isoformat(),
                "version": inc.version,
                "created_at": inc.created_at.isoformat(),
                "updated_at": inc.updated_at.isoformat(),
            }
            for inc in incidents
        ],
    }


@app.get(
    "/api/v1/incidents/{incident_id}",
    tags=["Incident Management"],
    summary="Get Incident Details",
)
async def get_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve full incident details including associated detections, entities, and evidence."""
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    # Detections
    det_links = db.execute(
        select(IncidentDetection).where(IncidentDetection.incident_id == incident_id)
    ).scalars().all()

    # Entities
    ent_links = db.execute(
        select(IncidentEntity).where(IncidentEntity.incident_id == incident_id)
    ).scalars().all()

    # Evidence
    evidences = db.execute(
        select(Evidence).where(Evidence.incident_id == incident_id)
    ).scalars().all()

    return {
        "id": inc.id,
        "title": inc.title,
        "severity": inc.severity,
        "status": inc.status,
        "owner_id": inc.owner_id,
        "confidence": inc.confidence,
        "first_seen": inc.first_seen.isoformat(),
        "last_seen": inc.last_seen.isoformat(),
        "version": inc.version,
        "created_at": inc.created_at.isoformat(),
        "updated_at": inc.updated_at.isoformat(),
        "detections": [
            {
                "detection_id": dl.detection_id,
                "link_reason": dl.link_reason,
                "linked_by": dl.linked_by,
                "linked_at": dl.linked_at.isoformat(),
            }

            for dl in det_links
        ],
        "entities": [
            {
                "entity_type": el.entity_type,
                "entity_key": el.entity_key,
                "relation": el.relation,
                "first_seen": el.first_seen.isoformat(),
                "last_seen": el.last_seen.isoformat(),
            }
            for el in ent_links
        ],
        "evidence": [
            {
                "id": ev.id,
                "evidence_type": ev.evidence_type,
                "source_ref": ev.source_ref,
                "checksum": ev.checksum,
                "collected_at": ev.collected_at.isoformat(),
            }
            for ev in evidences
        ],
    }


@app.get(
    "/api/v1/incidents/{incident_id}/export",
    tags=["Incident Management"],
    summary="Export Incident Report",
)
async def export_incident_report(
    incident_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Export an auditable incident report without raw event or evidence payloads."""
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    detections = db.execute(
        select(IncidentDetection).where(IncidentDetection.incident_id == incident_id)
    ).scalars().all()
    entities = db.execute(
        select(IncidentEntity).where(IncidentEntity.incident_id == incident_id)
    ).scalars().all()
    evidences = db.execute(
        select(Evidence).where(Evidence.incident_id == incident_id)
    ).scalars().all()
    notes = db.execute(
        select(IncidentNote).where(IncidentNote.incident_id == incident_id)
    ).scalars().all()

    report = {
        "report_version": "1.0.0",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "exported_by": operator.id,
        "incident": {
            "id": inc.id,
            "title": inc.title,
            "severity": inc.severity,
            "status": inc.status,
            "confidence": inc.confidence,
            "owner_id": inc.owner_id,
            "first_seen": inc.first_seen.isoformat(),
            "last_seen": inc.last_seen.isoformat(),
            "version": inc.version,
            "created_at": inc.created_at.isoformat(),
            "updated_at": inc.updated_at.isoformat(),
        },
        "detections": [
            {
                "detection_id": item.detection_id,
                "link_reason": item.link_reason,
                "linked_by": item.linked_by,
                "linked_at": item.linked_at.isoformat(),
            }
            for item in detections
        ],
        "entities": [
            {
                "entity_type": item.entity_type,
                "entity_key": item.entity_key,
                "relation": item.relation,
                "first_seen": item.first_seen.isoformat(),
                "last_seen": item.last_seen.isoformat(),
            }
            for item in entities
        ],
        "evidence": [
            {
                "id": item.id,
                "evidence_type": item.evidence_type,
                "source_ref": item.source_ref,
                "checksum": item.checksum,
                "classification": item.classification,
                "collected_at": item.collected_at.isoformat(),
            }
            for item in evidences
        ],
        "notes": [
            {
                "id": item.id,
                "author_id": item.author_id,
                "body": item.body_redacted,
                "created_at": item.created_at.isoformat(),
            }
            for item in notes
        ],
    }
    db.add(
        AuditEvent(
            id=str(uuid4()),
            actor_type="user",
            actor_id=operator.id,
            action="incident:export",
            object_type="incident",
            object_id=incident_id,
            outcome="success",
            occurred_at=datetime.now(timezone.utc),
            metadata_redacted={"report_version": "1.0.0"},
        )
    )
    db.commit()
    return JSONResponse(
        content=report,
        headers={
            "Content-Disposition": f'attachment; filename="incident-{incident_id}.json"',
        },
    )


@app.post(
    "/api/v1/incidents/{incident_id}/merge",
    tags=["Incident Management"],
    summary="Merge Incidents",
)
async def merge_incident(
    incident_id: str,
    body: IncidentMergeRequest,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles([RBACRoleEnum.SOC_MANAGER, RBACRoleEnum.ADMIN])
    ),
):
    """Merge a source incident into a target incident with version checks and audit history."""
    if incident_id == body.target_incident_id:
        raise HTTPException(status_code=400, detail="Source and target incidents must differ")
    source = db.get(Incident, incident_id)
    target = db.get(Incident, body.target_incident_id)
    if not source or not target:
        raise HTTPException(status_code=404, detail="Source or target incident not found")
    if source.version != body.source_version or target.version != body.target_version:
        raise HTTPException(status_code=409, detail="Incident version conflict")
    if source.status == IncidentStateEnum.CLOSED.value:
        raise HTTPException(status_code=409, detail="Closed incidents cannot be merged")

    for link in db.execute(
        select(IncidentDetection).where(IncidentDetection.incident_id == source.id)
    ).scalars().all():
        if db.get(IncidentDetection, (target.id, link.detection_id)) is None:
            link.incident_id = target.id
        else:
            db.delete(link)
    for entity in db.execute(
        select(IncidentEntity).where(IncidentEntity.incident_id == source.id)
    ).scalars().all():
        existing = db.get(IncidentEntity, (target.id, entity.entity_type, entity.entity_key))
        if existing is None:
            entity.incident_id = target.id
        else:
            db.delete(entity)
    for evidence in db.execute(
        select(Evidence).where(Evidence.incident_id == source.id)
    ).scalars().all():
        evidence.incident_id = target.id
    for relation in db.execute(
        select(EvidenceRelation).where(EvidenceRelation.incident_id == source.id)
    ).scalars().all():
        relation.incident_id = target.id
    for note in db.execute(
        select(IncidentNote).where(IncidentNote.incident_id == source.id)
    ).scalars().all():
        note.incident_id = target.id

    target.first_seen = min(target.first_seen, source.first_seen)
    target.last_seen = max(target.last_seen, source.last_seen)
    target.version += 1
    target.updated_at = datetime.now(timezone.utc)
    source.status = IncidentStateEnum.CLOSED.value
    source.version += 1
    source.updated_at = datetime.now(timezone.utc)
    db.add(
        AuditEvent(
            id=str(uuid4()),
            actor_type="user",
            actor_id=operator.id,
            action="incident:merge",
            object_type="incident",
            object_id=target.id,
            outcome="success",
            occurred_at=datetime.now(timezone.utc),
            metadata_redacted={"source_incident_id": source.id, "reason": body.reason},
        )
    )
    db.commit()
    return {
        "target_incident_id": target.id,
        "source_incident_id": source.id,
        "target_version": target.version,
        "source_status": source.status,
    }


@app.post(
    "/api/v1/incidents/{incident_id}/split",
    status_code=status.HTTP_201_CREATED,
    tags=["Incident Management"],
    summary="Split Incident",
)
async def split_incident(
    incident_id: str,
    body: IncidentSplitRequest,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles([RBACRoleEnum.SOC_MANAGER, RBACRoleEnum.ADMIN])
    ),
):
    """Create a child incident and move selected linked records with an audit trail."""
    source = db.get(Incident, incident_id)
    if not source:
        raise HTTPException(status_code=404, detail="Source incident not found")
    if source.version != body.source_version:
        raise HTTPException(status_code=409, detail="Incident version conflict")

    detections = db.execute(
        select(IncidentDetection).where(
            IncidentDetection.incident_id == incident_id,
            IncidentDetection.detection_id.in_(body.detection_ids),
        )
    ).scalars().all()
    if {item.detection_id for item in detections} != set(body.detection_ids):
        raise HTTPException(status_code=422, detail="All detection IDs must belong to the source incident")
    evidence = db.execute(
        select(Evidence).where(
            Evidence.incident_id == incident_id,
            Evidence.id.in_(body.evidence_ids),
        )
    ).scalars().all()
    if {item.id for item in evidence} != set(body.evidence_ids):
        raise HTTPException(status_code=422, detail="All evidence IDs must belong to the source incident")

    child = Incident(
        id=f"inc-{uuid4().hex[:28]}",
        title=body.title,
        status=source.status,
        severity=source.severity,
        confidence=source.confidence,
        first_seen=source.first_seen,
        last_seen=source.last_seen,
        version=1,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(child)
    db.flush()
    for link in detections:
        link.incident_id = child.id
    for item in evidence:
        item.incident_id = child.id
    moved_evidence_ids = {item.id for item in evidence}
    for relation in db.execute(
        select(EvidenceRelation).where(EvidenceRelation.incident_id == source.id)
    ).scalars().all():
        if (
            relation.from_evidence_id in moved_evidence_ids
            and relation.to_evidence_id in moved_evidence_ids
        ):
            relation.incident_id = child.id
    source.version += 1
    source.updated_at = datetime.now(timezone.utc)
    db.add(
        AuditEvent(
            id=str(uuid4()),
            actor_type="user",
            actor_id=operator.id,
            action="incident:split",
            object_type="incident",
            object_id=source.id,
            outcome="success",
            occurred_at=datetime.now(timezone.utc),
            metadata_redacted={
                "child_incident_id": child.id,
                "detection_count": len(detections),
                "evidence_count": len(evidence),
                "reason": body.reason,
            },
        )
    )
    db.commit()
    return {
        "source_incident_id": source.id,
        "child_incident_id": child.id,
        "source_version": source.version,
        "child_version": child.version,
    }


@app.post(
    "/api/v1/incidents/{incident_id}/transition",
    tags=["Incident Management"],
    summary="Transition Incident State",
)
async def transition_incident_state(
    incident_id: str,
    body: IncidentTransitionRequest,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Execute a validated state transition on an incident with optimistic concurrency control."""
    try:
        updated = lifecycle_manager.transition(
            session=db,
            incident_id=incident_id,
            to_state=body.to_state,
            operator=operator,
            expected_version=body.version,
            reason=body.reason,
        )
        return {
            "incident_id": updated.id,
            "status": updated.status,
            "version": updated.version,
            "updated_at": updated.updated_at.isoformat(),
            "message": f"Successfully transitioned to {updated.status}",
        }
    except InvalidIncidentTransitionError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except IncidentConcurrencyError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )


@app.post(
    "/api/v1/incidents/{incident_id}/notes",
    tags=["Incident Management"],
    summary="Add Analyst Note to Incident",
)
async def add_incident_note(
    incident_id: str,
    body: IncidentNoteRequest,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Add a sanitized analyst investigation note to the incident."""
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    note = incident_manager.add_note(
        session=db,
        incident_id=incident_id,
        author_id=operator.id,
        note_text=body.note,
    )
    return {
        "id": note.id,
        "incident_id": note.incident_id,
        "author_id": note.author_id,
        "created_at": note.created_at.isoformat(),
        "note": note.body_redacted,
    }


@app.get(
    "/api/v1/incidents/{incident_id}/timeline",
    tags=["Incident Management"],
    summary="Get Unified Incident Timeline",
)
async def get_incident_timeline(
    incident_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve chronological unified timeline for an incident."""
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    timeline = incident_manager.get_incident_timeline(session=db, incident_id=incident_id)
    return {
        "incident_id": incident_id,
        "timeline_events_count": len(timeline),
        "timeline": timeline,
    }


# ==============================================================================
# Phase 5: Autonomous Investigation & Triage Agent Endpoints
# ==============================================================================


@app.post(
    "/api/v1/incidents/{incident_id}/investigations",
    tags=["Agent Investigation"],
    summary="Start Incident Investigation Run",
    status_code=status.HTTP_201_CREATED,
)
async def start_incident_investigation(
    incident_id: str,
    body: Optional[InvestigationRunRequest] = None,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Queue and execute a bounded, read-only multi-agent investigation run on an incident."""
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    req = body or InvestigationRunRequest()
    try:
        run_status = await orchestrator.execute_investigation(
            session=db,
            incident_id=incident_id,
            request=req,
        )
        return run_status
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Investigation execution failed: {str(e)}",
        )


@app.get(
    "/api/v1/investigations",
    tags=["Agent Investigation"],
    summary="List Investigation Runs",
)
async def list_investigation_runs(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0, le=10000),
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.VIEWER,
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """List bounded investigation runs for analyst navigation."""
    runs = db.execute(
        select(AgentRun)
        .order_by(AgentRun.started_at.desc())
        .offset(offset)
        .limit(limit)
    ).scalars().all()
    return {
        "count": len(runs),
        "investigations": [
            {
                "id": run.id,
                "incident_id": run.incident_id,
                "task_type": run.task_type,
                "state": run.state,
                "model_ref": run.model_ref,
                "template_version": run.template_version,
                "started_at": run.started_at.isoformat(),
                "finished_at": run.finished_at.isoformat() if run.finished_at else None,
                "failure_code": run.failure_code,
                "budget": run.budget_json,
            }
            for run in runs
        ],
    }


@app.get(
    "/api/v1/investigations/{run_id}",
    tags=["Agent Investigation"],
    summary="Get Investigation Run Status",
)
async def get_investigation_run_status(
    run_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.VIEWER,
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve execution state, tasks, and budget metrics for an investigation run."""
    run_status = orchestrator.get_run_status(session=db, run_id=run_id)
    if not run_status:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation run '{run_id}' not found",
        )
    return run_status


@app.get(
    "/api/v1/investigations/{run_id}/findings",
    tags=["Agent Investigation"],
    summary="Get Investigation Run Findings",
)
async def get_investigation_findings(
    run_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.VIEWER,
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve verified, evidence-grounded findings produced during an investigation."""
    run_status = orchestrator.get_run_status(session=db, run_id=run_id)
    if not run_status:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation run '{run_id}' not found",
        )

    findings = orchestrator.get_run_findings(session=db, run_id=run_id)
    return {
        "run_id": run_id,
        "findings_count": len(findings),
        "findings": findings,
    }


@app.get(
    "/api/v1/investigations/{run_id}/summary",
    tags=["Agent Investigation"],
    summary="Get Investigation Summary",
)
async def get_investigation_summary(
    run_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.VIEWER,
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve structured analyst summary separating facts from hypotheses."""
    summary = orchestrator.get_investigation_summary(session=db, run_id=run_id)
    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation run '{run_id}' not found",
        )
    return summary


@app.post(
    "/api/v1/investigations/{run_id}/review",
    tags=["Agent Investigation"],
    summary="Submit Human Review of Investigation",
)
async def review_investigation_run(
    run_id: str,
    body: InvestigationReviewRequest,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Submit an analyst review decision on an investigation and optionally apply lifecycle transitions."""
    try:
        result = orchestrator.review_investigation(
            session=db,
            run_id=run_id,
            review_request=body,
            operator=operator,
        )
        return result
    except InvalidIncidentTransitionError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except IncidentConcurrencyError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@app.post(
    "/api/v1/investigations/{run_id}/cancel",
    tags=["Agent Investigation"],
    summary="Cancel Investigation Run",
)
async def cancel_investigation_run(
    run_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Cancel an ongoing or queued investigation run."""
    success = orchestrator.cancel_investigation(session=db, run_id=run_id, operator=operator)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Investigation run '{run_id}' not found or cannot be cancelled.",
        )
    return {"run_id": run_id, "status": "CANCELLED", "message": "Investigation run cancelled."}


@app.get(
    "/api/v1/incidents/{incident_id}/investigations",
    tags=["Agent Investigation"],
    summary="Get Incident Investigation History",
)
async def get_incident_investigations(
    incident_id: str,
    limit: int = Query(default=20, ge=1, le=100, description="Max history records to return"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.VIEWER,
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve bounded history of previous investigation runs on an incident."""
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    runs = orchestrator.get_incident_investigations(
        session=db, incident_id=incident_id, limit=limit, offset=offset
    )
    return {
        "incident_id": incident_id,
        "total_count": len(runs),
        "limit": limit,
        "offset": offset,
        "investigations": runs,
    }


@app.post(
    "/api/v1/investigations/{run_id}/continue",
    tags=["Agent Investigation"],
    summary="Continue Investigation Run",
)
async def continue_investigation_run(
    run_id: str,
    body: Optional[InvestigationContinuationRequest] = None,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Perform a bounded continuation of an existing investigation run."""
    run = db.get(AgentRun, run_id)
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation run '{run_id}' not found",
        )

    req = body or InvestigationContinuationRequest()
    try:
        updated_status = await orchestrator.continue_investigation(
            session=db,
            run_id=run_id,
            continuation_request=req,
            operator=operator,
        )
        return updated_status
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Investigation continuation failed: {str(e)}",
        )


# -----------------------------------------------------------------------------
# Phase 6: Response Playbook Proposals & Approval Governance
# -----------------------------------------------------------------------------


@app.get(
    "/api/v1/response/catalogue",
    tags=["Response & Playbook Governance"],
    summary="List Safe Response Action Catalogue",
)
async def get_response_action_catalogue(
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.VIEWER,
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.RESEARCHER,
            ]
        )
    ),
):
    """Retrieve bounded catalogue of authorized response action templates."""
    return [t.model_dump() for t in list_action_catalogue()]


@app.post(
    "/api/v1/incidents/{incident_id}/proposals",
    tags=["Response & Playbook Governance"],
    summary="Create Response Proposal for Incident",
)
async def create_response_proposal(
    incident_id: str,
    body: CreateProposalRequest,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Create a structured, evidence-grounded response proposal subject to policy evaluation."""
    try:
        proposal = response_manager.submit_proposal(
            incident_id=incident_id,
            request=body,
            actor_id=operator.id,
            db_session=db,
        )
        return proposal
    except ProposalNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except ProposalPolicyViolationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )


@app.post(
    "/api/v1/incidents/{incident_id}/proposals/generate",
    tags=["Response & Playbook Governance"],
    summary="Generate Playbook Proposals from Investigation Findings",
)
async def generate_playbook_proposals(
    incident_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Synthesize response proposals grounded in persisted investigation findings and incident telemetry."""
    # 1. Fetch incident
    incident = db.execute(select(Incident).where(Incident.id == incident_id)).scalar_one_or_none()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    # 2. Fetch findings and entities
    from services.persistence.models import AgentFinding, AgentRun, IncidentEntity

    runs = db.execute(select(AgentRun).where(AgentRun.incident_id == incident_id)).scalars().all()
    run_ids = [r.id for r in runs]
    findings: list[AgentFinding] = []
    if run_ids:
        findings = list(
            db.execute(
                select(AgentFinding).where(AgentFinding.run_id.in_(run_ids))
            ).scalars().all()
        )

    entities = db.execute(
        select(IncidentEntity).where(IncidentEntity.incident_id == incident_id)
    ).scalars().all()
    entity_dicts = [
        {"entity_type": e.entity_type, "entity_key": e.entity_key} for e in entities
    ]

    generated_requests = playbook_generator.generate_proposals(
        incident_id=incident.id,
        incident_title=incident.title,
        incident_severity=incident.severity,
        findings=list(findings),
        incident_entities=entity_dicts,
    )

    created_proposals = []
    for req in generated_requests:
        try:
            prop = response_manager.submit_proposal(
                incident_id=incident.id,
                request=req,
                actor_id=operator.id,
                db_session=db,
            )
            created_proposals.append(prop)
        except ProposalPolicyViolationError:
            continue

    return created_proposals


@app.get(
    "/api/v1/incidents/{incident_id}/proposals",
    tags=["Response & Playbook Governance"],
    summary="List Response Proposals for Incident",
)
async def list_incident_proposals(
    incident_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.VIEWER,
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.RESEARCHER,
            ]
        )
    ),
):
    """Retrieve all response action proposals formulated for an incident."""
    incident = db.execute(select(Incident).where(Incident.id == incident_id)).scalar_one_or_none()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )
    return response_manager.list_proposals_for_incident(incident_id=incident_id, db_session=db)


@app.get(
    "/api/v1/proposals/{proposal_id}",
    tags=["Response & Playbook Governance"],
    summary="Get Proposal Details",
)
async def get_proposal_details(
    proposal_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.VIEWER,
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.RESEARCHER,
            ]
        )
    ),
):
    """Retrieve full specification, current state, and approval history of a proposal."""
    try:
        return response_manager.get_proposal(proposal_id=proposal_id, db_session=db)
    except ProposalNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@app.post(
    "/api/v1/proposals/{proposal_id}/approve",
    tags=["Response & Playbook Governance"],
    summary="Submit Human Approval/Rejection for Proposal",
)
async def approve_response_proposal(
    proposal_id: str,
    body: SubmitApprovalRequest,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Submit an authorized human approval or rejection decision enforcing separation-of-duties."""
    try:
        return response_manager.submit_approval(
            proposal_id=proposal_id,
            request=body,
            approver=operator,
            db_session=db,
        )
    except ProposalNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except ApprovalViolationError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except ProposalExpiredError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )


@app.post(
    "/api/v1/proposals/{proposal_id}/revoke",
    tags=["Response & Playbook Governance"],
    summary="Revoke Response Proposal",
)
async def revoke_response_proposal(
    proposal_id: str,
    reason: str = Query(default="Revoked by operator", min_length=3),
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Revoke a pending or approved proposal."""
    try:
        return response_manager.revoke_proposal(
            proposal_id=proposal_id,
            user=operator,
            reason=reason,
            db_session=db,
        )
    except ProposalNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except ApprovalViolationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@app.post(
    "/api/v1/response-actions/{proposal_id}/execute",
    tags=["Response & Playbook Governance"],
    summary="Dispatch Approved Action to Execution Boundary",
)
async def execute_response_action(
    proposal_id: str,
    body: ExecuteActionRequest,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Dispatch an approved response action to the execution boundary.

    Safety Invariant: LIVE_RESPONSE_DISABLED=true is strictly enforced.
    Simulates the action or blocks with safety record; never invokes production containment APIs.
    """
    try:
        return response_manager.execute_action(
            proposal_id=proposal_id,
            request=body,
            actor_id=operator.id,
            db_session=db,
        )
    except ProposalNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except ActionExecutionBlockedError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except ProposalExpiredError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )


@app.post(
    "/api/v1/proposals/{proposal_id}/execute",
    tags=["Response & Playbook Governance"],
    summary="Dispatch Approved Action to Execution Boundary (Alias)",
)
async def execute_proposal_action_alias(
    proposal_id: str,
    body: ExecuteActionRequest,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Dispatch an approved response action to the execution boundary."""
    return await execute_response_action(
        proposal_id=proposal_id,
        body=body,
        db=db,
        operator=operator,
    )


@app.get(
    "/api/v1/incidents/{incident_id}/response-history",
    tags=["Response & Playbook Governance"],
    summary="Get Bounded Response Execution History for Incident",
)
async def get_incident_response_history(
    incident_id: str,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.VIEWER,
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.RESEARCHER,
            ]
        )
    ),
):
    """Retrieve bounded response action history for an incident."""
    incident = db.execute(select(Incident).where(Incident.id == incident_id)).scalar_one_or_none()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )
    actions = (
        db.execute(
            select(ResponseAction)
            .join(ResponseProposal, ResponseAction.proposal_id == ResponseProposal.id)
            .where(ResponseProposal.incident_id == incident_id)
            .order_by(ResponseAction.started_at.desc())
            .offset(offset)
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return [
        {
            "id": a.id,
            "proposal_id": a.proposal_id,
            "idempotency_key": a.idempotency_key,
            "state": a.state,
            "result": a.result_redacted,
            "started_at": a.started_at.isoformat(),
            "finished_at": a.finished_at.isoformat() if a.finished_at else None,
            "verified_at": a.verified_at.isoformat() if a.verified_at else None,
        }
        for a in actions
    ]


@app.get(
    "/api/v1/response-actions/{action_id}",
    tags=["Response & Playbook Governance"],
    summary="Get Response Action Details",
)
async def get_response_action_details(
    action_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.VIEWER,
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.RESEARCHER,
            ]
        )
    ),
):
    """Retrieve execution result details for a specific response action."""
    action = db.execute(select(ResponseAction).where(ResponseAction.id == action_id)).scalar_one_or_none()
    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Response action '{action_id}' not found",
        )
    return {
        "id": action.id,
        "proposal_id": action.proposal_id,
        "idempotency_key": action.idempotency_key,
        "state": action.state,
        "result": action.result_redacted,
        "started_at": action.started_at.isoformat(),
        "finished_at": action.finished_at.isoformat() if action.finished_at else None,
        "verified_at": action.verified_at.isoformat() if action.verified_at else None,
    }


# ==============================================================================
# Sprint 12 MITRE ATT&CK Endpoints
# ==============================================================================

def _get_active_rule_tuples() -> list[tuple[str, str, list[str]]]:
    """Gather all active Sigma and correlation rules with their raw tags."""
    from pathlib import Path

    if detection_engine.rule_count == 0:
        sigma_dir = Path("rules/sigma")
        if sigma_dir.exists():
            detection_engine.load_rules_from_directory(str(sigma_dir))

    if len(correlation_engine.list_rules()) == 0:
        corr_dir = Path("rules/correlation")
        if corr_dir.exists():
            correlation_engine.load_rules_from_directory(str(corr_dir))

    tuples = []
    # 1. Sigma detection rules
    for r in detection_engine.list_rules():
        tuples.append((r.id, "sigma", r.tags or []))
    # 2. Stateful correlation rules
    for cr in correlation_engine.list_rules():
        tags = list(cr.tags or [])
        if cr.sequence:
            for step in cr.sequence:
                if step.tag:
                    tags.append(step.tag)
        tuples.append((str(cr.id), "correlation", tags))
    return tuples


@app.get(
    "/api/v1/attack/tactics",
    tags=["MITRE ATT&CK Integration"],
    summary="List Authoritative ATT&CK Tactics",
)
async def list_attack_tactics(
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve all authoritative Enterprise tactics from the pinned ATT&CK catalog."""
    tactics = attack_catalog.list_tactics()
    return {
        "catalog_version": attack_catalog.version,
        "count": len(tactics),
        "tactics": [t.model_dump() for t in tactics],
    }


@app.get(
    "/api/v1/attack/catalog",
    tags=["MITRE ATT&CK Integration"],
    summary="Get Pinned ATT&CK Catalog Status",
)
async def get_attack_catalog_status(
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Return pinned release metadata and integrity validation results."""
    errors = attack_catalog.validate()
    return {
        **attack_catalog.metadata(),
        "validation_errors": errors,
        "upgrade_requires": [
            "replace the pinned catalog file",
            "verify checksum and version",
            "run ATT&CK mapping and coverage tests",
            "review deprecated and revoked technique diagnostics",
        ],
    }


@app.get(
    "/api/v1/attack/techniques",
    tags=["MITRE ATT&CK Integration"],
    summary="List & Filter ATT&CK Techniques",
)
async def list_attack_techniques(
    tactic: Optional[str] = Query(None, description="Filter by tactic short name, e.g. 'execution'"),
    platform: Optional[str] = Query(None, description="Filter by platform, e.g. 'Windows'"),
    include_deprecated: bool = Query(False, description="Include deprecated/revoked techniques"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """List and paginate techniques from the authoritative pinned ATT&CK Enterprise catalog."""
    techniques = attack_catalog.list_techniques(
        tactic=tactic,
        platform=platform,
        include_deprecated=include_deprecated,
        limit=limit,
        offset=offset,
    )
    total_count = attack_catalog.count_techniques(include_deprecated=include_deprecated)
    return {
        "catalog_version": attack_catalog.version,
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "count": len(techniques),
        "techniques": [t.model_dump() for t in techniques],
    }


@app.get(
    "/api/v1/attack/techniques/{technique_id}",
    tags=["MITRE ATT&CK Integration"],
    summary="Get Technique by Identifier",
)
async def get_attack_technique(
    technique_id: str,
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve details for a single canonical technique or sub-technique."""
    tech = attack_catalog.get_technique(technique_id)
    if not tech:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Technique '{technique_id}' not found in ATT&CK catalog v{attack_catalog.version}",
        )
    return {
        "catalog_version": attack_catalog.version,
        "technique": tech.model_dump(),
    }


@app.get(
    "/api/v1/attack/mappings",
    tags=["MITRE ATT&CK Integration"],
    summary="List Detection & Correlation Rule Mappings",
)
async def list_attack_mappings(
    rule_id: Optional[str] = Query(None, description="Filter by rule ID"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by resolution status"),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """View canonical ATT&CK resolution mappings for all active detection and correlation rules."""
    rule_tuples = _get_active_rule_tuples()
    if rule_id:
        rule_tuples = [rt for rt in rule_tuples if rt[0] == rule_id]

    report = attack_mapping_service.generate_mapping_report(rule_tuples)
    mappings = report.mappings
    if status_filter:
        mappings = [m for m in mappings if m.status == status_filter.lower()]

    return {
        "catalog_version": report.catalog_version,
        "total_tags": len(mappings),
        "valid_mappings": report.valid_mappings,
        "deprecated_mappings": report.deprecated_mappings,
        "revoked_mappings": report.revoked_mappings,
        "unresolved_mappings": report.unresolved_mappings,
        "mappings": [m.model_dump() for m in mappings],
    }


@app.get(
    "/api/v1/attack/coverage",
    tags=["MITRE ATT&CK Integration"],
    summary="Platform ATT&CK Detection Coverage Summary",
)
async def get_attack_coverage(
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Calculate platform-wide ATT&CK coverage statistics across tactics based on loaded rules."""
    rule_tuples = _get_active_rule_tuples()
    summary = attack_mapping_service.calculate_coverage(rule_tuples)
    return summary.model_dump()


@app.get(
    "/api/v1/incidents/{incident_id}/attack-coverage",
    tags=["MITRE ATT&CK Integration"],
    summary="Incident ATT&CK Coverage & Mapped Techniques",
)
async def get_incident_attack_coverage(
    incident_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve all ATT&CK techniques and tactics associated with an incident's detections."""
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    from pathlib import Path

    if detection_engine.rule_count == 0:
        sigma_dir = Path("rules/sigma")
        if sigma_dir.exists():
            detection_engine.load_rules_from_directory(str(sigma_dir))

    stmt = (
        select(IncidentDetection, Detection)
        .join(Detection, IncidentDetection.detection_id == Detection.id)
        .where(IncidentDetection.incident_id == incident_id)
    )
    results = db.execute(stmt).all()

    covered_techniques: Dict[str, dict] = {}
    tactics_observed: Set[str] = set()

    for link, det in results:
        sigma_rule = detection_engine.get_rule(det.rule_id)
        tags = sigma_rule.tags if sigma_rule else []
        for tag in tags:
            mapping = attack_mapping_service.resolve_tag(tag, det.rule_id, "sigma")
            if mapping.status == "valid":
                if mapping.technique_id:
                    tech = attack_catalog.get_technique(mapping.technique_id)
                    if tech:
                        covered_techniques[tech.id] = tech.model_dump()
                        for t in tech.tactics:
                            tactics_observed.add(t)
                if mapping.tactic:
                    tactics_observed.add(mapping.tactic)

    return {
        "incident_id": incident_id,
        "detection_count": len(results),
        "techniques": list(covered_techniques.values()),
        "tactics_observed": sorted(list(tactics_observed)),
    }


@app.get(
    "/api/v1/incidents/{incident_id}/attack-timeline",
    tags=["MITRE ATT&CK Integration"],
    summary="Incident Chronological ATT&CK Technique Timeline",
)
async def get_incident_attack_timeline(
    incident_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve chronological technique progression across the incident based on detection timestamps."""
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    from pathlib import Path

    if detection_engine.rule_count == 0:
        sigma_dir = Path("rules/sigma")
        if sigma_dir.exists():
            detection_engine.load_rules_from_directory(str(sigma_dir))

    stmt = (
        select(IncidentDetection, Detection)
        .join(Detection, IncidentDetection.detection_id == Detection.id)
        .where(IncidentDetection.incident_id == incident_id)
        .order_by(Detection.first_seen.asc())
    )
    results = db.execute(stmt).all()

    timeline = []
    for link, det in results:
        sigma_rule = detection_engine.get_rule(det.rule_id)
        rule_name = sigma_rule.title if sigma_rule else det.rule_id
        tags = sigma_rule.tags if sigma_rule else []

        for tag in tags:
            mapping = attack_mapping_service.resolve_tag(tag, det.rule_id, "sigma")
            if mapping.status == "valid" and mapping.technique_id:
                tech = attack_catalog.get_technique(mapping.technique_id)
                timeline.append(
                    {
                        "timestamp": det.first_seen.isoformat(),
                        "detection_id": det.id,
                        "rule_id": det.rule_id,
                        "rule_name": rule_name,
                        "severity": det.severity,
                        "technique_id": mapping.technique_id,
                        "technique_name": tech.name if tech else mapping.technique_name,
                        "tactic": mapping.tactic or (tech.tactics[0] if tech and tech.tactics else "unknown"),
                    }
                )

    return {
        "incident_id": incident_id,
        "timeline_items_count": len(timeline),
        "timeline": timeline,
    }


# ==============================================================================
# Sprint 13 Threat Intelligence Endpoints
# ==============================================================================

class FeedIngestApiRequest(BaseModel):
    source_id: Optional[str] = Field(None, description="Explicit source identifier")
    source_name: Optional[str] = Field(None, description="Human-readable source name")
    file_path: Optional[str] = Field(None, description="Local filesystem path to feed file")
    feed_payload: Optional[Dict[str, Any]] = Field(None, description="Inline STIX 2.1 or JSON feed payload")


@app.get(
    "/api/v1/threat-intel/lookup",
    tags=["Threat Intelligence"],
    summary="Query Threat Intelligence for Indicator",
)
async def lookup_threat_indicator(
    type: str = Query(..., description="Indicator type: ipv4, ipv6, domain, url, hash_sha256, hash_sha1, hash_md5"),
    value: str = Query(..., description="Indicator value"),
    include_expired: bool = Query(False, description="Whether to include expired intelligence"),
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Enrich an indicator of compromise against the local threat intelligence repository."""
    service = ThreatIntelService(session=db)
    result = service.lookup_indicator(
        indicator_type=type, indicator_value=value, include_expired=include_expired
    )
    return result.model_dump()


@app.get(
    "/api/v1/threat-intel/indicators",
    tags=["Threat Intelligence"],
    summary="List & Filter Threat Indicators",
)
async def list_threat_indicators(
    type: Optional[str] = Query(None, description="Filter by indicator type"),
    status: Optional[str] = Query(None, description="Filter by status (active, expired, etc.)"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """List persisted canonical indicators with pagination."""
    stmt = select(ThreatIndicator)
    if type:
        stmt = stmt.where(ThreatIndicator.indicator_type == type.lower())
    if status:
        stmt = stmt.where(ThreatIndicator.status == status.lower())
    stmt = stmt.order_by(ThreatIndicator.created_at.desc()).offset(offset).limit(limit)

    indicators = db.execute(stmt).scalars().all()
    return {
        "limit": limit,
        "offset": offset,
        "count": len(indicators),
        "indicators": [
            {
                "id": ind.id,
                "type": ind.indicator_type,
                "value": ind.value,
                "raw_value": ind.raw_value,
                "status": ind.status,
                "created_at": ind.created_at.isoformat(),
                "updated_at": ind.updated_at.isoformat(),
            }
            for ind in indicators
        ],
    }


@app.get(
    "/api/v1/threat-intel/sources",
    tags=["Threat Intelligence"],
    summary="List Threat Intelligence Sources",
)
async def list_threat_sources(
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """List configured threat feed sources and their reliability ratings."""
    sources = db.execute(select(ThreatSource)).scalars().all()
    return {
        "count": len(sources),
        "sources": [
            {
                "id": s.id,
                "name": s.name,
                "source_type": s.source_type,
                "reliability": s.reliability,
                "description": s.description,
                "endpoint_url": s.endpoint_url,
                "enabled": s.enabled,
                "polling_interval_minutes": s.polling_interval_minutes,
                "updated_at": s.updated_at.isoformat(),
                "created_at": s.created_at.isoformat(),
            }
            for s in sources
        ],
    }


@app.patch(
    "/api/v1/threat-intel/sources/{source_id}",
    tags=["Threat Intelligence"],
    summary="Update Threat Intelligence Source",
)
async def update_threat_source(
    source_id: str,
    body: ThreatSourceUpdateRequest,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles([RBACRoleEnum.SECURITY_ENGINEER, RBACRoleEnum.ADMIN])
    ),
):
    source = db.get(ThreatSource, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="Threat source not found")
    if (
        body.reliability is None
        and body.description is None
        and body.endpoint_url is None
        and body.enabled is None
        and body.polling_interval_minutes is None
    ):
        raise HTTPException(status_code=422, detail="At least one source field is required")
    before = {
        "reliability": source.reliability,
        "description": source.description,
        "endpoint_url": source.endpoint_url,
        "enabled": source.enabled,
        "polling_interval_minutes": source.polling_interval_minutes,
    }
    if body.reliability is not None:
        source.reliability = body.reliability
    if body.description is not None:
        source.description = body.description
    if body.endpoint_url is not None:
        source.endpoint_url = body.endpoint_url
    if body.enabled is not None:
        source.enabled = body.enabled
    if body.polling_interval_minutes is not None:
        source.polling_interval_minutes = body.polling_interval_minutes
    db.add(
        AuditEvent(
            id=str(uuid4()),
            actor_type="user",
            actor_id=operator.id,
            action="threat_intel:source_update",
            object_type="threat_source",
            object_id=source_id,
            outcome="success",
            occurred_at=datetime.now(timezone.utc),
            metadata_redacted={
                "before": before,
                "after": {
                    "reliability": source.reliability,
                    "description": source.description,
                    "endpoint_url": source.endpoint_url,
                    "enabled": source.enabled,
                    "polling_interval_minutes": source.polling_interval_minutes,
                },
            },
        )
    )
    db.commit()
    return {
        "id": source.id,
        "name": source.name,
        "source_type": source.source_type,
        "reliability": source.reliability,
        "description": source.description,
        "endpoint_url": source.endpoint_url,
        "enabled": source.enabled,
        "polling_interval_minutes": source.polling_interval_minutes,
        "updated_at": source.updated_at.isoformat(),
    }


@app.get(
    "/api/v1/threat-intel/sources/health",
    tags=["Threat Intelligence"],
    summary="Get Threat Feed Freshness",
)
async def get_threat_source_health(
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Return deterministic source freshness and reliability status."""
    health = ThreatIntelService().source_health(db)
    return {
        "freshness_policy": {
            "fresh_within_hours": 24,
            "stale_within_hours": 72,
            "expired_after_hours": 72,
        },
        "source_count": len(health),
        "sources": health,
    }


@app.get(
    "/api/v1/events/{event_id}/threat-intel",
    tags=["Threat Intelligence"],
    summary="Match Event Against Threat Intelligence",
)
async def match_event_threat_intel(
    event_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Match indexed canonical event fields against local IOC observations."""
    event = db.get(EventMetadata, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return ThreatIntelService(session=db).match_event(db, event)


@app.post(
    "/api/v1/threat-intel/feeds/ingest",
    tags=["Threat Intelligence"],
    summary="Ingest Threat Feed (STIX 2.1 or JSON)",
)
async def ingest_threat_feed(
    body: FeedIngestApiRequest,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles([RBACRoleEnum.SECURITY_ENGINEER, RBACRoleEnum.ADMIN])
    ),
):
    """Ingest a STIX 2.1 or JSON threat feed from a validated local file path or payload."""
    from pathlib import Path
    service = ThreatIntelService(session=db)

    # 1. Ingest from local file path if specified
    if body.file_path:
        path = Path(body.file_path)
        # Prevent path traversal outside allowed directories
        allowed_dirs = [Path("datasets"), Path("tests"), Path("services/threat_intel")]
        resolved = path.resolve()
        is_safe = any(
            str(resolved).startswith(str(d.resolve())) for d in allowed_dirs if d.exists()
        )
        if not is_safe:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Feed file path must reside within datasets/ or tests/ directories",
            )
        if not path.is_file():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Feed file not found: {body.file_path}",
            )

        try:
            result = service.ingest_feed_file(
                session=db,
                file_path=path,
                source_id=body.source_id,
                source_name=body.source_name,
            )
            return result.model_dump()
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Feed ingestion failed: {ex}",
            )

    # 2. Ingest from inline JSON payload
    if body.feed_payload:
        sid = body.source_id or f"inline_{uuid4().hex[:8]}"
        sname = body.source_name or "Inline Feed Payload"
        payload = body.feed_payload

        try:
            if payload.get("type") == "bundle":
                records = Stix21FeedParser.parse_bundle(payload)
                result = service.ingest_records(
                    session=db,
                    source_id=sid,
                    source_name=sname,
                    source_type="stix21",
                    records=records,
                )
                return result.model_dump()
            elif "indicators" in payload:
                records = JsonFeedParser.parse_feed(payload)
                result = service.ingest_records(
                    session=db,
                    source_id=sid,
                    source_name=sname,
                    source_type="json_feed",
                    records=records,
                    feed_version=payload.get("version", "1.0"),
                )
                return result.model_dump()
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Unrecognized payload schema. Expected STIX bundle or JSON with 'indicators'.",
                )
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to parse or ingest feed payload: {ex}",
            )

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Must provide either 'file_path' or 'feed_payload'",
    )


# ==============================================================================
# Sprint 14 Explainable Incident Risk Engine Endpoints

@app.get(
    "/api/v1/risk/policy",
    tags=["Incident Risk Engine"],
    summary="Get Active Risk Policy",
)
async def get_risk_policy(
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    record = db.execute(
        select(RiskScoringPolicyModel)
        .where(RiskScoringPolicyModel.active.is_(True))
        .order_by(RiskScoringPolicyModel.created_at.desc())
    ).scalars().first()
    if record:
        risk_engine.policy = _risk_policy_from_record(record)
    return risk_engine.policy.model_dump()


@app.put(
    "/api/v1/risk/policy",
    tags=["Incident Risk Engine"],
    summary="Update Risk Policy",
)
async def update_risk_policy(
    body: RiskPolicyUpdateRequest,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles([RBACRoleEnum.SECURITY_ENGINEER, RBACRoleEnum.ADMIN])
    ),
):
    active_record = db.execute(
        select(RiskScoringPolicyModel)
        .where(RiskScoringPolicyModel.active.is_(True))
        .order_by(RiskScoringPolicyModel.created_at.desc())
    ).scalars().first()
    previous = _risk_policy_from_record(active_record) if active_record else risk_engine.policy
    if body.version == previous.version:
        raise HTTPException(status_code=409, detail="Risk policy version must change")
    if db.get(RiskScoringPolicyModel, body.version) is not None:
        raise HTTPException(status_code=409, detail="Risk policy version already exists")
    policy = RiskScoringPolicy.model_validate(body.model_dump(exclude={"change_reason"}))
    db.query(RiskScoringPolicyModel).update({RiskScoringPolicyModel.active: False})
    db.add(
        RiskScoringPolicyModel(
            version=policy.version,
            weights_json=policy.weights,
            band_thresholds_json=policy.band_thresholds,
            stale_intel_discount=policy.stale_intel_discount,
            missing_intel_baseline=policy.missing_intel_baseline,
            active=True,
            created_by=operator.id,
            change_reason=body.change_reason,
        )
    )
    risk_engine.policy = policy
    db.add(
        AuditEvent(
            id=str(uuid4()),
            actor_type="user",
            actor_id=operator.id,
            action="risk_policy:update",
            object_type="risk_policy",
            object_id=policy.version,
            outcome="success",
            occurred_at=datetime.now(timezone.utc),
            metadata_redacted={
                "previous_version": previous.version,
                "new_version": policy.version,
                "change_reason": body.change_reason,
                "weights": policy.weights,
                "band_thresholds": policy.band_thresholds,
            },
        )
    )
    db.commit()
    return policy.model_dump()


@app.get(
    "/api/v1/risk/policy/history",
    tags=["Incident Risk Engine"],
    summary="List Risk Policy Versions",
)
async def list_risk_policy_history(
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    records = db.execute(
        select(RiskScoringPolicyModel).order_by(
            RiskScoringPolicyModel.created_at.desc(),
            RiskScoringPolicyModel.version.desc(),
        )
    ).scalars().all()
    return [
        {
            **_risk_policy_from_record(record).model_dump(),
            "active": record.active,
            "created_by": record.created_by,
            "change_reason": record.change_reason,
            "created_at": record.created_at,
        }
        for record in records
    ]


@app.post(
    "/api/v1/risk/policy/{version}/rollback",
    tags=["Incident Risk Engine"],
    summary="Activate Prior Risk Policy",
)
async def rollback_risk_policy(
    version: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles([RBACRoleEnum.SECURITY_ENGINEER, RBACRoleEnum.ADMIN])
    ),
):
    record = db.get(RiskScoringPolicyModel, version)
    if record is None:
        raise HTTPException(status_code=404, detail="Risk policy version not found")
    if record.active:
        raise HTTPException(status_code=409, detail="Risk policy version is already active")
    previous = risk_engine.policy.version
    db.query(RiskScoringPolicyModel).update({RiskScoringPolicyModel.active: False})
    record.active = True
    db.add(
        AuditEvent(
            id=str(uuid4()),
            actor_type="user",
            actor_id=operator.id,
            action="risk_policy:rollback",
            object_type="risk_policy",
            object_id=version,
            outcome="success",
            occurred_at=datetime.now(timezone.utc),
            metadata_redacted={"previous_version": previous, "activated_version": version},
        )
    )
    db.commit()
    risk_engine.policy = _risk_policy_from_record(record)
    return risk_engine.policy.model_dump()
# ==============================================================================

@app.post(
    "/api/v1/incidents/{incident_id}/risk-assessment",
    tags=["Incident Risk Engine"],
    summary="Calculate or Refresh Incident Risk Assessment",
)
async def calculate_incident_risk_assessment(
    incident_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Calculate and persist an explainable, deterministic risk assessment for the incident."""
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    assessment = risk_engine.assess_incident(
        incident=incident,
        db_session=db,
        actor_id=operator.id,
        persist=True,
    )
    return assessment.model_dump(mode="json")


@app.get(
    "/api/v1/incidents/{incident_id}/risk-assessment",
    tags=["Incident Risk Engine"],
    summary="Get Current Incident Risk Assessment",
)
async def get_current_incident_risk_assessment(
    incident_id: str,
    auto_calculate: bool = Query(True, description="Calculate assessment if none exists"),
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve the latest risk assessment for the specified incident."""
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    stmt = (
        select(IncidentRiskAssessmentModel)
        .where(IncidentRiskAssessmentModel.incident_id == incident_id)
        .order_by(IncidentRiskAssessmentModel.assessed_at.desc())
    )
    record = db.execute(stmt).scalars().first()

    if not record:
        if auto_calculate:
            assessment = risk_engine.assess_incident(
                incident=incident,
                db_session=db,
                actor_id=operator.id,
                persist=True,
            )
            return assessment.model_dump(mode="json")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No risk assessment found for incident '{incident_id}'",
        )

    return {
        "id": record.id,
        "incident_id": record.incident_id,
        "overall_score": record.overall_score,
        "risk_band": record.risk_band,
        "policy_version": record.policy_version,
        "factors": record.factors_json,
        "primary_drivers": record.primary_drivers_json,
        "uncertainties": record.uncertainties_json,
        "limitations": record.limitations_json,
        "evidence_refs": record.evidence_refs_json,
        "assessed_by": record.assessed_by,
        "assessed_at": record.assessed_at.isoformat(),
    }


@app.get(
    "/api/v1/incidents/{incident_id}/risk-assessment/history",
    tags=["Incident Risk Engine"],
    summary="Get Incident Risk Assessment History",
)
async def get_incident_risk_assessment_history(
    incident_id: str,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve paginated historical risk assessments for auditability and drift tracking."""
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    stmt = (
        select(IncidentRiskAssessmentModel)
        .where(IncidentRiskAssessmentModel.incident_id == incident_id)
        .order_by(IncidentRiskAssessmentModel.assessed_at.desc())
        .offset(offset)
        .limit(limit)
    )
    records = db.execute(stmt).scalars().all()

    return {
        "incident_id": incident_id,
        "total": len(records),
        "limit": limit,
        "offset": offset,
        "assessments": [
            {
                "id": r.id,
                "overall_score": r.overall_score,
                "risk_band": r.risk_band,
                "policy_version": r.policy_version,
                "assessed_by": r.assessed_by,
                "assessed_at": r.assessed_at.isoformat(),
            }
            for r in records
        ],
    }


@app.get(
    "/api/v1/incidents/{incident_id}/risk-assessment/explanation",
    tags=["Incident Risk Engine"],
    summary="Get Factor Breakdown & Explainable Risk Rationale",
)
async def get_incident_risk_assessment_explanation(
    incident_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve detailed factor scores, weights, drivers, and uncertainty flags."""
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    stmt = (
        select(IncidentRiskAssessmentModel)
        .where(IncidentRiskAssessmentModel.incident_id == incident_id)
        .order_by(IncidentRiskAssessmentModel.assessed_at.desc())
    )
    record = db.execute(stmt).scalars().first()

    if record:
        from services.risk.models import (
            IncidentRiskAssessment,
            IncidentRiskBandEnum,
            RiskFactorContribution,
        )
        factors_dict = {
            k: RiskFactorContribution(**v) for k, v in record.factors_json.items()
        }
        assessment = IncidentRiskAssessment(
            id=record.id,
            incident_id=record.incident_id,
            overall_score=record.overall_score,
            risk_band=IncidentRiskBandEnum(record.risk_band),
            policy_version=record.policy_version,
            assessed_at=record.assessed_at,
            assessed_by=record.assessed_by,
            factors=factors_dict,
            primary_drivers=record.primary_drivers_json,
            uncertainties=record.uncertainties_json,
            limitations=record.limitations_json,
            evidence_refs=record.evidence_refs_json,
        )
    else:
        assessment = risk_engine.assess_incident(
            incident=incident,
            db_session=db,
            actor_id=operator.id,
            persist=True,
        )

    explanation = risk_engine.explain_assessment(assessment)
    return explanation.model_dump(mode="json")


# ============================================================================
# SPRINT 15: AI Provider Abstraction & Triage Agent Endpoints
# ============================================================================


@app.post(
    "/api/v1/incidents/{incident_id}/triage",
    tags=["Incident Triage Agent"],
    summary="Execute Evidence-Grounded Incident Triage",
)
async def execute_incident_triage(
    incident_id: str,
    force_fallback: bool = Query(False, description="Force deterministic offline rule fallback"),
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Execute evidence-grounded incident triage evaluation.

    Guarantees:
    - Bounded execution.
    - Anti-hallucination reference validation.
    - Preserves deterministic risk scoring as authoritative.
    - Defends against prompt-injection attacks.
    - Never authorizes or executes response actions.
    """
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    try:
        report = await triage_agent.triage_incident(
            incident_id=incident_id,
            db_session=db,
            actor_id=operator.id,
            force_fallback=force_fallback,
            persist=True,
        )
        return report.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        logger.error("Triage evaluation failed for incident %s: %s", incident_id, e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Triage execution failed: {str(e)}",
        )


@app.get(
    "/api/v1/incidents/{incident_id}/triage",
    tags=["Incident Triage Agent"],
    summary="Get Current Incident Triage Assessment",
)
async def get_current_incident_triage(
    incident_id: str,
    auto_triage: bool = Query(True, description="Run triage evaluation if none exists"),
    force_fallback: bool = Query(False, description="Force deterministic offline fallback if auto-triaging"),
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve the latest triage assessment for an incident."""
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    stmt = (
        select(IncidentTriageAssessmentModel)
        .where(IncidentTriageAssessmentModel.incident_id == incident_id)
        .order_by(IncidentTriageAssessmentModel.created_at.desc())
    )
    record = db.execute(stmt).scalars().first()

    if not record:
        if auto_triage:
            report = await triage_agent.triage_incident(
                incident_id=incident_id,
                db_session=db,
                actor_id=operator.id,
                force_fallback=force_fallback,
                persist=True,
            )
            return report.model_dump(mode="json")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No triage assessment found for incident '{incident_id}'",
        )

    return {
        "id": record.id,
        "incident_id": record.incident_id,
        "summary": record.summary,
        "suspected_activity": record.suspected_activity,
        "confidence": record.confidence,
        "recommended_severity": record.recommended_severity,
        "recommended_priority": record.recommended_priority,
        "supporting_evidence": record.supporting_evidence_json,
        "contradictory_evidence": record.contradictory_evidence_json,
        "unresolved_questions": record.unresolved_questions_json,
        "attack_techniques": record.attack_techniques_json,
        "threat_intel_findings": record.threat_intel_json,
        "risk_assessment": {
            "overall_score": record.risk_score,
            "risk_band": record.risk_band,
            "policy_version": record.risk_policy_version,
        },
        "recommended_steps": record.recommended_steps_json,
        "data_gaps": record.data_gaps_json,
        "uncertainties": record.uncertainties_json,
        "requires_analyst_review": record.requires_analyst_review,
        "provider_info": record.provider_info_json,
        "is_fallback": record.is_fallback,
        "triage_policy_version": record.triage_policy_version,
        "assessed_by": record.assessed_by,
        "created_at": record.created_at.isoformat(),
    }


@app.get(
    "/api/v1/incidents/{incident_id}/triage/history",
    tags=["Incident Triage Agent"],
    summary="Get Incident Triage Assessment History",
)
async def get_incident_triage_history(
    incident_id: str,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve paginated historical triage assessments for an incident."""
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    stmt = (
        select(IncidentTriageAssessmentModel)
        .where(IncidentTriageAssessmentModel.incident_id == incident_id)
        .order_by(IncidentTriageAssessmentModel.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    records = db.execute(stmt).scalars().all()

    return {
        "incident_id": incident_id,
        "total": len(records),
        "limit": limit,
        "offset": offset,
        "assessments": [
            {
                "id": r.id,
                "summary": r.summary,
                "suspected_activity": r.suspected_activity,
                "confidence": r.confidence,
                "recommended_severity": r.recommended_severity,
                "recommended_priority": r.recommended_priority,
                "risk_score": r.risk_score,
                "risk_band": r.risk_band,
                "is_fallback": r.is_fallback,
                "assessed_by": r.assessed_by,
                "created_at": r.created_at.isoformat(),
            }
            for r in records
        ],
    }


@app.get(
    "/api/v1/triage/providers",
    tags=["Incident Triage Agent"],
    summary="Get AI Triage Provider Diagnostics",
)
async def get_triage_provider_diagnostics(
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve secret-safe diagnostics for configured AI triage provider and fallback provider."""
    primary_info = triage_agent.provider.check_availability()
    fallback_info = triage_agent.fallback_provider.check_availability()
    return {
        "primary_provider": primary_info.model_dump(),
        "fallback_provider": fallback_info.model_dump(),
        "safety_invariants": {
            "LIVE_RESPONSE_DISABLED": True,
            "deterministic_risk_authoritative": True,
            "prompt_injection_guard_active": True,
            "read_only_tools_enforced": True,
        },
    }


# =====================================================================
# SPRINT 16: TOOL REGISTRY & AUTHORIZATION ENDPOINTS
# =====================================================================


@app.get(
    "/api/v1/tools",
    response_model=dict,
    tags=["Agent Tool Registry"],
    summary="List Registered Agent Tools",
)
async def list_tools(
    role: Optional[str] = Query(None, description="Filter by authorized role"),
    agent_type: Optional[str] = Query(None, description="Filter by agent identifier"),
    enabled_only: bool = Query(True, description="Filter to enabled tools only"),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """List tools registered in the central typed tool registry."""
    tools = default_registry.list_tools(
        role=role,
        agent_type=agent_type,
        enabled_only=enabled_only,
    )
    return {
        "total": len(tools),
        "registry_version": default_registry.registry_version,
        "policy_version": default_registry.policy_version,
        "tools": [t.to_metadata().model_dump() for t in tools],
    }


@app.get(
    "/api/v1/tools/{tool_name}",
    response_model=ToolMetadataDTO,
    tags=["Agent Tool Registry"],
    summary="Get Tool Details",
)
async def get_tool_details(
    tool_name: str,
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve detailed metadata for a registered tool."""
    tool = default_registry.get(tool_name)
    if not tool:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tool '{tool_name}' not found in registry",
        )
    return tool.to_metadata()


@app.post(
    "/api/v1/incidents/{incident_id}/tools/execute",
    response_model=ToolExecutionResult,
    tags=["Agent Tool Registry"],
    summary="Execute Controlled Investigation Tool",
)
async def execute_tool_endpoint(
    incident_id: str,
    payload: ToolExecutionRequest,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Execute a registered investigation tool within strict server-side authorization boundaries."""
    if payload.incident_id != incident_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Mismatched incident_id: URL specifies '{incident_id}', payload specifies '{payload.incident_id}'",
        )

    try:
        result = default_tool_executor.execute_tool(
            request=payload,
            db_session=db,
            principal=operator,
        )
        return result
    except ToolNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ToolDisabledError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ToolAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ToolValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e)
        )
    except ToolExecutionLimitError as e:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(e)
        )


# ==============================================================================
# Sprint 18: Retrieval-Augmented Generation (RAG) Endpoints
# ==============================================================================


@app.post(
    "/api/v1/rag/query",
    response_model=RAGQueryResponse,
    tags=["RAG & Knowledge Retrieval"],
    summary="Query RAG Security Knowledge Base",
)
async def query_rag_knowledge(
    payload: RAGQueryRequest,
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
                RBACRoleEnum.RESEARCHER,
                RBACRoleEnum.SOC_MANAGER,
            ]
        )
    ),
):
    """Execute bounded, evidence-grounded search over approved security knowledge corpus."""
    try:
        return rag_engine.query(request=payload, principal=operator)
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        logger.error("RAG query failed: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Knowledge retrieval error: {str(e)}",
        )


@app.get(
    "/api/v1/rag/sources",
    response_model=RAGIndexStatus,
    tags=["RAG & Knowledge Retrieval"],
    summary="Get RAG Knowledge Base Index Status",
)
async def get_rag_sources(
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve indexing status, document counts, and retrieval backend health."""
    return rag_engine.get_status()


# ==============================================================================
# Sprint 18: Controlled Threat Hunting Endpoints
# ==============================================================================


@app.post(
    "/api/v1/hunting/jobs",
    response_model=HuntJobStatus,
    status_code=status.HTTP_201_CREATED,
    tags=["Controlled Threat Hunting"],
    summary="Launch Bounded Threat Hunt",
)
async def launch_threat_hunt(
    payload: HuntJobRequest,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Execute bounded structured threat hunt across telemetry and detections."""
    try:
        return hunting_service.launch_hunt(session=db, request=payload, principal=operator)
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))


@app.get(
    "/api/v1/hunting/jobs/{hunt_id}",
    response_model=HuntJobStatus,
    tags=["Controlled Threat Hunting"],
    summary="Get Threat Hunt Status and Findings",
)
async def get_hunt_job(
    hunt_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve status, findings, and telemetry coverage gaps for an executed threat hunt."""
    job = hunting_service.get_hunt_status(session=db, hunt_id=hunt_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Hunt job '{hunt_id}' not found.")
    return job


@app.get(
    "/api/v1/hunting/jobs",
    response_model=List[HuntJobStatus],
    tags=["Controlled Threat Hunting"],
    summary="List Threat Hunting Jobs",
)
async def list_hunt_jobs(
    limit: int = 20,
    offset: int = 0,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve bounded history of threat hunting runs."""
    return hunting_service.list_hunt_jobs(session=db, limit=limit, offset=offset)


# ==============================================================================
# Sprint 18: Investigation Orchestration Endpoints
# ==============================================================================


@app.post(
    "/api/v1/orchestrator/plans",
    response_model=InvestigationPlan,
    tags=["Investigation Orchestration"],
    summary="Generate Bounded Multi-Agent Investigation Plan",
)
async def generate_orchestration_plan(
    payload: OrchestrationPlanRequest,
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Generate a DAG-directed investigation plan with task dependencies and budgets."""
    return orchestrator.build_investigation_plan(
        incident_id=payload.incident_id,
        max_steps=payload.max_steps,
        budget_usd=payload.budget_limit_usd,
        focus_areas=payload.focus_areas,
    )


@app.post(
    "/api/v1/orchestrator/execute",
    response_model=OrchestrationExecutionResult,
    tags=["Investigation Orchestration"],
    summary="Execute Orchestrated Multi-Agent Investigation Plan",
)
async def execute_orchestration_plan(
    plan: InvestigationPlan,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Execute multi-agent investigation plan with dependency resolution, retries, and failure isolation."""
    try:
        return await orchestrator.execute_orchestrated_plan(session=db, plan=plan, operator=operator)
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND if "not found" in str(e).lower() else status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )


@app.get(
    "/api/v1/orchestrator/history",
    tags=["Investigation Orchestration"],
    summary="Get Orchestration Run History",
)
async def get_orchestration_history(
    limit: int = 20,
    offset: int = 0,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve bounded history of multi-agent orchestration runs."""
    return orchestrator.get_orchestration_history(session=db, limit=limit, offset=offset)


# ==============================================================================
# Sprint 19: Detection Engineering Assistant Endpoints
# ==============================================================================


@app.post(
    "/api/v1/detection/candidates",
    response_model=CandidateRuleResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Detection Engineering"],
    summary="Generate Candidate Sigma Rule",
)
async def generate_candidate_rule_endpoint(
    payload: RuleGenerationRequest,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Generate a structured candidate Sigma rule from a detection objective."""
    try:
        return detection_assistant.generate_candidate_rule(payload, author=operator, db_session=db)
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))


@app.get(
    "/api/v1/detection/candidates",
    response_model=List[CandidateRuleResponse],
    tags=["Detection Engineering"],
    summary="List Detection Rule Candidates",
)
async def list_candidates_endpoint(
    status_filter: Optional[str] = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """List detection rule candidates with optional lifecycle status filter."""
    try:
        return detection_assistant.list_candidates(db_session=db, caller=operator, status=status_filter, limit=limit)
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


@app.get(
    "/api/v1/detection/candidates/{candidate_id}",
    response_model=CandidateRuleResponse,
    tags=["Detection Engineering"],
    summary="Get Detection Rule Candidate",
)
async def get_candidate_endpoint(
    candidate_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve details, validation report, and test results for a candidate rule."""
    try:
        return detection_assistant.get_candidate(candidate_id=candidate_id, db_session=db, caller=operator)
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@app.post(
    "/api/v1/detection/candidates/{candidate_id}/validate",
    response_model=CandidateRuleResponse,
    tags=["Detection Engineering"],
    summary="Validate Detection Rule Candidate",
)
async def validate_candidate_endpoint(
    candidate_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Re-run comprehensive static validation against a candidate rule."""
    try:
        return detection_assistant.validate_candidate(candidate_id=candidate_id, db_session=db, caller=operator)
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@app.post(
    "/api/v1/detection/candidates/{candidate_id}/test",
    response_model=RuleTestResult,
    tags=["Detection Engineering"],
    summary="Test Detection Rule Candidate",
)
async def test_candidate_endpoint(
    candidate_id: str,
    payload: RuleTestRequest,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Safely test a candidate rule against approved synthetic fixtures or historical events."""
    try:
        return detection_assistant.test_candidate(
            candidate_id=candidate_id,
            test_req=payload,
            db_session=db,
            caller=operator,
        )
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@app.post(
    "/api/v1/detection/candidates/{candidate_id}/review",
    response_model=CandidateRuleResponse,
    tags=["Detection Engineering"],
    summary="Review Detection Rule Candidate",
)
async def review_candidate_endpoint(
    candidate_id: str,
    payload: CandidateReviewRequest,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Authorized human review of a candidate rule (approve, reject, or request changes)."""
    try:
        return detection_assistant.review_candidate(
            candidate_id=candidate_id,
            review_req=payload,
            reviewer=operator,
            db_session=db,
        )
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND if "not found" in str(e).lower() else status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )


@app.post(
    "/api/v1/detection/candidates/{candidate_id}/activate",
    response_model=CandidateRuleResponse,
    tags=["Detection Engineering"],
    summary="Activate Detection Rule Candidate",
)
async def activate_candidate_endpoint(
    candidate_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Explicitly activate an APPROVED candidate rule into the live detection engine."""
    try:
        return detection_assistant.activate_candidate(
            candidate_id=candidate_id,
            caller=operator,
            db_session=db,
        )
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND if "not found" in str(e).lower() else status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )


@app.post(
    "/api/v1/detection/candidates/{candidate_id}/deactivate",
    response_model=CandidateRuleResponse,
    tags=["Detection Engineering"],
    summary="Deactivate Detection Rule Candidate",
)
async def deactivate_candidate_endpoint(
    candidate_id: str,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Deactivate an ACTIVE rule and remove it from the live detection engine."""
    try:
        return detection_assistant.deactivate_candidate(
            candidate_id=candidate_id,
            caller=operator,
            db_session=db,
        )
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND if "not found" in str(e).lower() else status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )


@app.post(
    "/api/v1/detection/validate",
    response_model=RuleValidationReport,
    tags=["Detection Engineering"],
    summary="Ad-Hoc Validate Sigma Rule",
)
async def adhoc_validate_endpoint(
    payload: AdHocValidateRequest,
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Validate arbitrary Sigma rule YAML without persisting a candidate."""
    return detection_assistant.validator.validate_yaml(yaml_content=payload.rule_yaml)


@app.post(
    "/api/v1/detection/explain",
    response_model=RuleExplanationResponse,
    tags=["Detection Engineering"],
    summary="Ad-Hoc Explain Detection Rule",
)
async def adhoc_explain_endpoint(
    payload: AdHocExplainRequest,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Explain detection rule logic, ATT&CK mappings, telemetry requirements, and blind spots."""
    try:
        return detection_assistant.explain_rule(
            yaml_content=payload.rule_yaml,
            candidate_id=None,
            db_session=db,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND if "not found" in str(e).lower() else status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )


@app.post(
    "/api/v1/detection/test",
    response_model=RuleTestResult,
    tags=["Detection Engineering"],
    summary="Ad-Hoc Test Sigma Rule",
)
async def adhoc_test_endpoint(
    payload: RuleTestRequest,
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Safely test arbitrary Sigma YAML against synthetic fixtures without persisting a candidate."""
    return detection_assistant.tester.test_rule(request=payload)


# ---------------------------------------------------------------------------
# SPRINT 23: BENCHMARK & EVALUATION API ENDPOINTS
# ---------------------------------------------------------------------------


class BenchmarkRunApiRequest(BaseModel):
    scenario_ids: Optional[List[str]] = Field(default=None, description="Optional list of scenario IDs to run")
    category: Optional[str] = Field(default=None, description="Optional category filter")
    execution_mode: BenchmarkExecutionModeEnum = Field(
        default=BenchmarkExecutionModeEnum.DETERMINISTIC_OFFLINE,
        description="Execution mode: deterministic_offline, mocked_provider, live_provider",
    )


class BenchmarkCompareApiRequest(BaseModel):
    run_result: BenchmarkRunResult = Field(..., description="Benchmark run result to compare")
    baseline_id: str = Field(default="baseline_v1_0", description="Baseline identifier to compare against")
    tolerance: float = Field(default=0.001, ge=0.0, le=0.1, description="Numerical regression tolerance threshold")


@app.get(
    "/api/v1/benchmarks/ground-truth",
    response_model=BenchmarkDataset,
    tags=["Benchmarking & Evaluation"],
    summary="Get Authoritative Ground Truth Dataset",
)
async def get_ground_truth_endpoint(
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Retrieve the versioned ground-truth dataset and scenario labels."""
    return default_ground_truth_repo.dataset


@app.post(
    "/api/v1/benchmarks/run",
    response_model=BenchmarkRunResult,
    tags=["Benchmarking & Evaluation"],
    summary="Execute Benchmark Suite",
)
async def run_benchmark_endpoint(
    payload: BenchmarkRunApiRequest,
    db: Session = Depends(get_db),
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Execute reproducible defensive benchmark suite and compute evidence-grounded metrics."""
    from scenarios.models import ScenarioCategoryEnum

    cat_enum = None
    if payload.category:
        try:
            cat_enum = ScenarioCategoryEnum(payload.category)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Unknown scenario category '{payload.category}'",
            )

    return await default_benchmark_runner.run_benchmark(
        db_session=db,
        scenario_ids=payload.scenario_ids,
        category=cat_enum,
        execution_mode=payload.execution_mode,
    )


@app.get(
    "/api/v1/benchmarks/baselines",
    response_model=List[str],
    tags=["Benchmarking & Evaluation"],
    summary="List Stored Benchmark Baselines",
)
async def list_baselines_endpoint(
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SOC_ANALYST,
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.THREAT_HUNTER,
                RBACRoleEnum.DETECTION_ENGINEER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """List all stored reference baseline identifiers."""
    return default_baseline_comparator.list_baselines()


@app.post(
    "/api/v1/benchmarks/compare",
    response_model=BaselineComparisonResult,
    tags=["Benchmarking & Evaluation"],
    summary="Compare Benchmark Run Against Baseline",
)
async def compare_benchmark_endpoint(
    payload: BenchmarkCompareApiRequest,
    operator: Principal = Depends(
        require_roles(
            [
                RBACRoleEnum.SECURITY_ENGINEER,
                RBACRoleEnum.SOC_MANAGER,
                RBACRoleEnum.ADMIN,
            ]
        )
    ),
):
    """Compare a benchmark run result against a reference baseline and detect regressions."""
    try:
        return default_baseline_comparator.compare(
            current_run=payload.run_result,
            baseline=payload.baseline_id,
            tolerance=payload.tolerance,
        )
    except FileNotFoundError as fnf:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(fnf))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))

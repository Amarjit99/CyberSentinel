"""CyberSentinel AI — Retrieval-Augmented Generation (RAG) Schemas (Sprint 18)
Governing Decisions: ADR-0002, ADR-0005, Phase 18 Specification, doc 16-RAG-ARCHITECTURE
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RAGSourceTypeEnum(str, Enum):
    """Approved data source categories for RAG retrieval."""

    ATTACK = "attack"
    SIGMA = "sigma"
    THREAT_INTEL = "threat_intel"
    PLAYBOOK = "playbook"
    INCIDENT_EVIDENCE = "incident_evidence"
    INCIDENT_FINDINGS = "incident_findings"


class DocumentChunk(BaseModel):
    """Normalized document chunk prepared for bounded lexical/vector retrieval."""

    chunk_id: str = Field(default_factory=lambda: f"chk-{uuid4().hex[:12]}")
    source_id: str = Field(..., description="Stable source identifier (e.g. attack:T1059.001)")
    source_type: RAGSourceTypeEnum = Field(..., description="Approved source category")
    incident_id: Optional[str] = Field(
        default=None,
        description="Optional incident scope; if set, chunk is restricted to this incident",
    )
    title: str = Field(..., description="Document or section title")
    content: str = Field(..., description="Chunk content text")
    citation_label: str = Field(..., description="Display citation tag (e.g. [ATT&CK:T1059.001])")
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    is_stale: bool = Field(default=False)


class RAGQueryRequest(BaseModel):
    """Bounded search query request for RAG knowledge retrieval."""

    query: str = Field(..., min_length=2, max_length=500, description="Natural language search query")
    source_types: Optional[List[RAGSourceTypeEnum]] = Field(
        default=None,
        description="Optional source type filter; if omitted, all authorized sources searched",
    )
    incident_id: Optional[str] = Field(
        default=None,
        description="Optional incident filter for accessing incident-scoped evidence/findings",
    )
    top_k: int = Field(default=5, ge=1, le=20, description="Maximum number of candidate chunks to return")
    min_score: float = Field(default=0.05, ge=0.0, le=1.0, description="Relevance score threshold")


class RetrievedChunkResult(BaseModel):
    """Scored and ranked retrieved document chunk with provenance."""

    chunk_id: str
    source_id: str
    source_type: str
    incident_id: Optional[str] = None
    title: str
    content: str
    score: float
    citation_label: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    is_stale: bool = False


class RAGQueryResponse(BaseModel):
    """Grounded RAG retrieval response with citations and provenance."""

    query: str
    retrieval_method: str = Field(
        default="lexical_bm25",
        description="Exact retrieval method employed: 'lexical_bm25' or 'opensearch'",
    )
    total_candidates: int
    results: List[RetrievedChunkResult] = Field(default_factory=list)
    generated_summary: Optional[str] = Field(
        default=None,
        description="Evidence-grounded synthesized summary incorporating verified citations",
    )
    citations: List[str] = Field(
        default_factory=list,
        description="Verified citation labels present in both retrieved candidates and generated text",
    )
    unresolved_queries: List[str] = Field(
        default_factory=list,
        description="Sub-questions or aspects where no matching knowledge was discovered",
    )
    duration_ms: float = 0.0
    is_fallback: bool = Field(
        default=True,
        description="True when lexical BM25 fallback is active in absence of live OpenSearch cluster",
    )


class RAGIndexStatus(BaseModel):
    """Operational status and breakdown of indexed RAG knowledge sources."""

    status: str = "HEALTHY"
    retrieval_backend: str = "in_memory_lexical_bm25"
    total_chunks: int = 0
    sources_breakdown: Dict[str, int] = Field(default_factory=dict)
    last_indexed_at: datetime = Field(default_factory=utc_now)
    known_limitations: List[str] = Field(
        default_factory=lambda: [
            "Operating with deterministic lexical BM25 fallback; OpenSearch live cluster is not attached."
        ]
    )

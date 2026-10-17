"""CyberSentinel AI — Retrieval-Augmented Generation (RAG) Engine (Sprint 18)
Governing Decisions: ADR-0002, ADR-0005, Phase 18 Specification, doc 16-RAG-ARCHITECTURE
"""

import logging
import math
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from attack.registry import AttackCatalog
from packages.auth import Principal, RBACRoleEnum
from packages.observability.metrics import metrics
from services.agents.investigation import INJECTION_HEURISTICS
from services.agents.providers import (
    BaseLLMProvider,
    DeterministicRuleProvider,
)
from services.persistence.models import (
    AgentFinding as DbAgentFinding,
)
from services.persistence.models import (
    AgentRun as DbAgentRun,
)
from services.persistence.models import (
    Evidence as DbEvidence,
)
from services.persistence.models import (
    ThreatIndicator as DbThreatIndicator,
)
from services.rag.models import (
    DocumentChunk,
    RAGIndexStatus,
    RAGQueryRequest,
    RAGQueryResponse,
    RAGSourceTypeEnum,
    RetrievedChunkResult,
)

logger = logging.getLogger("cybersentinel.rag")

STOPWORDS = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are",
    "as", "at", "be", "because", "been", "before", "being", "below", "between", "both", "but", "by",
    "could", "did", "do", "does", "doing", "down", "during", "each", "few", "for", "from", "further",
    "had", "has", "have", "having", "he", "her", "here", "hers", "herself", "him", "himself", "his",
    "how", "i", "if", "in", "into", "is", "it", "its", "itself", "me", "more", "most", "my", "myself",
    "no", "nor", "not", "of", "off", "on", "once", "only", "or", "other", "ought", "our", "ours",
    "ourselves", "out", "over", "own", "same", "she", "should", "so", "some", "such", "than", "that",
    "the", "their", "theirs", "them", "themselves", "then", "there", "these", "they", "this", "those",
    "through", "to", "too", "under", "until", "up", "very", "was", "we", "were", "what", "when",
    "where", "which", "while", "who", "whom", "why", "with", "would", "you", "your", "yours", "yourself",
}

TOKEN_PATTERN = re.compile(r"\b[a-zA-Z0-9_\-\.]{2,}\b")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def tokenize(text: str) -> List[str]:
    """Tokenize and filter stopwords for lexical retrieval."""
    tokens = TOKEN_PATTERN.findall(text.lower())
    return [t for t in tokens if t not in STOPWORDS]


class RAGEngine:
    """Bounded, authorized security knowledge retrieval pipeline."""

    def __init__(
        self,
        provider: Optional[BaseLLMProvider] = None,
        k1: float = 1.5,
        b: float = 0.75,
    ):
        self.provider = provider or DeterministicRuleProvider()
        self.k1 = k1
        self.b = b
        self._chunks: Dict[str, DocumentChunk] = {}
        self._inverted_index: Dict[str, Set[str]] = defaultdict(set)
        self._doc_token_counts: Dict[str, int] = {}
        self._doc_term_freqs: Dict[str, Counter[str]] = {}
        self._avg_doc_len: float = 0.0
        self._last_indexed_at: datetime = utc_now()
        self._initialized: bool = False

    def initialize_default_sources(self, db_session: Optional[Session] = None) -> RAGIndexStatus:
        """Load and index all approved baseline security sources (ATT&CK, Sigma, Playbooks, Threat Intel)."""
        logger.info("Initializing baseline RAG security knowledge corpus...")
        self._initialized = True

        # 1. Index MITRE ATT&CK Catalog
        try:
            catalog = AttackCatalog()
            self.index_attack_catalog(catalog)
        except Exception as ex:
            logger.warning("Failed indexing ATT&CK catalog: %s", ex)

        # 2. Index Sigma Detection Rules
        sigma_dir = Path(__file__).resolve().parents[2] / "rules" / "sigma"
        if sigma_dir.is_dir():
            self.index_sigma_directory(sigma_dir)

        # 3. Index Playbooks
        playbooks_dir = Path(__file__).resolve().parents[2] / "playbooks"
        if playbooks_dir.is_dir():
            self.index_playbooks_directory(playbooks_dir)

        # 4. Index Threat Intel (if database session provided)
        if db_session:
            self.index_threat_intel(db_session)

        self._recalculate_bm25_stats()
        self._initialized = True
        logger.info("RAG Engine indexed %d chunks across approved security sources.", len(self._chunks))
        return self.get_status()

    def clear(self) -> None:
        """Clear all indexed documents and inverted index structures."""
        self._chunks.clear()
        self._inverted_index.clear()
        self._doc_token_counts.clear()
        self._doc_term_freqs.clear()
        self._avg_doc_len = 0.0

    def add_chunk(self, chunk: DocumentChunk) -> None:
        """Add a document chunk to the in-memory inverted index."""
        # Sanitize untrusted input against prompt-injection directives
        sanitized_content = chunk.content
        for pattern in INJECTION_HEURISTICS:
            if pattern.search(sanitized_content):
                chunk.metadata["injection_flagged"] = True
                break

        tokens = tokenize(f"{chunk.title} {chunk.content}")
        token_count = len(tokens)
        term_freq = Counter(tokens)

        self._chunks[chunk.chunk_id] = chunk
        self._doc_token_counts[chunk.chunk_id] = token_count
        self._doc_term_freqs[chunk.chunk_id] = term_freq

        for term in term_freq.keys():
            self._inverted_index[term].add(chunk.chunk_id)

    def _recalculate_bm25_stats(self) -> None:
        """Recalculate average document length for BM25 scoring."""
        if not self._doc_token_counts:
            self._avg_doc_len = 0.0
        else:
            self._avg_doc_len = sum(self._doc_token_counts.values()) / float(len(self._doc_token_counts))
        self._last_indexed_at = utc_now()

    def index_attack_catalog(self, catalog: AttackCatalog) -> int:
        """Index all MITRE ATT&CK techniques as discrete chunks."""
        count = 0
        for tech in catalog.list_techniques():
            content_parts = [
                f"Technique ID: {tech.id}",
                f"Name: {tech.name}",
                f"Description: {tech.description}",
                f"Tactics: {', '.join(tech.tactics)}",
                f"Platforms: {', '.join(tech.platforms)}",
                f"Data Sources: {', '.join(tech.data_sources)}",
            ]
            chunk = DocumentChunk(
                chunk_id=f"chk-att-{tech.id.lower()}",
                source_id=f"attack:{tech.id}",
                source_type=RAGSourceTypeEnum.ATTACK,
                incident_id=None,
                title=f"ATT&CK {tech.id}: {tech.name}",
                content="\n".join(content_parts),
                citation_label=f"[ATT&CK:{tech.id}]",
                metadata={
                    "technique_id": tech.id,
                    "tactics": tech.tactics,
                    "platforms": tech.platforms,
                    "catalog_version": catalog.version,
                },
            )
            self.add_chunk(chunk)
            count += 1
        return count

    def index_sigma_directory(self, sigma_dir: Path) -> int:
        """Index Sigma detection rules from YAML files."""
        count = 0
        for yml_file in sigma_dir.glob("*.yml"):
            try:
                data = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
                if not isinstance(data, dict):
                    continue
                rule_id = str(data.get("id", yml_file.stem))
                title = data.get("title", yml_file.stem)
                desc = data.get("description", "")
                tags = data.get("tags", [])
                level = data.get("level", "medium")
                fps = data.get("falsepositives", [])

                content = (
                    f"Sigma Rule: {title}\n"
                    f"Rule ID: {rule_id}\n"
                    f"Severity: {level}\n"
                    f"Description: {desc}\n"
                    f"Tags: {', '.join(tags)}\n"
                    f"Known False Positives: {', '.join(str(f) for f in fps)}"
                )
                chunk = DocumentChunk(
                    chunk_id=f"chk-sig-{rule_id[:16]}",
                    source_id=f"sigma:{rule_id}",
                    source_type=RAGSourceTypeEnum.SIGMA,
                    incident_id=None,
                    title=f"Sigma: {title}",
                    content=content,
                    citation_label=f"[SIGMA:{rule_id[:8]}]",
                    metadata={"rule_id": rule_id, "level": level, "tags": tags, "filename": yml_file.name},
                )
                self.add_chunk(chunk)
                count += 1
            except Exception as ex:
                logger.warning("Failed parsing Sigma rule %s: %s", yml_file.name, ex)
        return count

    def index_playbooks_directory(self, playbooks_dir: Path) -> int:
        """Index approved response and investigation playbooks."""
        count = 0
        for md_file in playbooks_dir.glob("*.md"):
            try:
                text = md_file.read_text(encoding="utf-8")
                chunk = DocumentChunk(
                    chunk_id=f"chk-pb-{md_file.stem}",
                    source_id=f"playbook:{md_file.stem}",
                    source_type=RAGSourceTypeEnum.PLAYBOOK,
                    incident_id=None,
                    title=f"Playbook: {md_file.stem.replace('_', ' ').title()}",
                    content=text[:2000],  # Bounded chunk size
                    citation_label=f"[PLAYBOOK:{md_file.stem}]",
                    metadata={"filename": md_file.name},
                )
                self.add_chunk(chunk)
                count += 1
            except Exception as ex:
                logger.warning("Failed parsing playbook %s: %s", md_file.name, ex)
        return count

    def index_threat_intel(self, session: Session, limit: int = 200) -> int:
        """Index threat intelligence indicator records from the database."""
        stmt = select(DbThreatIndicator).limit(limit)
        indicators = session.execute(stmt).scalars().all()
        count = 0
        for rec in indicators:
            content = (
                f"Indicator: {rec.value} ({rec.indicator_type})\n"
                f"Status: {rec.status}\n"
                f"Raw Value: {rec.raw_value}"
            )
            chunk = DocumentChunk(
                chunk_id=f"chk-ti-{rec.id[:12]}",
                source_id=f"threat_intel:{rec.value}",
                source_type=RAGSourceTypeEnum.THREAT_INTEL,
                incident_id=None,
                title=f"Threat Indicator: {rec.value}",
                content=content,
                citation_label=f"[TI:{rec.value}]",
                metadata={
                    "indicator_type": rec.indicator_type,
                    "status": rec.status,
                },
            )
            self.add_chunk(chunk)
            count += 1
        return count

    def index_incident_evidence(self, session: Session, incident_id: str) -> int:
        """Index incident-specific evidence records with strict incident scoping isolation."""
        stmt = select(DbEvidence).where(DbEvidence.incident_id == incident_id)
        evidence_items = session.execute(stmt).scalars().all()
        count = 0
        for ev in evidence_items:
            content = (
                f"Evidence ID: {ev.id}\n"
                f"Incident: {ev.incident_id}\n"
                f"Type: {ev.evidence_type}\n"
                f"Source Ref: {ev.source_ref}\n"
                f"Checksum: {ev.checksum}\n"
                f"Collector: {ev.created_by}"
            )
            chunk = DocumentChunk(
                chunk_id=f"chk-ev-{ev.id[:12]}",
                source_id=f"evidence:{ev.id}",
                source_type=RAGSourceTypeEnum.INCIDENT_EVIDENCE,
                incident_id=incident_id,
                title=f"Incident Evidence: {ev.id}",
                content=content,
                citation_label=f"[EVIDENCE:{ev.id}]",
                metadata={"evidence_type": ev.evidence_type, "checksum": ev.checksum},
            )
            self.add_chunk(chunk)
            count += 1
        self._recalculate_bm25_stats()
        return count

    def index_incident_findings(self, session: Session, incident_id: str) -> int:
        """Index prior investigation findings scoped strictly to an incident."""
        stmt = (
            select(DbAgentFinding)
            .join(DbAgentRun, DbAgentFinding.run_id == DbAgentRun.id)
            .where(DbAgentRun.incident_id == incident_id, DbAgentFinding.claim != "")
            .limit(50)
        )
        findings = session.execute(stmt).scalars().all()
        count = 0
        for f in findings:
            chunk = DocumentChunk(
                chunk_id=f"chk-find-{f.id[:12]}",
                source_id=f"finding:{f.id}",
                source_type=RAGSourceTypeEnum.INCIDENT_FINDINGS,
                incident_id=incident_id,
                title=f"Investigation Finding: {f.id}",
                content=f"Claim: {f.claim}\nType: {f.finding_type}\nConfidence: {f.confidence}",
                citation_label=f"[FINDING:{f.id}]",
                metadata={"finding_type": f.finding_type, "confidence": f.confidence},
            )
            self.add_chunk(chunk)
            count += 1
        self._recalculate_bm25_stats()
        return count

    def query(
        self,
        request: RAGQueryRequest,
        principal: Principal,
    ) -> RAGQueryResponse:
        """Execute bounded lexical retrieval with access control and citation validation."""
        if not self._initialized:
            self.initialize_default_sources()
        start_time = time.perf_counter()

        # 1. Authorize principal
        allowed_roles = {
            RBACRoleEnum.SOC_ANALYST,
            RBACRoleEnum.THREAT_HUNTER,
            RBACRoleEnum.SECURITY_ENGINEER,
            RBACRoleEnum.ADMIN,
            RBACRoleEnum.RESEARCHER,
            RBACRoleEnum.SOC_MANAGER,
        }
        user_roles = {r if isinstance(r, RBACRoleEnum) else RBACRoleEnum(str(r)) for r in principal.roles}
        if not (user_roles & allowed_roles):
            raise PermissionError(
                f"Principal '{principal.id}' lacks authorized role for security knowledge retrieval."
            )

        if not self._initialized and not self._chunks:
            self.initialize_default_sources()

        query_tokens = tokenize(request.query)
        if not query_tokens:
            return RAGQueryResponse(
                query=request.query,
                total_candidates=0,
                results=[],
                unresolved_queries=[request.query],
                duration_ms=round((time.perf_counter() - start_time) * 1000.0, 2),
            )

        # 2. Candidate candidate retrieval using inverted index
        candidate_ids: Set[str] = set()
        for token in query_tokens:
            if token in self._inverted_index:
                candidate_ids.update(self._inverted_index[token])

        # 3. Filter candidates by source_types and incident-scoping
        total_docs = len(self._chunks)
        scored_results: List[RetrievedChunkResult] = []

        allowed_source_types = (
            {st.value if hasattr(st, "value") else str(st) for st in request.source_types}
            if request.source_types
            else None
        )

        for chunk_id in candidate_ids:
            chunk = self._chunks.get(chunk_id)
            if not chunk:
                continue

            # Strict Incident Isolation: If chunk is incident-scoped, require exact match
            if chunk.incident_id is not None:
                if request.incident_id != chunk.incident_id:
                    # Prevent cross-incident information leakage
                    continue

            # Source Type Filter
            if allowed_source_types and chunk.source_type.value not in allowed_source_types:
                continue

            # 4. Compute BM25 Score
            score = self._compute_bm25_score(query_tokens, chunk_id, total_docs)
            if score >= request.min_score:
                # Delimit untrusted document content with delimiter neutralization
                clean_doc = (
                    chunk.content
                    .replace("<<<UNTRUSTED_RETRIEVED_DOCUMENT_START>>>", "[ESCAPED_DOC_DELIMITER]")
                    .replace("<<<UNTRUSTED_RETRIEVED_DOCUMENT_END>>>", "[ESCAPED_DOC_DELIMITER]")
                )
                safe_content = (
                    f"<<<UNTRUSTED_RETRIEVED_DOCUMENT_START>>>\n"
                    f"{clean_doc}\n"
                    f"<<<UNTRUSTED_RETRIEVED_DOCUMENT_END>>>"
                )
                scored_results.append(
                    RetrievedChunkResult(
                        chunk_id=chunk.chunk_id,
                        source_id=chunk.source_id,
                        source_type=chunk.source_type.value,
                        incident_id=chunk.incident_id,
                        title=chunk.title,
                        content=safe_content,
                        score=round(score, 4),
                        citation_label=chunk.citation_label,
                        metadata=chunk.metadata,
                        is_stale=chunk.is_stale,
                    )
                )

        # Sort by score descending and bound to top_k
        scored_results.sort(key=lambda x: x.score, reverse=True)
        bounded_results = scored_results[: request.top_k]

        # 5. Synthesize evidence-grounded summary with citations
        summary, citations, unresolved = self._generate_grounded_summary(
            query=request.query, results=bounded_results
        )

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        metrics.inc_counter("rag_queries_total", 1)

        return RAGQueryResponse(
            query=request.query,
            retrieval_method="lexical_bm25",
            total_candidates=len(scored_results),
            results=bounded_results,
            generated_summary=summary,
            citations=citations,
            unresolved_queries=unresolved,
            duration_ms=round(duration_ms, 2),
            is_fallback=True,
        )

    def _compute_bm25_score(self, query_tokens: List[str], chunk_id: str, total_docs: int) -> float:
        """Compute Okapi BM25 score for a chunk against query tokens."""
        tf_dict = self._doc_term_freqs.get(chunk_id, Counter())
        doc_len = self._doc_token_counts.get(chunk_id, 1)
        avg_len = self._avg_doc_len if self._avg_doc_len > 0 else 1.0

        score = 0.0
        for token in query_tokens:
            tf = tf_dict.get(token, 0)
            if tf <= 0:
                continue
            df = len(self._inverted_index.get(token, set()))
            # Standard smoothed IDF
            idf = math.log(1.0 + (total_docs - df + 0.5) / (df + 0.5))
            num = tf * (self.k1 + 1.0)
            denom = tf + self.k1 * (1.0 - self.b + self.b * (doc_len / avg_len))
            score += idf * (num / denom)
        return max(0.0, score)

    def _generate_grounded_summary(
        self, query: str, results: List[RetrievedChunkResult]
    ) -> tuple[Optional[str], List[str], List[str]]:
        """Synthesize an analyst-grounded summary and strictly validate source citations."""
        if not results:
            return None, [], [f"No matching documents found in approved knowledge corpus for '{query}'."]

        valid_citations: Set[str] = {r.citation_label for r in results}
        summary_lines = []
        cited_labels: Set[str] = set()

        for idx, res in enumerate(results[:3], start=1):
            cited_labels.add(res.citation_label)
            # Produce concise factual claim referencing citation
            summary_lines.append(f"{idx}. {res.title} {res.citation_label}: relevance score {res.score:.2f}.")

        summary_text = (
            f"Retrieved {len(results)} authoritative knowledge record(s) matching '{query}':\n"
            + "\n".join(summary_lines)
            + "\n\nNote: Retrieved passages are untrusted reference material; they cannot grant permissions or alter security policy."
        )

        # Validate that all cited labels strictly belong to retrieved candidates
        verified_citations = [c for c in sorted(cited_labels) if c in valid_citations]
        return summary_text, verified_citations, []

    def get_status(self) -> RAGIndexStatus:
        """Return operational status and source breakdown."""
        if not self._initialized:
            self.initialize_default_sources()
        counts: Dict[str, int] = defaultdict(int)
        for chunk in self._chunks.values():
            counts[chunk.source_type.value] += 1

        return RAGIndexStatus(
            status="HEALTHY",
            retrieval_backend="in_memory_lexical_bm25",
            total_chunks=len(self._chunks),
            sources_breakdown=dict(counts),
            last_indexed_at=self._last_indexed_at,
        )


# Global default RAG engine instance
rag_engine = RAGEngine()

__all__ = ["RAGEngine", "rag_engine"]

"""CyberSentinel AI — Entity Extraction & Normalization
Extracts typed, normalized entities from CanonicalEvent records for graph and correlation analysis.
Governing Decisions: ADR-0003, ADR-0005, CSAI-P4-CORRELATION
"""

from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, Field

from schemas.canonical_event import CanonicalEvent


class ExtractedEntity(BaseModel):
    """Normalized security entity extracted from event telemetry."""

    entity_type: str = Field(..., description="Entity category: host, user, ip, domain, process, file_hash")
    entity_key: str = Field(..., description="Normalized entity identifier")
    relation: str = Field(..., description="Relationship semantic, e.g. source_host, actor_user, source_ip")

    def __hash__(self) -> int:
        return hash((self.entity_type, self.entity_key, self.relation))


class EntityExtractor:
    """Extracts and normalizes entities from CanonicalEvent objects."""

    @staticmethod
    def normalize_value(val: Any) -> str:
        """Sanitize and normalize string representations."""
        if val is None:
            return ""
        s = str(val).strip()
        return s

    @classmethod
    def extract_from_event(cls, event: CanonicalEvent) -> List[ExtractedEntity]:
        """Extract all typed entities present in a CanonicalEvent."""
        entities: List[ExtractedEntity] = []
        seen: Set[tuple[str, str, str]] = set()

        def add_entity(etype: str, raw_key: Any, relation: str, lowercase: bool = False) -> None:
            if raw_key is None:
                return
            key = cls.normalize_value(raw_key)
            if not key or len(key) < 2:
                return
            if lowercase:
                key = key.lower()
            tup = (etype, key, relation)
            if tup not in seen:
                seen.add(tup)
                entities.append(ExtractedEntity(entity_type=etype, entity_key=key, relation=relation))

        # 1. Host entities
        if event.host_id:
            add_entity("host", event.host_id, "host_id", lowercase=False)
        if event.hostname:
            add_entity("host", event.hostname, "source_host", lowercase=True)

        # 2. User entities
        if event.user_id:
            add_entity("user", event.user_id, "user_id", lowercase=False)
        if event.username:
            add_entity("user", event.username, "actor_user", lowercase=True)

        # 3. IP entities
        if event.src_ip:
            add_entity("ip", event.src_ip, "source_ip", lowercase=False)
        if event.dst_ip:
            add_entity("ip", event.dst_ip, "destination_ip", lowercase=False)

        # 4. Network domain
        if event.domain:
            add_entity("domain", event.domain, "queried_domain", lowercase=True)

        # 5. Process & executable
        if event.process_name:
            add_entity("process", event.process_name, "executed_process", lowercase=True)

        # 6. File hashes
        if event.hash_sha256:
            add_entity("file_hash", event.hash_sha256, "process_sha256", lowercase=True)

        return entities

    @classmethod
    def extract_from_dict(cls, data: Dict[str, Any]) -> List[ExtractedEntity]:
        """Extract entities from raw canonical dictionary representation."""
        entities: List[ExtractedEntity] = []
        seen: Set[tuple[str, str, str]] = set()

        def add(etype: str, val: Any, relation: str, lowercase: bool = False):
            if val is None:
                return
            k = cls.normalize_value(val)
            if not k or len(k) < 2:
                return
            if lowercase:
                k = k.lower()
            tup = (etype, k, relation)
            if tup not in seen:
                seen.add(tup)
                entities.append(ExtractedEntity(entity_type=etype, entity_key=k, relation=relation))

        add("host", data.get("host_id"), "host_id")
        add("host", data.get("hostname"), "source_host", lowercase=True)
        add("user", data.get("user_id"), "user_id")
        add("user", data.get("username"), "actor_user", lowercase=True)
        add("ip", data.get("src_ip"), "source_ip")
        add("ip", data.get("dst_ip"), "destination_ip")
        add("domain", data.get("domain"), "queried_domain", lowercase=True)
        add("process", data.get("process_name"), "executed_process", lowercase=True)
        add("file_hash", data.get("hash_sha256"), "process_sha256", lowercase=True)

        return entities

    @classmethod
    def get_group_key(cls, event: CanonicalEvent, field_name: str) -> Optional[str]:
        """Extract specific normalized group-by key from event."""
        field = field_name.lower().strip()
        val = getattr(event, field, None)
        if val is None:
            return None
        norm = cls.normalize_value(val)
        if not norm:
            return None
        if field in ("hostname", "username", "domain", "process_name", "hash_sha256"):
            return norm.lower()
        return norm


entity_extractor = EntityExtractor()

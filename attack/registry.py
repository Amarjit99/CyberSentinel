"""CyberSentinel AI — MITRE ATT&CK Enterprise Catalog & Mapping Service (Sprint 12)

Governing Decisions: ADR-0001, ADR-0005, Phase 12 Specification
"""

import hashlib
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from attack.models import (
    AttackCoverageSummary,
    AttackTactic,
    AttackTagMapping,
    AttackTechnique,
    MappingReport,
    TacticCoverageItem,
)
from packages.observability.metrics import metrics

# Regular expressions for explicit tag parsing
TECHNIQUE_TAG_PATTERN = re.compile(r"^(?:attack\.)?(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
TACTIC_TAG_PATTERN = re.compile(r"^(?:attack\.)?([a-z_]+)$", re.IGNORECASE)


class AttackCatalog:
    """In-memory index of authoritative MITRE ATT&CK techniques and tactics."""

    def __init__(self, catalog_path: Optional[Path] = None):
        if catalog_path is None:
            catalog_path = Path(__file__).parent / "enterprise-attack-v15.1.json"

        self.catalog_path = catalog_path
        self.version = "15.1"
        self.checksum = ""
        self._tactics: Dict[str, AttackTactic] = {}
        self._tactics_by_short_name: Dict[str, AttackTactic] = {}
        self._techniques: Dict[str, AttackTechnique] = {}
        self._load_catalog()

    def _load_catalog(self) -> None:
        """Deterministic offline load from pinned local JSON dataset."""
        if not self.catalog_path.is_file():
            raise FileNotFoundError(f"ATT&CK catalog file not found: {self.catalog_path}")

        raw_data = json.loads(self.catalog_path.read_text(encoding="utf-8"))
        self.checksum = hashlib.sha256(self.catalog_path.read_bytes()).hexdigest()
        self.version = raw_data.get("attack_version", "15.1")

        # Load tactics
        for tac in raw_data.get("tactics", []):
            item = AttackTactic(
                id=tac["id"],
                short_name=tac["short_name"].lower(),
                name=tac["name"],
                description=tac.get("description", ""),
            )
            self._tactics[item.id] = item
            self._tactics_by_short_name[item.short_name] = item

        # Load techniques
        for tech in raw_data.get("techniques", []):
            tech_item = AttackTechnique(
                id=tech["id"].upper(),
                name=tech["name"],
                description=tech.get("description", ""),
                tactics=[t.lower() for t in tech.get("tactics", [])],
                parent_id=tech.get("parent_id"),
                is_subtechnique=tech.get("is_subtechnique", False),
                platforms=tech.get("platforms", []),
                data_sources=tech.get("data_sources", []),
                url=tech.get("url", ""),
                is_deprecated=tech.get("is_deprecated", False),
                is_revoked=tech.get("is_revoked", False),
            )
            self._techniques[tech_item.id] = tech_item

    def validate(self) -> List[str]:
        """Validate pinned catalog integrity and internal references."""
        errors: List[str] = []
        if not self.version or not re.fullmatch(r"\d+\.\d+", self.version):
            errors.append("Catalog version is missing or malformed")
        if not self._tactics:
            errors.append("Catalog contains no tactics")
        if not self._techniques:
            errors.append("Catalog contains no techniques")
        for technique in self._techniques.values():
            for tactic in technique.tactics:
                if tactic not in self._tactics_by_short_name:
                    errors.append(f"{technique.id} references unknown tactic '{tactic}'")
            if technique.parent_id and technique.parent_id not in self._techniques:
                errors.append(f"{technique.id} references unknown parent '{technique.parent_id}'")
        return errors

    def metadata(self) -> Dict[str, object]:
        """Return safe release metadata for audit and upgrade verification."""
        return {
            "version": self.version,
            "checksum_sha256": self.checksum,
            "tactic_count": len(self._tactics),
            "technique_count": len(self._techniques),
            "active_technique_count": self.count_techniques(),
            "valid": not self.validate(),
        }

    def get_tactic(self, identifier: str) -> Optional[AttackTactic]:
        """Lookup tactic by ID (TA0002) or short_name (execution)."""
        clean = identifier.strip().lower()
        if clean.upper() in self._tactics:
            return self._tactics[clean.upper()]
        return self._tactics_by_short_name.get(clean)

    def list_tactics(self) -> List[AttackTactic]:
        """Return all authoritative Enterprise tactics."""
        return list(self._tactics.values())

    def get_technique(self, technique_id: str) -> Optional[AttackTechnique]:
        """Lookup technique by normalized ID, e.g. T1059.001."""
        return self._techniques.get(technique_id.strip().upper())

    def list_techniques(
        self,
        tactic: Optional[str] = None,
        platform: Optional[str] = None,
        include_deprecated: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AttackTechnique]:
        """Query and paginate techniques with optional tactic or platform filters."""
        results = []
        target_tactic = tactic.strip().lower() if tactic else None
        target_platform = platform.strip().lower() if platform else None

        for tech in self._techniques.values():
            if not include_deprecated and (tech.is_deprecated or tech.is_revoked):
                continue
            if target_tactic and target_tactic not in tech.tactics:
                continue
            if target_platform and not any(target_platform in p.lower() for p in tech.platforms):
                continue
            results.append(tech)

        results.sort(key=lambda t: t.id)
        return results[offset : offset + limit]

    def count_techniques(self, include_deprecated: bool = False) -> int:
        """Count active or total catalog techniques."""
        if include_deprecated:
            return len(self._techniques)
        return sum(1 for t in self._techniques.values() if not (t.is_deprecated or t.is_revoked))


class AttackMappingService:
    """Resolves rule tags to canonical ATT&CK records and calculates coverage."""

    def __init__(self, catalog: Optional[AttackCatalog] = None):
        self.catalog = catalog or AttackCatalog()

    def resolve_tag(self, raw_tag: str, rule_id: str, rule_type: str = "sigma") -> AttackTagMapping:
        """Parse, classify, normalize, and resolve an individual rule tag."""
        tag_clean = raw_tag.strip().lower()

        # 1. Check for Technique ID pattern (e.g. attack.t1059.001, t1110)
        tech_match = TECHNIQUE_TAG_PATTERN.match(tag_clean)
        if tech_match:
            technique_id = tech_match.group(1).upper()
            tech = self.catalog.get_technique(technique_id)
            if tech:
                if tech.is_revoked:
                    return AttackTagMapping(
                        raw_tag=raw_tag,
                        rule_id=rule_id,
                        rule_type=rule_type,
                        mapping_type="technique",
                        technique_id=tech.id,
                        technique_name=tech.name,
                        tactic=tech.tactics[0] if tech.tactics else None,
                        status="revoked",
                        diagnostic=f"Technique {tech.id} is revoked in ATT&CK v{self.catalog.version}",
                        catalog_version=self.catalog.version,
                    )
                if tech.is_deprecated:
                    return AttackTagMapping(
                        raw_tag=raw_tag,
                        rule_id=rule_id,
                        rule_type=rule_type,
                        mapping_type="technique",
                        technique_id=tech.id,
                        technique_name=tech.name,
                        tactic=tech.tactics[0] if tech.tactics else None,
                        status="deprecated",
                        diagnostic=f"Technique {tech.id} is deprecated in ATT&CK v{self.catalog.version}",
                        catalog_version=self.catalog.version,
                    )
                return AttackTagMapping(
                    raw_tag=raw_tag,
                    rule_id=rule_id,
                    rule_type=rule_type,
                    mapping_type="technique",
                    technique_id=tech.id,
                    technique_name=tech.name,
                    tactic=tech.tactics[0] if tech.tactics else None,
                    status="valid",
                    diagnostic=None,
                    catalog_version=self.catalog.version,
                )

            # Unrecognized technique ID
            metrics.inc_counter("attack_unresolved_tags_total", 1)
            return AttackTagMapping(
                raw_tag=raw_tag,
                rule_id=rule_id,
                rule_type=rule_type,
                mapping_type="technique",
                technique_id=technique_id,
                technique_name=None,
                tactic=None,
                status="unresolved",
                diagnostic=f"Technique ID {technique_id} not found in ATT&CK catalog v{self.catalog.version}",
                catalog_version=self.catalog.version,
            )

        # 2. Check for Tactic pattern (e.g. attack.execution, attack.credential_access)
        tactic_match = TACTIC_TAG_PATTERN.match(tag_clean)
        if tactic_match:
            tactic_name = tactic_match.group(1).lower()
            tac = self.catalog.get_tactic(tactic_name)
            if tac:
                return AttackTagMapping(
                    raw_tag=raw_tag,
                    rule_id=rule_id,
                    rule_type=rule_type,
                    mapping_type="tactic",
                    technique_id=None,
                    technique_name=None,
                    tactic=tac.short_name,
                    status="valid",
                    diagnostic=None,
                    catalog_version=self.catalog.version,
                )

        # 3. Unresolved generic or malformed tag
        metrics.inc_counter("attack_unresolved_tags_total", 1)
        return AttackTagMapping(
            raw_tag=raw_tag,
            rule_id=rule_id,
            rule_type=rule_type,
            mapping_type="unknown",
            technique_id=None,
            technique_name=None,
            tactic=None,
            status="unresolved",
            diagnostic=f"Tag '{raw_tag}' does not match any recognized ATT&CK technique or tactic",
            catalog_version=self.catalog.version,
        )

    def generate_mapping_report(
        self, rules: List[Tuple[str, str, List[str]]]
    ) -> MappingReport:
        """Process list of (rule_id, rule_type, tags) tuples and produce mapping report."""
        mappings: List[AttackTagMapping] = []
        valid_cnt = 0
        dep_cnt = 0
        rev_cnt = 0
        unres_cnt = 0

        for rule_id, rule_type, tags in rules:
            for tag in tags:
                mapping = self.resolve_tag(raw_tag=tag, rule_id=rule_id, rule_type=rule_type)
                mappings.append(mapping)
                if mapping.status == "valid":
                    valid_cnt += 1
                elif mapping.status == "deprecated":
                    dep_cnt += 1
                elif mapping.status == "revoked":
                    rev_cnt += 1
                else:
                    unres_cnt += 1

        return MappingReport(
            catalog_version=self.catalog.version,
            total_tags=len(mappings),
            valid_mappings=valid_cnt,
            deprecated_mappings=dep_cnt,
            revoked_mappings=rev_cnt,
            unresolved_mappings=unres_cnt,
            mappings=mappings,
        )

    def calculate_coverage(
        self, rules: List[Tuple[str, str, List[str]]]
    ) -> AttackCoverageSummary:
        """Calculate authoritative detection coverage across tactics and catalog techniques."""
        covered_techniques_by_tactic: Dict[str, Set[str]] = {
            t.short_name: set() for t in self.catalog.list_tactics()
        }
        all_covered_techniques: Set[str] = set()

        for rule_id, rule_type, tags in rules:
            for tag in tags:
                mapping = self.resolve_tag(raw_tag=tag, rule_id=rule_id, rule_type=rule_type)
                if mapping.status == "valid" and mapping.technique_id:
                    tech = self.catalog.get_technique(mapping.technique_id)
                    if tech:
                        all_covered_techniques.add(tech.id)
                        for tactic_name in tech.tactics:
                            if tactic_name in covered_techniques_by_tactic:
                                covered_techniques_by_tactic[tactic_name].add(tech.id)

        # Build tactic coverage breakdown
        tactics_coverage: List[TacticCoverageItem] = []
        for tactic_obj in self.catalog.list_tactics():
            catalog_techs_in_tactic = [
                t.id for t in self.catalog.list_techniques(tactic=tactic_obj.short_name)
            ]
            total_in_tactic = len(catalog_techs_in_tactic)
            covered_in_tactic = sorted(
                list(covered_techniques_by_tactic.get(tactic_obj.short_name, set()))
            )
            cov_ratio = (
                round(len(covered_in_tactic) / total_in_tactic, 4) if total_in_tactic > 0 else 0.0
            )

            tactics_coverage.append(
                TacticCoverageItem(
                    tactic_id=tactic_obj.id,
                    tactic_name=tactic_obj.name,
                    short_name=tactic_obj.short_name,
                    technique_count_catalog=total_in_tactic,
                    technique_count_covered=len(covered_in_tactic),
                    coverage_ratio=cov_ratio,
                    covered_technique_ids=covered_in_tactic,
                )
            )

        total_catalog = self.catalog.count_techniques(include_deprecated=False)
        overall_pct = (
            round((len(all_covered_techniques) / total_catalog) * 100, 2)
            if total_catalog > 0
            else 0.0
        )

        return AttackCoverageSummary(
            catalog_version=self.catalog.version,
            total_catalog_techniques=total_catalog,
            total_rules_evaluated=len(rules),
            unique_techniques_covered=len(all_covered_techniques),
            overall_coverage_percentage=overall_pct,
            tactics=tactics_coverage,
        )


# Global catalog and mapping service instances
attack_catalog = AttackCatalog()
attack_mapping_service = AttackMappingService(attack_catalog)

__all__ = [
    "AttackCatalog",
    "AttackMappingService",
    "attack_catalog",
    "attack_mapping_service",
]

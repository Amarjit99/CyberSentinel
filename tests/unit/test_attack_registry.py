"""CyberSentinel AI — Unit Tests: MITRE ATT&CK Registry & Mapping (Sprint 12)"""



from attack.registry import (
    AttackCatalog,
    attack_catalog,
    attack_mapping_service,
)


def test_catalog_loads_pinned_v15_dataset():
    """Verify that the pinned MITRE ATT&CK v15.1 Enterprise catalog loads deterministically."""
    catalog = AttackCatalog()
    assert catalog.version == "15.1"
    assert catalog.count_techniques(include_deprecated=False) >= 20
    assert len(catalog.list_tactics()) == 14


def test_pinned_catalog_integrity_metadata_is_valid():
    assert attack_catalog.validate() == []
    metadata = attack_catalog.metadata()
    assert metadata["version"] == "15.1"
    assert len(metadata["checksum_sha256"]) == 64
    assert metadata["valid"] is True


def test_tactic_lookup_by_id_and_short_name():
    """Verify lookup of tactics by canonical ID (TA0002) and normalized name (execution)."""
    tactic_by_id = attack_catalog.get_tactic("TA0002")
    assert tactic_by_id is not None
    assert tactic_by_id.name == "Execution"
    assert tactic_by_id.short_name == "execution"

    tactic_by_name = attack_catalog.get_tactic("execution")
    assert tactic_by_name is not None
    assert tactic_by_name.id == "TA0002"

    tactic_case_insensitive = attack_catalog.get_tactic("CREDENTIAL_ACCESS")
    assert tactic_case_insensitive is not None
    assert tactic_case_insensitive.id == "TA0006"


def test_technique_lookup_and_subtechnique_relationship():
    """Verify technique retrieval and parent-child sub-technique relationships."""
    parent = attack_catalog.get_technique("T1059")
    assert parent is not None
    assert parent.is_subtechnique is False
    assert parent.parent_id is None
    assert "execution" in parent.tactics

    subtech = attack_catalog.get_technique("T1059.001")
    assert subtech is not None
    assert subtech.is_subtechnique is True
    assert subtech.parent_id == "T1059"
    assert "PowerShell" in subtech.name


def test_tag_resolution_for_active_techniques():
    """Verify that Sigma technique tags resolve accurately to canonical catalog records."""
    mapping = attack_mapping_service.resolve_tag("attack.t1059.001", "rule-ps-01", "sigma")
    assert mapping.status == "valid"
    assert mapping.mapping_type == "technique"
    assert mapping.technique_id == "T1059.001"
    assert "PowerShell" in (mapping.technique_name or "")
    assert mapping.tactic == "execution"
    assert mapping.diagnostic is None

    # Technique without subtechnique
    mapping_root = attack_mapping_service.resolve_tag("attack.t1110", "rule-brute-01", "sigma")
    assert mapping_root.status == "valid"
    assert mapping_root.technique_id == "T1110"
    assert mapping_root.technique_name == "Brute Force"
    assert mapping_root.tactic == "credential_access"


def test_tag_resolution_for_tactics():
    """Verify that tactic tags (e.g. attack.execution) are distinguished from technique tags."""
    mapping = attack_mapping_service.resolve_tag("attack.execution", "rule-ps-01", "sigma")
    assert mapping.status == "valid"
    assert mapping.mapping_type == "tactic"
    assert mapping.technique_id is None
    assert mapping.tactic == "execution"


def test_tag_resolution_for_deprecated_and_revoked_techniques():
    """Verify that deprecated and revoked technique tags are flagged explicitly with diagnostics."""
    mapping = attack_mapping_service.resolve_tag("attack.t1086", "rule-old-01", "sigma")
    assert mapping.status in ("deprecated", "revoked")
    assert mapping.technique_id == "T1086"
    assert mapping.diagnostic is not None
    assert "revoked" in mapping.diagnostic.lower() or "deprecated" in mapping.diagnostic.lower()


def test_tag_resolution_for_unrecognized_identifiers():
    """Verify that unknown technique IDs are retained as unresolved rather than silently discarded."""
    mapping = attack_mapping_service.resolve_tag("attack.t9999.001", "rule-unknown", "sigma")
    assert mapping.status == "unresolved"
    assert mapping.mapping_type == "technique"
    assert mapping.technique_id == "T9999.001"
    assert mapping.diagnostic is not None
    assert "not found" in mapping.diagnostic.lower()


def test_tag_resolution_for_malformed_tags():
    """Verify handling of completely invalid tag strings."""
    mapping = attack_mapping_service.resolve_tag("not_a_valid_tag", "rule-malformed", "sigma")
    assert mapping.status == "unresolved"
    assert mapping.mapping_type == "unknown"


def test_mapping_report_and_coverage_calculation():
    """Verify mapping report compilation and platform coverage calculation."""
    sample_rules = [
        ("r1", "sigma", ["attack.t1059.001", "attack.execution"]),
        ("r2", "sigma", ["attack.t1110", "attack.credential_access"]),
        ("r3", "correlation", ["attack.t1033", "attack.t9999"]),
    ]
    report = attack_mapping_service.generate_mapping_report(sample_rules)
    assert report.total_tags == 6
    assert report.valid_mappings == 5
    assert report.unresolved_mappings == 1

    coverage = attack_mapping_service.calculate_coverage(sample_rules)
    assert coverage.total_rules_evaluated == 3
    assert coverage.unique_techniques_covered == 3  # T1059.001, T1110, T1033
    assert coverage.overall_coverage_percentage > 0.0

    # Verify tactic breakdown has execution and credential_access covered
    exec_tactic = next(t for t in coverage.tactics if t.short_name == "execution")
    assert exec_tactic.technique_count_covered >= 1
    assert "T1059.001" in exec_tactic.covered_technique_ids

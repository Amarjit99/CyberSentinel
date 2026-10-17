"""CyberSentinel AI — Repository Layout & Modular Monolith Boundary Tests"""

from pathlib import Path

from packages.schemas import CanonicalEvent as PackageCanonicalEvent
from schemas.canonical_event import CanonicalEvent as CoreCanonicalEvent


def test_top_level_directories_exist():
    """Verify that all agreed top-level architectural directories exist."""
    required_dirs = [
        "apps",
        "services",
        "packages",
        "rules",
        "attack",
        "playbooks",
        "datasets",
        "scenarios",
        "benchmarks",
        "infrastructure",
        "tests",
        "docs",
        "scripts",
    ]
    for d in required_dirs:
        p = Path(d)
        assert p.is_dir(), f"Required top-level directory missing: {d}"


def test_domain_services_boundaries_exist():
    """Verify all 11 modular monolith service boundaries exist under services/."""
    required_services = [
        "ingestion",
        "normalization",
        "detection",
        "correlation",
        "incidents",
        "threat_intel",
        "evidence",
        "agents",
        "risk",
        "response",
        "reporting",
        "persistence",
    ]
    for svc in required_services:
        p = Path("services") / svc
        assert p.is_dir(), f"Missing domain service directory: services/{svc}"
        init_file = p / "__init__.py"
        assert init_file.is_file(), f"Missing __init__.py in services/{svc}"


def test_packages_boundaries_exist():
    """Verify shared packages boundaries exist under packages/."""
    required_packages = ["schemas", "auth", "policy", "observability", "common"]
    for pkg in required_packages:
        p = Path("packages") / pkg
        assert p.is_dir(), f"Missing package directory: packages/{pkg}"
        init_file = p / "__init__.py"
        assert init_file.is_file(), f"Missing __init__.py in packages/{pkg}"


def test_package_schemas_reexports_canonical_models_without_duplication():
    """Verify packages.schemas provides identical object identity as schemas.canonical_event."""
    assert PackageCanonicalEvent is CoreCanonicalEvent, (
        "packages.schemas.CanonicalEvent must re-export the single canonical model"
    )


def test_compose_files_exist_and_match():
    """Verify compose.yaml and docker-compose.yml exist and contain valid service definitions."""
    p_compose = Path("compose.yaml")
    p_docker_compose = Path("docker-compose.yml")
    assert p_compose.is_file(), "compose.yaml must exist as canonical Compose v2 file"
    assert p_docker_compose.is_file(), (
        "docker-compose.yml must be preserved for legacy compatibility"
    )


def test_makefile_exists():
    """Verify Makefile exists with standard targets."""
    p_make = Path("Makefile")
    assert p_make.is_file(), "Makefile must exist"
    content = p_make.read_text(encoding="utf-8")
    for target in ["help:", "lint:", "typecheck:", "test:", "check:"]:
        assert target in content, f"Makefile missing required target: {target}"

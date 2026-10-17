"""Unit tests for Controlled Threat Hunting Service (Sprint 18)
Governing Decisions: ADR-0001, ADR-0002, ADR-0005, Phase 18 Specification
"""

from datetime import datetime, timezone
from typing import Generator

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from packages.auth import Principal, RBACRoleEnum
from services.hunting.models import HuntJobRequest, HuntTypeEnum
from services.hunting.service import ThreatHuntingService
from services.persistence.models import (
    Base,
    Detection,
    EventMetadata,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        # Seed 6 failed authentication events
        for i in range(6):
            ev = EventMetadata(
                id=f"ev-auth-{i}",
                source_id="auth-collector",
                event_time=utc_now(),
                schema_version="1.0.0",
                raw_ref=f"raw-{i}",
                checksum=f"sha256:auth-{i}",
                classification="auth_failed",
            )
            session.add(ev)

        # Seed detection for suspicious PowerShell
        det = Detection(
            id="det-proc-1",
            rule_id="proc_powershell_download",
            rule_version="1.0.0",
            severity="high",
            first_seen=utc_now(),
            last_seen=utc_now(),
            status="NEW",
        )
        session.add(det)
        session.commit()
        yield session


@pytest.fixture
def hunter_principal() -> Principal:
    return Principal(id="hunter-1", name="Threat Hunter", roles=[RBACRoleEnum.THREAT_HUNTER])


@pytest.fixture
def viewer_principal() -> Principal:
    return Principal(id="viewer-1", name="Viewer", roles=[RBACRoleEnum.VIEWER])


def test_hunt_brute_force_auth_detects_activity(
    db_session: Session, hunter_principal: Principal
):
    """Verify brute force hunt detects failed authentication events exceeding threshold."""
    service = ThreatHuntingService()
    req = HuntJobRequest(
        hunt_type=HuntTypeEnum.BRUTE_FORCE_AUTH,
        time_window_minutes=60,
        threshold=5,
    )

    status = service.launch_hunt(db_session, req, hunter_principal)

    assert status.state == "COMPLETED"
    assert status.matched_events_count >= 6
    assert len(status.findings) >= 1

    finding = status.findings[0]
    assert finding.attack_technique == "T1110"
    assert "Authentication Brute Force" in finding.title
    assert finding.severity in ["medium", "high"]


def test_hunt_suspicious_process_execution(
    db_session: Session, hunter_principal: Principal
):
    """Verify hunting for suspicious processes detects PowerShell download detection."""
    service = ThreatHuntingService()
    req = HuntJobRequest(
        hunt_type=HuntTypeEnum.SUSPICIOUS_PROCESS,
        time_window_minutes=60,
        threshold=1,
    )

    status = service.launch_hunt(db_session, req, hunter_principal)

    assert status.state == "COMPLETED"
    assert status.matched_events_count >= 1
    assert len(status.findings) >= 1
    assert status.findings[0].attack_technique == "T1059.001"


def test_hunt_telemetry_missing_records_coverage_gap(
    db_session: Session, hunter_principal: Principal
):
    """Verify that when telemetry is absent, an explicit coverage gap is logged without claiming benign."""
    service = ThreatHuntingService()
    req = HuntJobRequest(
        hunt_type=HuntTypeEnum.DNS_BEACONING,
        time_window_minutes=60,
        threshold=1,
    )

    status = service.launch_hunt(db_session, req, hunter_principal)

    assert status.state == "COMPLETED"
    assert len(status.findings) == 0
    # Must report that DNS telemetry is unobserved
    assert len(status.coverage_gaps) >= 1
    assert any("dns" in g.lower() for g in status.coverage_gaps)

    # Must include uncertainty note stating lack of match is not proof of safety
    assert any("does not prove" in u.lower() for u in status.uncertainty_notes)


def test_hunt_attack_technique_informed_search(
    db_session: Session, hunter_principal: Principal
):
    """Verify ATT&CK-informed hunt query matches mapped detection rules."""
    service = ThreatHuntingService()
    req = HuntJobRequest(
        hunt_type=HuntTypeEnum.ATTACK_TECHNIQUE,
        technique_id="T1059.001",
        time_window_minutes=60,
        threshold=1,
    )

    status = service.launch_hunt(db_session, req, hunter_principal)
    assert status.state == "COMPLETED"
    assert status.matched_events_count >= 1
    assert len(status.findings) >= 1
    assert status.findings[0].attack_technique == "T1059.001"


def test_hunt_rbac_denial(db_session: Session, viewer_principal: Principal):
    """Verify unauthorized principal (VIEWER) cannot execute threat hunts."""
    service = ThreatHuntingService()
    req = HuntJobRequest(
        hunt_type=HuntTypeEnum.BRUTE_FORCE_AUTH,
        time_window_minutes=60,
    )

    with pytest.raises(PermissionError, match="lacks authorized role"):
        service.launch_hunt(db_session, req, viewer_principal)

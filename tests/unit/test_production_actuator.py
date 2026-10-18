"""Unit tests for production containment actuators and live response execution."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from schemas.enums import ResponseRiskTierEnum
from services.persistence.models import Base, ResponseProposal
from services.response.actuators import ProductionActuator, WebhookContainmentActuator
from services.response.manager import ResponseManager
from services.response.models import ExecuteActionRequest, ProposalStateEnum
from services.response.policy import compute_payload_hash


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()
    engine.dispose()


def test_webhook_containment_actuator_dry_run():
    actuator = WebhookContainmentActuator(endpoint_url=None)
    res = actuator.execute_action(
        action_type="isolate_host",
        target_entity="prod-db-01",
        action_payload={"reason": "Active beaconing detected"},
    )
    assert res["success"] is True
    assert res["action_type"] == "isolate_host"
    assert res["target_entity"] == "prod-db-01"
    assert "MOCK_ACTUATION_SUCCESS" in res["status"]


def test_response_manager_live_vs_disabled(db_session):
    # 1. Disabled manager (default safety invariant)
    disabled_mgr = ResponseManager(live_response_disabled=True)
    h = compute_payload_hash({})
    proposal = ResponseProposal(
        id="prop-live-test-1",
        incident_id="inc-test-1",
        action_type="isolate_host",
        action_payload_hash=h,
        risk=ResponseRiskTierEnum.TIER_1.value,
        state=ProposalStateEnum.APPROVED.value,
        created_by="analyst-1",
        created_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db_session.add(proposal)
    db_session.commit()

    # Executing live on disabled manager -> BLOCKED_SAFETY
    req = ExecuteActionRequest(
        dry_run=False,
        target_environment="production",
        target_entity="prod-db-01",
        action_payload={},
    )
    res_blocked = disabled_mgr.execute_action("prop-live-test-1", req, "analyst-1", db_session)
    assert res_blocked["state"] == ProposalStateEnum.BLOCKED_SAFETY.value

    # 2. Enabled manager with production actuator
    enabled_mgr = ResponseManager(
        live_response_disabled=False,
        production_actuator=ProductionActuator(),
    )
    proposal2 = ResponseProposal(
        id="prop-live-test-2",
        incident_id="inc-test-2",
        action_type="isolate_host",
        action_payload_hash=h,
        risk=ResponseRiskTierEnum.TIER_1.value,
        state=ProposalStateEnum.APPROVED.value,
        created_by="analyst-1",
        created_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db_session.add(proposal2)
    db_session.commit()

    req2 = ExecuteActionRequest(
        dry_run=False,
        target_environment="production",
        target_entity="prod-db-01",
        action_payload={},
    )
    res_live = enabled_mgr.execute_action("prop-live-test-2", req2, "analyst-1", db_session)
    assert res_live["state"] == ProposalStateEnum.SUCCEEDED.value
    assert "actuator_details" in res_live["result"]

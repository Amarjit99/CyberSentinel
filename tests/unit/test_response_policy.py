"""CyberSentinel AI — Response Policy & Catalogue Unit Tests (ADR-0006)

Verifies safe action catalogue integrity, risk-tier policy mapping,
payload hash generation, separation of duties, and playbook generation.
"""

from datetime import datetime, timedelta, timezone

from packages.policy import evaluate_action_policy
from schemas.enums import IncidentStateEnum, RBACRoleEnum, ResponseRiskTierEnum
from services.persistence.models import Approval, Incident, ResponseProposal, User
from services.response.catalogue import (
    get_action_template,
    list_action_catalogue,
    validate_action_invocation,
)
from services.response.generator import PlaybookGenerator
from services.response.models import (
    ApprovalDecisionEnum,
    CreateProposalRequest,
    SubmitApprovalRequest,
)
from services.response.policy import (
    PolicyOutcomeEnum,
    compute_payload_hash,
    evaluate_proposal_policy,
    validate_approval_submission,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def test_action_catalogue_contains_expected_templates():
    """Verify safe action catalogue is bounded and covers Tiers 0 to 3."""
    catalogue = list_action_catalogue()
    assert len(catalogue) >= 10

    tier_counts = {tier: 0 for tier in ResponseRiskTierEnum}
    for template in catalogue:
        tier_counts[template.risk_tier] += 1
        assert template.action_type
        assert template.name
        assert template.description
        assert len(template.allowed_target_types) > 0
        assert template.rollback_description

    assert tier_counts[ResponseRiskTierEnum.TIER_0] >= 3
    assert tier_counts[ResponseRiskTierEnum.TIER_1] >= 2
    assert tier_counts[ResponseRiskTierEnum.TIER_2] >= 4
    assert tier_counts[ResponseRiskTierEnum.TIER_3] >= 3


def test_catalogue_validation_rejects_unknown_action():
    """Verify that arbitrary or unapproved actions are rejected."""
    is_valid, err = validate_action_invocation(
        action_type="delete_root_volume",
        target_type="host",
        parameters={"force": True},
    )
    assert not is_valid
    assert "not recognized" in err


def test_catalogue_validation_rejects_invalid_target_type():
    """Verify that an action invoked against an unsupported target type is rejected."""
    # isolate_host only permits host target
    is_valid, err = validate_action_invocation(
        action_type="isolate_host",
        target_type="ip",
        parameters={"isolation_type": "network"},
    )
    assert not is_valid
    assert "Target type 'ip' is not permitted" in err


def test_catalogue_validation_rejects_missing_required_parameter():
    """Verify that missing required template parameters causes validation failure."""
    is_valid, err = validate_action_invocation(
        action_type="block_ip",
        target_type="ip",
        parameters={"direction": "ingress"},  # Missing duration_hours
    )
    assert not is_valid
    assert "duration_hours" in err


def test_payload_hash_is_deterministic_and_canonical():
    """Verify that compute_payload_hash is key-order independent and deterministic."""
    payload_a = {"direction": "both", "duration_hours": 24, "target": "1.2.3.4"}
    payload_b = {"target": "1.2.3.4", "duration_hours": 24, "direction": "both"}

    hash_a = compute_payload_hash(payload_a)
    hash_b = compute_payload_hash(payload_b)
    assert hash_a == hash_b
    assert len(hash_a) == 64

    # Different value alters hash
    payload_c = {"target": "1.2.3.5", "duration_hours": 24, "direction": "both"}
    assert compute_payload_hash(payload_c) != hash_a


def test_adr0006_risk_tier_approval_matrix():
    """Verify ADR-0006 approval requirements across all 4 tiers."""
    t0 = evaluate_action_policy(ResponseRiskTierEnum.TIER_0)
    assert t0.required_approvals == 0
    assert len(t0.allowed_approver_roles) == 0

    t1 = evaluate_action_policy(ResponseRiskTierEnum.TIER_1)
    assert t1.required_approvals == 1
    assert RBACRoleEnum.SOC_ANALYST in t1.allowed_approver_roles

    t2 = evaluate_action_policy(ResponseRiskTierEnum.TIER_2)
    assert t2.required_approvals == 1
    assert RBACRoleEnum.SOC_MANAGER in t2.allowed_approver_roles
    assert RBACRoleEnum.SECURITY_ENGINEER in t2.allowed_approver_roles
    assert RBACRoleEnum.SOC_ANALYST not in t2.allowed_approver_roles

    t3 = evaluate_action_policy(ResponseRiskTierEnum.TIER_3)
    assert t3.required_approvals == 2
    assert RBACRoleEnum.SOC_MANAGER in t3.allowed_approver_roles
    assert RBACRoleEnum.ADMIN in t3.allowed_approver_roles
    assert RBACRoleEnum.SOC_ANALYST not in t3.allowed_approver_roles


def test_proposal_policy_denies_closed_or_benign_incident():
    """Verify proposals cannot be created for CLOSED or BENIGN incidents."""
    incident = Incident(
        id="inc-closed-01",
        title="Closed Incident",
        severity="low",
        status=IncidentStateEnum.CLOSED.value,
    )
    request = CreateProposalRequest(
        action_type="isolate_host",
        target_entity="WORKSTATION-01",
        action_payload={"isolation_type": "network"},
        reason="Test proposal",
        evidence_refs=["ev-01"],
    )
    eval_result = evaluate_proposal_policy(incident, request)
    assert not eval_result.is_eligible
    assert eval_result.outcome == PolicyOutcomeEnum.DENY
    assert any("CLOSED" in r for r in eval_result.reasons)


def test_proposal_policy_requires_evidence_for_tier2_and_tier3():
    """Verify that Tier 2 and Tier 3 proposals without evidence are denied."""
    incident = Incident(
        id="inc-active-01",
        title="Active Incident",
        severity="high",
        status=IncidentStateEnum.INVESTIGATING.value,
    )
    request_no_evidence = CreateProposalRequest(
        action_type="isolate_host",
        target_entity="WORKSTATION-01",
        action_payload={"isolation_type": "network"},
        reason="Test isolation without evidence",
        evidence_refs=[],  # Empty evidence
    )
    eval_result = evaluate_proposal_policy(incident, request_no_evidence)
    assert not eval_result.is_eligible
    assert any("require at least one supporting evidence" in r for r in eval_result.reasons)


def test_separation_of_duties_prevents_author_approval():
    """Verify that an author/creator cannot approve their own proposal."""
    now = utc_now()
    proposal = ResponseProposal(
        id="prop-01",
        incident_id="inc-01",
        action_type="isolate_host",
        action_payload_hash="hash-123",
        risk=ResponseRiskTierEnum.TIER_2.value,
        state="PENDING",
        created_by="user-analyst-bob",
        created_at=now,
        expires_at=now + timedelta(minutes=30),
    )
    author_approver = User(id="user-analyst-bob", display_name="Bob Analyst")
    author_approver.role = RBACRoleEnum.SOC_MANAGER.value

    req = SubmitApprovalRequest(
        decision=ApprovalDecisionEnum.APPROVED,
        reason="Approving my own proposal",
    )
    is_valid, err = validate_approval_submission(proposal, author_approver, req, [])
    assert not is_valid
    assert "Separation of duties violation" in err


def test_validation_rejects_expired_proposal():
    """Verify that expired proposals cannot be approved."""
    past = utc_now() - timedelta(minutes=5)
    proposal = ResponseProposal(
        id="prop-expired-01",
        incident_id="inc-01",
        action_type="isolate_host",
        action_payload_hash="hash-123",
        risk=ResponseRiskTierEnum.TIER_2.value,
        state="PENDING",
        created_by="user-alice",
        created_at=past - timedelta(minutes=30),
        expires_at=past,
    )
    approver = User(id="user-manager-charlie", display_name="Charlie Manager")
    approver.role = RBACRoleEnum.SOC_MANAGER.value

    req = SubmitApprovalRequest(
        decision=ApprovalDecisionEnum.APPROVED,
        reason="Too late approval",
    )
    is_valid, err = validate_approval_submission(proposal, approver, req, [])
    assert not is_valid
    assert "expired" in err.lower()


def test_validation_rejects_payload_drift():
    """Verify that approval with mismatched expected_payload_hash is rejected."""
    now = utc_now()
    proposal = ResponseProposal(
        id="prop-drift-01",
        incident_id="inc-01",
        action_type="isolate_host",
        action_payload_hash="canonical-hash-abc",
        risk=ResponseRiskTierEnum.TIER_2.value,
        state="PENDING",
        created_by="user-alice",
        created_at=now,
        expires_at=now + timedelta(minutes=30),
    )
    approver = User(id="user-manager-charlie", display_name="Charlie Manager")
    approver.role = RBACRoleEnum.SOC_MANAGER.value

    req = SubmitApprovalRequest(
        decision=ApprovalDecisionEnum.APPROVED,
        reason="Approved with drifted hash",
        expected_payload_hash="tampered-hash-xyz",
    )
    is_valid, err = validate_approval_submission(proposal, approver, req, [])
    assert not is_valid
    assert "Payload drift detected" in err


def test_validation_rejects_duplicate_approvals():
    """Verify that the same approver cannot approve twice."""
    now = utc_now()
    proposal = ResponseProposal(
        id="prop-dup-01",
        incident_id="inc-01",
        action_type="disable_user_account",
        action_payload_hash="hash-123",
        risk=ResponseRiskTierEnum.TIER_3.value,
        state="PENDING",
        created_by="user-alice",
        created_at=now,
        expires_at=now + timedelta(minutes=30),
    )
    approver = User(id="user-manager-charlie", display_name="Charlie Manager")
    approver.role = RBACRoleEnum.SOC_MANAGER.value

    existing = [
        Approval(
            id="app-01",
            proposal_id="prop-dup-01",
            approver_id="user-manager-charlie",
            decision="APPROVED",
            policy_version="1.0.0",
            action_payload_hash="hash-123",
            reason="First approval",
            decided_at=now,
        )
    ]

    req = SubmitApprovalRequest(
        decision=ApprovalDecisionEnum.APPROVED,
        reason="Second approval by same user",
    )
    is_valid, err = validate_approval_submission(proposal, approver, req, existing)
    assert not is_valid
    assert "already submitted a decision" in err


def test_playbook_generator_grounds_proposals_in_findings():
    """Verify PlaybookGenerator derives valid catalogue proposals from finding telemetry."""
    generator = PlaybookGenerator()

    findings = [
        {
            "id": "find-01",
            "finding_type": "detection_analysis",
            "claim": "Confirmed command and control beaconing to external IP address",
            "evidence_refs_json": ["ev-net-01"],
        },
        {
            "id": "find-02",
            "finding_type": "detection_analysis",
            "claim": "Malware persistence via scheduled task on WORKSTATION-01",
            "evidence_refs_json": ["ev-host-01"],
        },
        {
            "id": "find-03",
            "finding_type": "detection_analysis",
            "claim": "Compromised user credential with anomalous sign-in from foreign country",
            "evidence_refs_json": ["ev-auth-01"],
        },
    ]

    entities = [
        {"entity_type": "ip", "entity_key": "203.0.113.88"},
        {"entity_type": "host", "entity_key": "WORKSTATION-01"},
        {"entity_type": "user", "entity_key": "victim.user"},
    ]

    proposals = generator.generate_proposals(
        incident_id="inc-gen-01",
        incident_title="Advanced Multistage Attack",
        incident_severity="high",
        findings=findings,
        incident_entities=entities,
    )

    action_types = [p.action_type for p in proposals]
    assert "block_ip" in action_types
    assert "isolate_host" in action_types
    assert "revoke_user_session" in action_types

    # Every proposal must exist in catalogue
    for prop in proposals:
        template = get_action_template(prop.action_type)
        assert template is not None
        assert len(prop.evidence_refs) > 0

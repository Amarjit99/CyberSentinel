"""CyberSentinel AI — Security Invariants Verification Tests"""

import inspect
from pathlib import Path

import services.agents
from packages.policy import evaluate_action_policy
from schemas.canonical_event import CanonicalEvent
from schemas.enums import EventSeverityEnum, RBACRoleEnum, ResponseRiskTierEnum


def test_live_response_disabled_in_env_example():
    """Verify .env.example strictly enforces LIVE_RESPONSE_DISABLED=true."""
    env_path = Path(".env.example")
    assert env_path.exists(), ".env.example must exist"
    content = env_path.read_text(encoding="utf-8")
    assert "LIVE_RESPONSE_DISABLED=true" in content, (
        "Security Invariant: LIVE_RESPONSE_DISABLED must be set to 'true' in .env.example"
    )
    assert "DRY_RUN_DEFAULT=true" in content, (
        "Security Invariant: DRY_RUN_DEFAULT must be set to 'true' in .env.example"
    )


def test_safety_invariants_in_container_compose_files():
    """Verify compose.yaml and docker-compose.yml strictly enforce LIVE_RESPONSE_DISABLED and DRY_RUN_DEFAULT."""
    for filename in ("compose.yaml", "docker-compose.yml"):
        file_path = Path(filename)
        assert file_path.exists(), f"{filename} must exist"
        content = file_path.read_text(encoding="utf-8")
        assert 'LIVE_RESPONSE_DISABLED: "true"' in content or "LIVE_RESPONSE_DISABLED: 'true'" in content, (
            f"Security Invariant: LIVE_RESPONSE_DISABLED must be 'true' in {filename}"
        )
        assert 'DRY_RUN_DEFAULT: "true"' in content or "DRY_RUN_DEFAULT: 'true'" in content, (
            f"Security Invariant: DRY_RUN_DEFAULT must be 'true' in {filename}"
        )


def test_no_shell_tools_in_agent_service():
    """Verify services.agents exposes no free-form shell execution tool."""
    agent_members = inspect.getmembers(services.agents)
    for name, obj in agent_members:
        name_lower = name.lower()
        assert "shell" not in name_lower, f"Forbidden shell tool found in services.agents: {name}"
        assert "exec" not in name_lower or "execution" in name_lower or "executor" in name_lower, (
            f"Dangerous exec helper found in services.agents: {name}"
        )


def test_tier_3_requires_dual_authorization_and_restricted_roles():
    """Verify ADR-0006 dual authorization requirement for Tier 3 actions."""
    decision = evaluate_action_policy(ResponseRiskTierEnum.TIER_3)
    assert decision.required_approvals == 2, "Tier 3 must require 2 independent approvals"
    assert RBACRoleEnum.SOC_ANALYST not in decision.allowed_approver_roles
    assert RBACRoleEnum.THREAT_HUNTER not in decision.allowed_approver_roles
    assert RBACRoleEnum.SOC_MANAGER in decision.allowed_approver_roles
    assert RBACRoleEnum.ADMIN in decision.allowed_approver_roles


def test_redaction_pipeline_masks_passwords_and_api_keys():
    """Verify CanonicalEvent.to_redacted_dict() masks sensitive credentials."""
    event = CanonicalEvent(
        timestamp="2026-10-16T12:00:00Z",
        source_type="auth",
        source_name="okta",
        event_type="user_login",
        severity=EventSeverityEnum.HIGH,
        raw_ref="s3://raw-telemetry/auth/01.json",
        raw_event={
            "user": "alice",
            "api_key": "sec_live_123456789abcdef",
            "db_password": "supersecretpassword123",
            "authorization_header": "Bearer eyJhbGciOi...",
        },
    )
    redacted = event.to_redacted_dict()
    assert "sec_live_123456789abcdef" not in str(redacted["raw_event"])
    assert "supersecretpassword123" not in str(redacted["raw_event"])
    assert redacted["raw_event"]["api_key"] == "********"
    assert redacted["raw_event"]["db_password"] == "********"
    assert redacted["raw_event"]["authorization_header"] == "********"
    assert redacted["raw_event"]["user"] == "alice"

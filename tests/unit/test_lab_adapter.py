"""CyberSentinel AI — Unit Tests: Lab-Only Response Adapter (Sprint 20)

Verifies:
- LabTargetAllowlist pattern and CIDR matching.
- Rejection of production targets, critical infrastructure, and out-of-bounds IPs.
- Deterministic simulation of safe response actions.
- Rejection of unapproved or unknown catalogue actions.
- Rollback plan retention and simulation telemetry generation.
"""

import pytest

from services.response.lab_adapter import (
    LabExecutionResult,
    LabResponseAdapter,
    LabTargetAllowlist,
    LabTargetNotPermittedError,
    UnsupportedLabActionError,
)
from services.response.models import ActionExecutionStateEnum


@pytest.fixture
def allowlist():
    return LabTargetAllowlist()


@pytest.fixture
def lab_adapter(allowlist):
    return LabResponseAdapter(allowlist=allowlist)


# ==============================================================================
# 1. Target Allowlist Validation Tests
# ==============================================================================


def test_allowlist_permits_valid_lab_hosts(allowlist):
    """Verify that lab, test, sandbox, and workstation hostnames are permitted."""
    valid_hosts = [
        "lab-workstation-01",
        "test-srv-02",
        "sandbox-host",
        "sim-node-03",
        "web-server-lab",
        "dc.lab",
        "client.test",
        "node01.sandbox",
        "WORKSTATION-01",
        "WORKSTATION-02",
        "workstation-05-lab",
        "srv-lab-10",
    ]
    for host in valid_hosts:
        is_permitted, err = allowlist.is_target_permitted(host)
        assert is_permitted is True, f"Expected {host} to be permitted, got error: {err}"
        assert err is None


def test_allowlist_permits_valid_lab_ips(allowlist):
    """Verify that synthetic lab subnets and RFC 5737 test ranges are permitted."""
    valid_ips = [
        "192.168.100.15",
        "10.99.1.50",
        "172.16.99.100",
        "127.0.0.1",
        "198.51.100.33",
        "192.0.2.1",
        "203.0.113.254",
    ]
    for ip in valid_ips:
        is_permitted, err = allowlist.is_target_permitted(ip)
        assert is_permitted is True, f"Expected IP {ip} to be permitted, got error: {err}"
        assert err is None


def test_allowlist_permits_valid_lab_users_and_domains(allowlist):
    """Verify that mock user accounts and synthetic domains are permitted."""
    valid_entities = [
        "lab_analyst_01",
        "test_user_bob",
        "sim_operator",
        "sandbox_service",
        "alice@lab.local",
        "bob@test.local",
        "service@sandbox.internal",
        "malicious.lab",
        "c2-beacon.test",
        "lab.cyber-sentinel.local",
        "malicious-lab.org",
    ]
    for entity in valid_entities:
        is_permitted, err = allowlist.is_target_permitted(entity)
        assert is_permitted is True, f"Expected {entity} to be permitted, got error: {err}"
        assert err is None


def test_allowlist_rejects_production_targets(allowlist):
    """Verify that production, enterprise, DC, and finance indicators are strictly rejected."""
    prod_targets = [
        "PROD-DC01",
        "prod-api-server",
        "finance-db-01",
        "payroll-workstation",
        "dc01.corp",
        "dc02.enterprise.internal",
        "corp-gateway-01",
        "administrator@corp.com",
        "root@enterprise.org",
        "8.8.8.8",
        "1.1.1.1",
        "10.0.1.5",
        "172.16.1.1",
    ]
    for target in prod_targets:
        is_permitted, err = allowlist.is_target_permitted(target)
        assert is_permitted is False, f"Expected production target {target} to be rejected"
        assert err is not None
        assert "forbidden" in err.lower() or "outside" in err.lower() or "not in the approved lab" in err.lower()


# ==============================================================================
# 2. Simulation Execution Tests Across Action Catalogue
# ==============================================================================


def test_simulate_isolate_host(lab_adapter):
    """Verify deterministic simulation for isolate_host against a lab workstation."""
    result = lab_adapter.execute_simulated_action(
        action_type="isolate_host",
        target_entity="WORKSTATION-01-LAB",
        action_payload={"isolation_type": "network", "allow_soc_management": True},
    )
    assert isinstance(result, LabExecutionResult)
    assert result.simulated is True
    assert result.status == "SIMULATED_SUCCESS"
    assert result.execution_state == ActionExecutionStateEnum.SIMULATED.value
    assert "WORKSTATION-01-LAB" in result.output
    assert "br-lab-isolated" in result.output
    assert "mock_edr_agent" in result.affected_subsystems
    assert "EDR control plane" in result.rollback_plan


def test_simulate_block_ip(lab_adapter):
    """Verify deterministic simulation for block_ip against a synthetic lab IP."""
    result = lab_adapter.execute_simulated_action(
        action_type="block_ip",
        target_entity="10.99.1.50",
        action_payload={"direction": "both", "duration_hours": 12},
    )
    assert result.status == "SIMULATED_SUCCESS"
    assert "iptables -A LAB_FORWARD -s 10.99.1.50" in result.output
    assert "lab_virtual_router" in result.affected_subsystems
    assert "Flush firewall drop rule" in result.rollback_plan


def test_simulate_sinkhole_domain(lab_adapter):
    """Verify deterministic simulation for sinkhole_domain against a synthetic domain."""
    result = lab_adapter.execute_simulated_action(
        action_type="sinkhole_domain",
        target_entity="malicious-c2.lab",
        action_payload={"sinkhole_ip": "10.99.1.200"},
    )
    assert result.status == "SIMULATED_SUCCESS"
    assert "10.99.1.200" in result.output
    assert "lab_dns_resolver" in result.affected_subsystems


def test_simulate_quarantine_file(lab_adapter):
    """Verify deterministic simulation for quarantine_file."""
    result = lab_adapter.execute_simulated_action(
        action_type="quarantine_file",
        target_entity="/tmp/lab/malware.exe",
        action_payload={"host": "WORKSTATION-01-LAB"},
    )
    assert result.status == "SIMULATED_SUCCESS"
    assert "encrypted synthetic vault" in result.output
    assert "lab_sandbox_fs" in result.affected_subsystems


def test_simulate_disable_user_account(lab_adapter):
    """Verify deterministic simulation for Tier 3 disable_user_account against lab user."""
    result = lab_adapter.execute_simulated_action(
        action_type="disable_user_account",
        target_entity="lab_user_compromised",
        action_payload={"notify_manager": True},
    )
    assert result.status == "SIMULATED_SUCCESS"
    assert "DISABLED" in result.output
    assert "mock_directory_service" in result.affected_subsystems


def test_simulate_revoke_user_session(lab_adapter):
    """Verify deterministic simulation for revoke_user_session."""
    result = lab_adapter.execute_simulated_action(
        action_type="revoke_user_session",
        target_entity="test_user_bob",
        action_payload={"revoke_all": True},
    )
    assert result.status == "SIMULATED_SUCCESS"
    assert "synthetic OAuth tokens" in result.output
    assert "mock_identity_provider" in result.affected_subsystems


def test_simulate_reset_privileged_credentials(lab_adapter):
    """Verify deterministic simulation for reset_privileged_credentials."""
    result = lab_adapter.execute_simulated_action(
        action_type="reset_privileged_credentials",
        target_entity="sim_service_account",
        action_payload={"rotation_scope": "all"},
    )
    assert result.status == "SIMULATED_SUCCESS"
    assert "mock_vault_service" in result.affected_subsystems


def test_simulate_modify_firewall_rule(lab_adapter):
    """Verify deterministic simulation for modify_firewall_rule."""
    result = lab_adapter.execute_simulated_action(
        action_type="modify_firewall_rule",
        target_entity="lab-vswitch-01",
        action_payload={"rule_name": "emergency_drop", "action": "deny"},
    )
    assert result.status == "SIMULATED_SUCCESS"
    assert "lab_virtual_switch" in result.affected_subsystems


def test_simulate_isolate_lab_container(lab_adapter):
    """Verify deterministic simulation for isolate_lab_container."""
    result = lab_adapter.execute_simulated_action(
        action_type="isolate_lab_container",
        target_entity="container-lab-web01",
        action_payload={"lab_id": "lab-sec-test"},
    )
    assert result.status == "SIMULATED_SUCCESS"
    assert "docker_lab_bridge" in result.affected_subsystems


def test_simulate_route_to_honeypot(lab_adapter):
    """Verify deterministic simulation for route_to_honeypot."""
    result = lab_adapter.execute_simulated_action(
        action_type="route_to_honeypot",
        target_entity="10.99.1.75",
        action_payload={"honeypot_id": "cowrie-lab-01"},
    )
    assert result.status == "SIMULATED_SUCCESS"
    assert "cowrie-lab-01" in result.output


def test_simulate_tier_0_read_only_action(lab_adapter):
    """Verify simulation for Tier 0 action enrich_entity."""
    result = lab_adapter.execute_simulated_action(
        action_type="enrich_entity",
        target_entity="10.99.1.50",
        action_payload={"query_types": ["threat_intel", "cmdb"]},
    )
    assert result.status == "SIMULATED_SUCCESS"
    assert "read-only simulated inspection" in result.output


# ==============================================================================
# 3. Negative & Boundary Tests
# ==============================================================================


def test_reject_production_target_raises_error(lab_adapter):
    """Verify that targeting a production asset raises LabTargetNotPermittedError."""
    with pytest.raises(LabTargetNotPermittedError) as exc_info:
        lab_adapter.execute_simulated_action(
            action_type="isolate_host",
            target_entity="PROD-FINANCE-DC01",
            action_payload={"isolation_type": "network"},
        )
    assert "forbidden" in str(exc_info.value).lower() or "not in the approved lab" in str(exc_info.value).lower()


def test_reject_unknown_action_type(lab_adapter):
    """Verify that requesting an action outside the approved catalogue raises UnsupportedLabActionError."""
    with pytest.raises(UnsupportedLabActionError):
        lab_adapter.execute_simulated_action(
            action_type="wipe_hard_drive",
            target_entity="WORKSTATION-01-LAB",
            action_payload={},
        )

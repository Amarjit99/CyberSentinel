"""CyberSentinel AI — Lab-Only Response Execution Adapter (Sprint 20, ADR-0006)

Controlled simulation adapter for executing approved response actions exclusively
against isolated synthetic or lab targets.

Safety Invariants:
1. Operates only against explicitly configured synthetic or isolated lab targets.
2. Strictly rejects production targets, critical infrastructure, and unrestricted destinations.
3. Completely isolated: never invokes real containment APIs or production networks.
4. Deterministic simulation outcomes with bounded timeouts and resource limits.
5. Invariant: LIVE_RESPONSE_DISABLED=true is strictly respected.
"""

import ipaddress
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from services.response.catalogue import get_action_template
from services.response.models import ActionExecutionStateEnum

logger = logging.getLogger("cybersentinel.response.lab_adapter")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class LabAdapterError(Exception):
    """Base exception for lab execution adapter errors."""

    pass


class LabTargetNotPermittedError(LabAdapterError):
    """Raised when an action targets a production or non-lab resource."""

    pass


class UnsupportedLabActionError(LabAdapterError):
    """Raised when the requested action is not in the approved catalogue."""

    pass


class LabExecutionTimeoutError(LabAdapterError):
    """Raised when simulation exceeds bounded execution limits."""

    pass


class LabTargetAllowlist:
    """Configurable target allowlist restricting simulation exclusively to synthetic lab entities."""

    DEFAULT_ALLOWED_HOST_PATTERNS = [
        re.compile(r"^lab-", re.IGNORECASE),
        re.compile(r"^test-", re.IGNORECASE),
        re.compile(r"^sandbox-", re.IGNORECASE),
        re.compile(r"^sim-", re.IGNORECASE),
        re.compile(r"-lab$", re.IGNORECASE),
        re.compile(r"\.lab$", re.IGNORECASE),
        re.compile(r"\.test$", re.IGNORECASE),
        re.compile(r"\.local$", re.IGNORECASE),
        re.compile(r"\.sandbox$", re.IGNORECASE),
        re.compile(r"^workstation", re.IGNORECASE),
        re.compile(r"^workstation-\d+-lab$", re.IGNORECASE),
        re.compile(r"^srv-lab-\d+$", re.IGNORECASE),
    ]

    DEFAULT_ALLOWED_IP_CIDRS = [
        "192.168.100.0/24",  # Primary synthetic lab subnet
        "10.99.0.0/16",      # Isolated simulation range
        "172.16.99.0/24",    # Sandbox bridge network
        "127.0.0.0/8",       # Loopback test range
        "198.51.100.0/24",   # RFC 5737 TEST-NET-2 (lab benchmark test subnet)
        "192.0.2.0/24",      # RFC 5737 TEST-NET-1 (lab test subnet)
        "203.0.113.0/24",    # RFC 5737 TEST-NET-3 (lab test subnet)
    ]

    DEFAULT_ALLOWED_USER_PATTERNS = [
        re.compile(r"^lab_", re.IGNORECASE),
        re.compile(r"^test_", re.IGNORECASE),
        re.compile(r"^sim_", re.IGNORECASE),
        re.compile(r"^sandbox_", re.IGNORECASE),
        re.compile(r"@lab\.local$", re.IGNORECASE),
        re.compile(r"@test\.local$", re.IGNORECASE),
        re.compile(r"@sandbox\.internal$", re.IGNORECASE),
    ]

    DEFAULT_ALLOWED_DOMAIN_PATTERNS = [
        re.compile(r"\.lab$", re.IGNORECASE),
        re.compile(r"\.test$", re.IGNORECASE),
        re.compile(r"\.sandbox$", re.IGNORECASE),
        re.compile(r"\.local$", re.IGNORECASE),
        re.compile(r"^lab\.cyber-sentinel\.local$", re.IGNORECASE),
        re.compile(r"^malicious-lab\.org$", re.IGNORECASE),
    ]

    # Explicit list of production keywords that cause immediate rejection
    PRODUCTION_INDICATORS = [
        "prod",
        "production",
        "corp",
        "enterprise",
        "dc01",
        "dc02",
        "finance",
        "payroll",
        "hr-db",
        "root@",
        "administrator@",
        "ceo@",
    ]

    def __init__(
        self,
        host_patterns: Optional[List[re.Pattern]] = None,
        ip_cidrs: Optional[List[str]] = None,
        user_patterns: Optional[List[re.Pattern]] = None,
        domain_patterns: Optional[List[re.Pattern]] = None,
    ) -> None:
        self.host_patterns = host_patterns or self.DEFAULT_ALLOWED_HOST_PATTERNS
        self.ip_cidrs = ip_cidrs or self.DEFAULT_ALLOWED_IP_CIDRS
        self.user_patterns = user_patterns or self.DEFAULT_ALLOWED_USER_PATTERNS
        self.domain_patterns = domain_patterns or self.DEFAULT_ALLOWED_DOMAIN_PATTERNS

    def is_target_permitted(
        self, target_entity: str, target_type: Optional[str] = None
    ) -> Tuple[bool, Optional[str]]:
        """Validate whether a target entity is strictly within the lab allowlist."""
        cleaned = target_entity.strip()
        cleaned_lower = cleaned.lower()

        # 1. Reject explicit production markers
        for ind in self.PRODUCTION_INDICATORS:
            if ind in cleaned_lower and not ("lab" in cleaned_lower or "test" in cleaned_lower):
                return (
                    False,
                    f"Target '{target_entity}' contains production indicator '{ind}' and is strictly forbidden.",
                )

        # 2. Check if IP address
        try:
            ip_obj = ipaddress.ip_address(cleaned)
            is_allowed_ip = any(
                ip_obj in ipaddress.ip_network(cidr) for cidr in self.ip_cidrs
            )
            if is_allowed_ip:
                return True, None
            return (
                False,
                f"IP target '{target_entity}' is outside allowed synthetic lab subnets ({self.ip_cidrs}).",
            )
        except ValueError:
            pass  # Not an IP address, evaluate as hostname, domain, or user

        # 3. Check domain patterns
        if any(pat.search(cleaned) for pat in self.domain_patterns):
            return True, None

        # 4. Check user patterns
        if any(pat.search(cleaned) for pat in self.user_patterns):
            return True, None

        # 5. Check host patterns
        if any(pat.search(cleaned) for pat in self.host_patterns):
            return True, None

        # 6. Check container/isolated identifiers
        if cleaned_lower.startswith(("lab-", "container-lab-", "sim-")):
            return True, None

        # 7. Check file and sandbox path patterns
        if any(
            cleaned_lower.startswith(prefix)
            # Allowlist prefix comparison for simulated lab sandbox targets, not tempfile creation
            for prefix in ("/tmp/lab", "/var/lab", "c:\\lab", "c:/lab", "scratch/")  # nosec B108
        ):
            return True, None

        # 8. Check generic lab/sandbox/test marker if no production indicator was present
        if "lab" in cleaned_lower or "test" in cleaned_lower or "sandbox" in cleaned_lower:
            return True, None

        return (
            False,
            f"Target entity '{target_entity}' is not in the approved lab allowlist. "
            "Simulated response actions can only execute against synthetic lab targets.",
        )


class LabExecutionResult(BaseModel):
    """Deterministic result record of a simulated lab action execution."""

    simulated: bool = Field(default=True, description="Always true for lab simulation")
    adapter: str = Field(default="LabResponseAdapter", description="Identifier of the lab adapter")
    action_type: str = Field(..., description="Action type executed from safe catalogue")
    target_entity: str = Field(..., description="Synthetic lab target identifier")
    status: str = Field(..., description="Execution status: SIMULATED_SUCCESS, FAILED, REJECTED")
    execution_state: str = Field(..., description="State corresponding to ActionExecutionStateEnum")
    output: str = Field(..., description="Simulated execution output details")
    affected_subsystems: List[str] = Field(default_factory=list, description="Simulated subsystem components")
    parameters_used: Dict[str, Any] = Field(default_factory=dict, description="Action parameters utilized")
    rollback_plan: str = Field(..., description="Rollback instructions from action catalogue")
    duration_ms: float = Field(..., description="Simulated execution time in milliseconds")
    timestamp: str = Field(..., description="Execution completion timestamp in ISO format")
    safety_barrier: str = Field(
        default="LIVE_RESPONSE_DISABLED=true enforced; executed strictly within synthetic lab sandbox.",
        description="Verification that real containment was prevented",
    )


class LabResponseAdapter:
    """Approved lab-only response adapter for controlled response testing.

    Simulates the effects of response actions against isolated, synthetic targets.
    Guarantees that no real production systems, networks, or cloud resources are contacted.
    """

    MAX_SIMULATION_DURATION_SECONDS: float = 5.0

    def __init__(
        self,
        allowlist: Optional[LabTargetAllowlist] = None,
        max_duration_seconds: float = 5.0,
    ) -> None:
        self.allowlist = allowlist or LabTargetAllowlist()
        self.max_duration_seconds = max_duration_seconds

    def execute_simulated_action(
        self,
        action_type: str,
        target_entity: str,
        action_payload: Dict[str, Any],
    ) -> LabExecutionResult:
        """Execute a safe, deterministic simulation of a response action against a lab target.

        Validates:
        1. Action exists in approved safe catalogue.
        2. Target entity is permitted under the synthetic lab allowlist.
        3. Generates structured, deterministic simulation telemetry.
        """
        start_time = time.perf_counter()
        now_iso = utc_now().isoformat()

        # 1. Action Catalogue Validation
        template = get_action_template(action_type)
        if not template:
            logger.warning("Lab execution rejected: action '%s' not recognized in catalogue.", action_type)
            raise UnsupportedLabActionError(
                f"Action '{action_type}' is not recognized in approved safe catalogue."
            )

        # 2. Target Allowlist Validation
        is_permitted, err_msg = self.allowlist.is_target_permitted(target_entity)
        if not is_permitted:
            logger.warning("Lab execution blocked: target '%s' not permitted: %s", target_entity, err_msg)
            raise LabTargetNotPermittedError(err_msg)

        # 3. Simulate Action Execution deterministically
        sim_output, affected_subsystems = self._simulate_action_behavior(
            action_type=action_type,
            target_entity=target_entity,
            payload=action_payload,
        )

        duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        if duration_ms > (self.max_duration_seconds * 1000.0):
            raise LabExecutionTimeoutError(
                f"Lab simulation exceeded maximum allowed duration of {self.max_duration_seconds}s."
            )

        return LabExecutionResult(
            simulated=True,
            adapter="LabResponseAdapter",
            action_type=action_type,
            target_entity=target_entity,
            status="SIMULATED_SUCCESS",
            execution_state=ActionExecutionStateEnum.SIMULATED.value,
            output=sim_output,
            affected_subsystems=affected_subsystems,
            parameters_used=action_payload,
            rollback_plan=template.rollback_description,
            duration_ms=duration_ms,
            timestamp=now_iso,
        )

    def _simulate_action_behavior(
        self,
        action_type: str,
        target_entity: str,
        payload: Dict[str, Any],
    ) -> Tuple[str, List[str]]:
        """Produce deterministic simulation behavior for known catalogue action types."""
        if action_type == "isolate_host":
            isolation_type = payload.get("isolation_type", "network")
            allow_soc = payload.get("allow_soc_management", True)
            return (
                f"[SIMULATION] Host '{target_entity}' network interfaces logically disconnected "
                f"from lab bridge 'br-lab-isolated' (isolation_type={isolation_type}). "
                f"Mock EDR management tunnel maintained (allow_soc_management={allow_soc}). "
                "Zero production network changes committed.",
                ["lab_virtual_bridge", "mock_edr_agent", "lab_firewall_ns"],
            )

        elif action_type == "block_ip":
            direction = payload.get("direction", "both")
            duration_hours = payload.get("duration_hours", 24)
            return (
                f"[SIMULATION] Injected synthetic firewall rule into lab router: "
                f"iptables -A LAB_FORWARD -s {target_entity} -j DROP (direction={direction}, duration={duration_hours}h). "
                "Perimeter network untouched.",
                ["lab_virtual_router", "lab_iptables_ns"],
            )

        elif action_type == "sinkhole_domain":
            sinkhole_ip = payload.get("sinkhole_ip", "10.99.1.200")
            return (
                f"[SIMULATION] Overrode DNS resolution for lab domain '{target_entity}' "
                f"to synthetic sinkhole IP '{sinkhole_ip}' in mock BIND resolver. "
                "Public enterprise DNS records unmodified.",
                ["lab_dns_resolver", "mock_sinkhole_collector"],
            )

        elif action_type == "quarantine_file":
            dest_vault = payload.get("destination_vault", "/var/lab/quarantine")
            return (
                f"[SIMULATION] Artifact '{target_entity}' logically relocated to encrypted "
                f"synthetic vault '{dest_vault}'. Local file permissions set to 000. "
                "Production filesystem unaffected.",
                ["lab_sandbox_fs", "lab_quarantine_vault"],
            )

        elif action_type == "revoke_user_session":
            return (
                f"[SIMULATION] Invalidated active synthetic OAuth tokens and Kerberos tickets "
                f"for lab identity '{target_entity}' in mock Keycloak IdP. "
                "Production Active Directory untouched.",
                ["mock_identity_provider", "lab_token_cache"],
            )

        elif action_type == "disable_user_account":
            return (
                f"[SIMULATION] Account status for lab user '{target_entity}' set to DISABLED "
                "in mock directory service. Password expiry forced. "
                "Production directory services unaffected.",
                ["mock_directory_service", "lab_auth_service"],
            )

        elif action_type == "reset_privileged_credentials":
            scope = payload.get("rotation_scope", "all")
            return (
                f"[SIMULATION] Synthetic credential rotation simulated for account '{target_entity}' "
                f"(scope={scope}). Generated ephemeral mock secret in lab vault. "
                "Production secret managers untouched.",
                ["mock_vault_service", "lab_credential_manager"],
            )

        elif action_type == "modify_firewall_rule":
            rule_name = payload.get("rule_name", "lab_emergency_block")
            action = payload.get("action", "deny")
            return (
                f"[SIMULATION] Synthetic ACL rule '{rule_name}' with action='{action}' "
                f"applied to virtual lab interface '{target_entity}'. "
                "Production network hardware untouched.",
                ["lab_virtual_switch", "lab_packet_filter"],
            )

        elif action_type == "isolate_lab_container":
            lab_id = payload.get("lab_id", "lab-default")
            return (
                f"[SIMULATION] Container '{target_entity}' unlinked from docker sandbox bridge "
                f"in lab '{lab_id}'. Memory state preserved.",
                ["lab_container_runtime", "docker_lab_bridge"],
            )

        elif action_type == "route_to_honeypot":
            honeypot_id = payload.get("honeypot_id", "cowrie-lab-01")
            return (
                f"[SIMULATION] Traffic originating from '{target_entity}' routed to high-interaction "
                f"honeypot '{honeypot_id}' via synthetic NAT mapping. "
                "Production routing tables untouched.",
                ["lab_honeypot_network", "lab_nat_router"],
            )

        # Tier 0 actions
        else:
            return (
                f"[SIMULATION] Executed read-only simulated inspection for action '{action_type}' "
                f"against lab target '{target_entity}'.",
                ["lab_mock_telemetry_source"],
            )

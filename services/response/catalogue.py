"""CyberSentinel AI — Safe Response Action Catalogue (ADR-0006, Doc 21)

Provides a strictly bounded catalogue of verified response actions across
Risk Tiers 0, 1, 2, and 3. Models or users cannot introduce arbitrary actions
outside this catalogue.
"""

from typing import Any, Dict, List, Optional, Tuple

from schemas.enums import ResponseRiskTierEnum
from services.response.models import PlaybookTemplate

RESPONSE_ACTION_CATALOGUE: Dict[str, PlaybookTemplate] = {
    # --------------------------------------------------------------------------
    # Tier 0: Read-Only / Autonomous Enrichment
    # --------------------------------------------------------------------------
    "enrich_entity": PlaybookTemplate(
        action_type="enrich_entity",
        name="Enrich Target Entity",
        description="Query threat intelligence, internal CMDB, and directory for contextual metadata.",
        risk_tier=ResponseRiskTierEnum.TIER_0,
        allowed_target_types=["ip", "host", "user", "domain", "file_hash"],
        required_parameters=["query_types"],
        optional_parameters=["timeout_seconds"],
        preconditions=["Incident exists in state NEW, TRIAGE, INVESTIGATING, or CONFIRMED"],
        rollback_description="Read-only operation; no rollback needed.",
    ),
    "collect_telemetry": PlaybookTemplate(
        action_type="collect_telemetry",
        name="Collect Endpoint/Network Telemetry",
        description="Trigger read-only forensic telemetry collection or increase log verbosity.",
        risk_tier=ResponseRiskTierEnum.TIER_0,
        allowed_target_types=["host", "network_device"],
        required_parameters=["window_minutes"],
        optional_parameters=["event_types", "collector_profile"],
        preconditions=["Target host or device is registered in incident entity list"],
        rollback_description="Read-only telemetry snapshot; no rollback needed.",
    ),
    "lookup_ioc": PlaybookTemplate(
        action_type="lookup_ioc",
        name="Lookup Indicator of Compromise",
        description="Check indicator reputation and passive DNS across approved threat feeds.",
        risk_tier=ResponseRiskTierEnum.TIER_0,
        allowed_target_types=["ip", "domain", "file_hash"],
        required_parameters=["sources"],
        optional_parameters=["max_age_days"],
        preconditions=["Backing detection or evidence artifact must reference the indicator"],
        rollback_description="Read-only lookup; no state change.",
    ),
    "generate_summary_report": PlaybookTemplate(
        action_type="generate_summary_report",
        name="Generate Triage Incident Summary",
        description="Compile structured incident timeline, entity graph, and findings into markdown report.",
        risk_tier=ResponseRiskTierEnum.TIER_0,
        allowed_target_types=["incident"],
        required_parameters=["report_format"],
        optional_parameters=["include_raw_events"],
        preconditions=["Incident has at least one correlated detection or investigation finding"],
        rollback_description="Idempotent document generation; no state rollback.",
    ),
    # --------------------------------------------------------------------------
    # Tier 1: Lab-Safe / Low Risk (Isolated reversible simulation)
    # --------------------------------------------------------------------------
    "isolate_lab_container": PlaybookTemplate(
        action_type="isolate_lab_container",
        name="Isolate Lab Simulation Container",
        description="Disconnect simulated lab container from sandbox bridge network.",
        risk_tier=ResponseRiskTierEnum.TIER_1,
        allowed_target_types=["container", "host"],
        required_parameters=["lab_id"],
        optional_parameters=["preserve_memory"],
        preconditions=["Target must be tagged explicitly as lab/simulation environment"],
        rollback_description="Re-attach lab container network interface to simulation bridge.",
    ),
    "route_to_honeypot": PlaybookTemplate(
        action_type="route_to_honeypot",
        name="Route Connection to Deception Honeypot",
        description="Divert suspicious incoming traffic to an isolated high-interaction honeypot.",
        risk_tier=ResponseRiskTierEnum.TIER_1,
        allowed_target_types=["ip", "session"],
        required_parameters=["honeypot_id"],
        optional_parameters=["duration_minutes"],
        preconditions=["Traffic must originate from untrusted external zone"],
        rollback_description="Remove NAT redirection rule to restore default routing.",
    ),
    # --------------------------------------------------------------------------
    # Tier 2: Disruptive Containment (Single Human Approval Required)
    # --------------------------------------------------------------------------
    "isolate_host": PlaybookTemplate(
        action_type="isolate_host",
        name="Isolate Host from Production Network",
        description="Sever host network connectivity while maintaining EDR management tunnel.",
        risk_tier=ResponseRiskTierEnum.TIER_2,
        allowed_target_types=["host"],
        required_parameters=["isolation_type"],
        optional_parameters=["allow_soc_management", "notification_email"],
        preconditions=[
            "Host must be linked to incident entities",
            "Evidence of confirmed malware execution or unauthorized lateral movement",
        ],
        rollback_description="Remove host network isolation via EDR control plane.",
    ),
    "block_ip": PlaybookTemplate(
        action_type="block_ip",
        name="Block Malicious IP Address",
        description="Deploy perimeter or host firewall block rule for malicious source/destination IP.",
        risk_tier=ResponseRiskTierEnum.TIER_2,
        allowed_target_types=["ip"],
        required_parameters=["direction", "duration_hours"],
        optional_parameters=["threat_category", "rule_priority"],
        preconditions=[
            "IP address cannot be in RFC 1918 private ranges or essential DNS/cloud infrastructure",
            "Backed by high-confidence detection or threat intel finding",
        ],
        rollback_description="Flush firewall drop rule for specified IP address.",
    ),
    "sinkhole_domain": PlaybookTemplate(
        action_type="sinkhole_domain",
        name="Sinkhole Malicious C2 Domain",
        description="Override DNS resolution for malicious domain to internal sinkhole collector.",
        risk_tier=ResponseRiskTierEnum.TIER_2,
        allowed_target_types=["domain"],
        required_parameters=["sinkhole_ip"],
        optional_parameters=["ttl_seconds", "zone"],
        preconditions=[
            "Domain cannot match corporate apex domain or public cloud foundation services",
            "Supported by threat intel or network beacon detection evidence",
        ],
        rollback_description="Remove authoritative DNS override entry from enterprise resolvers.",
    ),
    "quarantine_file": PlaybookTemplate(
        action_type="quarantine_file",
        name="Quarantine Suspicious Artifact",
        description="Move malicious binary or script to encrypted local quarantine vault.",
        risk_tier=ResponseRiskTierEnum.TIER_2,
        allowed_target_types=["file_hash", "file_path"],
        required_parameters=["host"],
        optional_parameters=["destination_vault"],
        preconditions=[
            "File path must not be a critical Windows/Linux system protected file",
            "Target host must be active in incident scope",
        ],
        rollback_description="Restore file from encrypted quarantine vault to original path.",
    ),
    "revoke_user_session": PlaybookTemplate(
        action_type="revoke_user_session",
        name="Revoke Active User Sessions",
        description="Invalidate active SSO refresh tokens, Kerberos tickets, and web sessions.",
        risk_tier=ResponseRiskTierEnum.TIER_2,
        allowed_target_types=["user"],
        required_parameters=["revoke_all"],
        optional_parameters=["reason_code"],
        preconditions=[
            "User identity must be linked to incident scope",
            "Suspicious credential use or MFA bypass confirmed",
        ],
        rollback_description="User can re-authenticate via primary IDP with multi-factor authentication.",
    ),
    # --------------------------------------------------------------------------
    # Tier 3: Consequential / High-Impact (Dual-Human Authorization Required)
    # --------------------------------------------------------------------------
    "disable_user_account": PlaybookTemplate(
        action_type="disable_user_account",
        name="Disable Enterprise User Account",
        description="Lock out user account in identity provider and Active Directory.",
        risk_tier=ResponseRiskTierEnum.TIER_3,
        allowed_target_types=["user"],
        required_parameters=["notify_manager"],
        optional_parameters=["backup_owner", "lockout_reason"],
        preconditions=[
            "Target cannot be break-glass admin emergency account",
            "Severe compromise or confirmed insider threat evidence required",
            "Dual human authorization from SOC Manager and Admin required",
        ],
        rollback_description="Re-enable user account in Active Directory and IdP via administrative workflow.",
    ),
    "reset_privileged_credentials": PlaybookTemplate(
        action_type="reset_privileged_credentials",
        name="Emergency Privileged Credential Reset",
        description="Force password reset and invalidate all API keys/service tokens.",
        risk_tier=ResponseRiskTierEnum.TIER_3,
        allowed_target_types=["user", "service_account"],
        required_parameters=["rotation_scope"],
        optional_parameters=["temporary_lockout"],
        preconditions=[
            "Compromised service account or privileged identity verified",
            "Dual authorization from SOC Manager and Admin",
        ],
        rollback_description="Issue newly provisioned credentials through secure vault secret dispenser.",
    ),
    "modify_firewall_rule": PlaybookTemplate(
        action_type="modify_firewall_rule",
        name="Modify Perimeter Firewall Rule",
        description="Alter core ingress/egress firewall policy or access control list.",
        risk_tier=ResponseRiskTierEnum.TIER_3,
        allowed_target_types=["network_device", "ip"],
        required_parameters=["rule_name", "action"],
        optional_parameters=["permanent", "justification"],
        preconditions=[
            "Change management ticket or emergency incident declaration active",
            "Dual authorization required",
        ],
        rollback_description="Revert firewall rule change to previous configuration revision.",
    ),
    "delete_malicious_data": PlaybookTemplate(
        action_type="delete_malicious_data",
        name="Purge Malicious Payload / Staged Exfiltration",
        description="Permanently delete dropped payload or staged exfiltration archive.",
        risk_tier=ResponseRiskTierEnum.TIER_3,
        allowed_target_types=["file_hash", "storage_uri"],
        required_parameters=["storage_uri"],
        optional_parameters=["backup_first", "shred_passes"],
        preconditions=[
            "Target path verified to contain only staging malware or attacker dropped data",
            "Dual human authorization required",
        ],
        rollback_description="Restore from forensic staging backup if backup_first=true, otherwise irreversible.",
    ),
}


def get_action_template(action_type: str) -> Optional[PlaybookTemplate]:
    """Retrieve template definition for a supported response action."""
    return RESPONSE_ACTION_CATALOGUE.get(action_type)


def list_action_catalogue() -> List[PlaybookTemplate]:
    """Return all supported playbook action templates."""
    return list(RESPONSE_ACTION_CATALOGUE.values())


def validate_action_invocation(
    action_type: str,
    target_type: str,
    parameters: Dict[str, Any],
) -> Tuple[bool, Optional[str]]:
    """Verify that an action invocation is within the safe catalogue and valid.

    Returns:
        (is_valid, error_message_if_any)
    """
    template = get_action_template(action_type)
    if not template:
        return False, f"Action '{action_type}' is not recognized in the approved safe catalogue."

    normalized_target = target_type.strip().lower()
    if normalized_target not in [t.lower() for t in template.allowed_target_types]:
        return (
            False,
            f"Target type '{target_type}' is not permitted for action '{action_type}'. "
            f"Allowed types: {template.allowed_target_types}",
        )

    # Check required parameters
    for param in template.required_parameters:
        if param not in parameters:
            return (
                False,
                f"Missing required parameter '{param}' for action '{action_type}'.",
            )

    return True, None

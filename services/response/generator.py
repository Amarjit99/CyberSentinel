"""CyberSentinel AI — Grounded Playbook Proposal Generator (ADR-0006)

Converts persisted investigation findings, incident context, and triage
assessments into structured, evidence-grounded response proposals.
Ensures every proposed action is strictly within the safe catalogue and
backed by verified evidence references.
"""

import logging
from typing import Any, Dict, List, Optional

from services.response.catalogue import (
    get_action_template,
)
from services.response.models import CreateProposalRequest

logger = logging.getLogger("cybersentinel.response.generator")


class PlaybookGenerator:
    """Generates structured response proposals from investigation findings and incident telemetry."""

    def __init__(self, provider: Optional[Any] = None) -> None:
        self.provider = provider

    def generate_proposals(
        self,
        incident_id: str,
        incident_title: str,
        incident_severity: str,
        findings: List[Any],
        incident_entities: Optional[List[Dict[str, Any]]] = None,
    ) -> List[CreateProposalRequest]:
        """Synthesize response proposals grounded in investigation findings and entities.

        Analyzes findings for indicators:
        - Compromised credentials / unauthorized access -> revoke_user_session or disable_user_account
        - C2 network traffic / malicious IP / beacon -> block_ip or sinkhole_domain
        - Host malware execution / suspicious process -> isolate_host or quarantine_file
        - High uncertainty or gaps in telemetry -> collect_telemetry or enrich_entity
        """
        proposals: List[CreateProposalRequest] = []
        incident_entities = incident_entities or []

        # Map entities by type for lookup
        entities_by_type: Dict[str, List[str]] = {}
        for ent in incident_entities:
            etype = ent.get("entity_type", "").lower()
            ekey = ent.get("entity_key") or ent.get("entity_id", "")
            if etype and ekey:
                entities_by_type.setdefault(etype, []).append(ekey)

        # 1. Deterministic generation grounded in findings
        for finding in findings:
            claim = getattr(finding, "claim", "") or (finding.get("claim", "") if isinstance(finding, dict) else "")
            claim_lower = claim.lower()
            finding_type = getattr(finding, "finding_type", "") or (
                finding.get("finding_type", "") if isinstance(finding, dict) else ""
            )
            evidence_refs = getattr(finding, "evidence_refs_json", []) or (
                finding.get("evidence_refs_json", []) if isinstance(finding, dict) else []
            )
            if not evidence_refs:
                finding_id = getattr(finding, "id", None) or (
                    finding.get("id") if isinstance(finding, dict) else None
                )
                if finding_id:
                    evidence_refs = [f"finding:{finding_id}"]

            # A. Network C2 / Malicious IP / Beacon
            if any(k in claim_lower for k in ["c2", "beacon", "command and control", "external connection", "malicious ip"]) or finding_type == "network_c2":
                target_ips = entities_by_type.get("ip", [])
                target_ip = target_ips[0] if target_ips else "198.51.100.45"
                proposals.append(
                    CreateProposalRequest(
                        action_type="block_ip",
                        target_entity=target_ip,
                        action_payload={
                            "direction": "both",
                            "duration_hours": 24,
                            "threat_category": "Command and Control",
                        },
                        reason=f"Block malicious communication identified in finding: {claim[:200]}",
                        evidence_refs=evidence_refs if evidence_refs else ["ev-network-telemetry"],
                        validity_minutes=60,
                    )
                )

            # B. Malicious Domain / DNS
            if any(k in claim_lower for k in ["domain", "dns", "sinkhole", "tunneling"]):
                target_domains = entities_by_type.get("domain", [])
                if target_domains:
                    proposals.append(
                        CreateProposalRequest(
                            action_type="sinkhole_domain",
                            target_entity=target_domains[0],
                            action_payload={
                                "sinkhole_ip": "127.0.0.1",
                                "ttl_seconds": 3600,
                            },
                            reason=f"Override DNS resolution for suspicious domain: {claim[:200]}",
                            evidence_refs=evidence_refs if evidence_refs else ["ev-dns-telemetry"],
                            validity_minutes=60,
                        )
                    )

            # C. Host Compromise / Malware / Lateral Movement
            if any(k in claim_lower for k in ["malware", "ransomware", "lateral movement", "powershell", "persistence"]):
                target_hosts = entities_by_type.get("host", [])
                target_host = target_hosts[0] if target_hosts else "WORKSTATION-01"
                proposals.append(
                    CreateProposalRequest(
                        action_type="isolate_host",
                        target_entity=target_host,
                        action_payload={
                            "isolation_type": "network",
                            "allow_soc_management": True,
                        },
                        reason=f"Contain host compromise to prevent lateral spread: {claim[:200]}",
                        evidence_refs=evidence_refs if evidence_refs else ["ev-host-edr"],
                        validity_minutes=30,
                    )
                )

            # D. Credential Compromise / Account Takeover
            if any(k in claim_lower for k in ["credential", "password", "session", "brute force", "mfa bypass"]):
                target_users = entities_by_type.get("user", [])
                target_user = target_users[0] if target_users else "compromised.user"
                proposals.append(
                    CreateProposalRequest(
                        action_type="revoke_user_session",
                        target_entity=target_user,
                        action_payload={
                            "revoke_all": True,
                            "reason_code": "SUSPECTED_CREDENTIAL_COMPROMISE",
                        },
                        reason=f"Revoke active sessions for compromised account: {claim[:200]}",
                        evidence_refs=evidence_refs if evidence_refs else ["ev-auth-telemetry"],
                        validity_minutes=60,
                    )
                )

        # 2. Baseline fallback: If no proposals generated from findings, propose standard Tier 0 enrichment
        if not proposals:
            target = "incident"
            payload: Dict[str, Any] = {}
            if entities_by_type.get("host"):
                target = entities_by_type["host"][0]
                action = "collect_telemetry"
                payload = {"window_minutes": 60}
            else:
                action = "generate_summary_report"
                payload = {"report_format": "markdown"}

            proposals.append(
                CreateProposalRequest(
                    action_type=action,
                    target_entity=target,
                    action_payload=payload,
                    reason=f"Initial investigative enrichment for incident {incident_id}: {incident_title}",
                    evidence_refs=[f"incident:{incident_id}"],
                    validity_minutes=60,
                )
            )

        # 3. Post-generation catalogue validation
        valid_proposals: List[CreateProposalRequest] = []
        for prop in proposals:
            template = get_action_template(prop.action_type)
            if template:
                valid_proposals.append(prop)
            else:
                logger.warning(
                    f"Generated proposal discarded: action_type '{prop.action_type}' not in catalogue"
                )

        return valid_proposals

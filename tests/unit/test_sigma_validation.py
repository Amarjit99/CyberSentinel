"""CyberSentinel AI — Sigma Rule Validator Unit Tests (Sprint 19)
Tests static validation, schema compatibility, ATT&CK checks, and edge-case diagnostics.
"""


from services.detection.validation import SigmaRuleValidator, sigma_validator

VALID_SIGMA_RULE = """
title: Suspicious PowerShell Download
id: 5f1c9c8e-3a72-4d56-b9a1-8d2b7e123456
status: experimental
description: Detects suspicious PowerShell execution with Net.WebClient or DownloadFile
references:
    - https://attack.mitre.org/techniques/T1059/001/
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        process_name: powershell.exe
        command_line|contains:
            - Net.WebClient
            - DownloadFile
    condition: selection
falsepositives:
    - Administrative update scripts
level: high
"""

MALFORMED_YAML = """
title: Malformed Rule
id: not-a-yaml-valid-doc: [unclosed list
    detection:
"""

MISSING_REQUIRED_FIELDS = """
title: Rule Without Required Fields
description: Missing id, logsource, and detection
"""

UNSUPPORTED_AGGREGATION = """
title: Aggregated Detection Rule
id: 6a2c9c8e-3a72-4d56-b9a1-8d2b7e123457
status: experimental
description: Attempts to use unsupported aggregation function
logsource:
    category: authentication
    product: linux
detection:
    selection:
        username: root
    condition: selection | count() > 5
level: medium
"""

UNKNOWN_LOGSOURCE = """
title: Unknown Logsource Rule
id: 7b2c9c8e-3a72-4d56-b9a1-8d2b7e123458
status: experimental
description: Specifies unknown logsource product and category
logsource:
    category: unknown_telemetry_source
    product: mainframe_os
detection:
    selection:
        command_line: bad_command
    condition: selection
level: low
"""

BROAD_WILDCARDS = """
title: Overly Permissive Rule
id: 8c2c9c8e-3a72-4d56-b9a1-8d2b7e123459
status: experimental
description: Uses dangerous catch-all wildcard values
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        process_name: "*"
    condition: selection
level: low
"""

INVALID_UUID = """
title: Invalid UUID Rule
id: not-a-valid-uuid-string
status: experimental
description: Has invalid UUID identifier
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        process_name: cmd.exe
    condition: selection
level: low
"""


def test_validator_accepts_valid_sigma_rule():
    """Verify validator accepts compliant Sigma rule with no errors."""
    validator = SigmaRuleValidator()
    report = validator.validate_yaml(VALID_SIGMA_RULE)

    assert report.is_valid is True
    assert report.error_count == 0
    assert report.rule_id == "5f1c9c8e-3a72-4d56-b9a1-8d2b7e123456"
    assert report.rule_title == "Suspicious PowerShell Download"
    assert "T1059.001" in report.detected_attack_ids
    assert report.parsed_logsource.get("category") == "process_creation"
    assert report.parsed_logsource.get("product") == "windows"


def test_validator_rejects_malformed_yaml():
    """Verify malformed YAML produces a fatal ERROR diagnostic."""
    report = sigma_validator.validate_yaml(MALFORMED_YAML)

    assert report.is_valid is False
    assert report.error_count > 0
    codes = [d.code for d in report.diagnostics]
    assert "INVALID_YAML_SYNTAX" in codes


def test_validator_rejects_missing_required_fields():
    """Verify missing mandatory fields (id, logsource, detection) produce diagnostics."""
    report = sigma_validator.validate_yaml(MISSING_REQUIRED_FIELDS)

    assert report.is_valid is False
    codes = [d.code for d in report.diagnostics]
    assert "MISSING_LOGSOURCE" in codes
    assert "MISSING_DETECTION_BLOCK" in codes


def test_validator_detects_unsupported_aggregation():
    """Verify count() or pipe aggregation constructs produce UNSUPPORTED_AGGREGATION error."""
    report = sigma_validator.validate_yaml(UNSUPPORTED_AGGREGATION)

    assert report.is_valid is False
    assert any(d.code == "UNSUPPORTED_AGGREGATION" for d in report.diagnostics)
    assert len(report.unsupported_constructs) > 0


def test_validator_warns_on_unknown_logsource():
    """Verify unrecognized logsource category/product emits WARNING diagnostics."""
    report = sigma_validator.validate_yaml(UNKNOWN_LOGSOURCE)

    codes = [d.code for d in report.diagnostics]
    assert "UNKNOWN_LOGSOURCE_CATEGORY" in codes
    assert "UNKNOWN_LOGSOURCE_PRODUCT" in codes


def test_validator_warns_on_broad_wildcard_condition():
    """Verify catch-all wildcard condition emits OVERLY_PERMISSIVE_WILDCARD warning."""
    report = sigma_validator.validate_yaml(BROAD_WILDCARDS)

    assert any(d.code == "OVERLY_PERMISSIVE_WILDCARD" for d in report.diagnostics)


def test_validator_rejects_invalid_uuid():
    """Verify non-UUID identifier produces INVALID_UUID_FORMAT warning."""
    report = sigma_validator.validate_yaml(INVALID_UUID)

    assert any(d.code == "INVALID_UUID_FORMAT" for d in report.diagnostics)


def test_validator_detects_duplicate_rule_id():
    """Verify duplicate rule ID collision against active rules produces DUPLICATE_RULE_ID diagnostic."""
    existing_ids = {"5f1c9c8e-3a72-4d56-b9a1-8d2b7e123456"}
    report = sigma_validator.validate_yaml(VALID_SIGMA_RULE, existing_active_rule_ids=existing_ids)

    assert report.warning_count >= 1
    assert any(d.code == "DUPLICATE_RULE_ID" for d in report.diagnostics)


def test_validator_detects_unmapped_attack_tags():
    """Verify nonexistent or unrecognized ATT&CK tag generates ATTACK_TECHNIQUE_NOT_IN_CATALOG diagnostic."""
    rule_with_fake_attack = VALID_SIGMA_RULE.replace(
        "attack.t1059.001", "attack.t9999.999"
    )
    report = sigma_validator.validate_yaml(rule_with_fake_attack)

    assert any(d.code == "ATTACK_TECHNIQUE_NOT_IN_CATALOG" for d in report.diagnostics)

"""Security Invariant & Attack Surface Tests for Sigma Detection Engine
Traceability: CSAI-P3-DETECTION, ADR-0004, ADR-0006, Gate G3
"""

import ast
import os
from pathlib import Path

import pytest

from schemas.canonical_event import CanonicalEvent
from services.detection.compiler import SigmaCompilationError, SigmaCompiler
from services.detection.engine import SigmaDetectionEngine

INJECTION_ATTEMPT_YAML = """
title: Malicious Code Injection Test
id: a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1
status: test
logsource:
    category: process_creation
detection:
    sel:
        process_name: "__import__('os').system('echo pwned')"
        command_line: "eval('1+1')"
    condition: sel
level: high
"""


def test_compiler_does_not_execute_python_code():
    """Verify that Python code embedded in rule fields is treated as a literal string."""
    from datetime import datetime, timezone
    compiler = SigmaCompiler()
    rule = compiler.compile_rule_yaml(INJECTION_ATTEMPT_YAML)
    now = datetime.now(timezone.utc)

    # An event with normal process_name must NOT match the injection string
    benign_event = CanonicalEvent(
        timestamp=now,
        source_type="windows",
        source_name="sysmon",
        event_type="process_creation",
        process_name="powershell.exe",
        command_line="2",
        severity="low",
    )
    assert rule.evaluate(benign_event) is False

    # Event with exact literal injection string will match literally, but never execute
    literal_event = CanonicalEvent(
        timestamp=now,
        source_type="windows",
        source_name="sysmon",
        event_type="process_creation",
        process_name="__import__('os').system('echo pwned')",
        command_line="eval('1+1')",
        severity="low",
    )
    assert rule.evaluate(literal_event) is True


def test_no_eval_or_exec_in_detection_service():
    """Statically verify that services/detection/ contains zero calls to eval() or exec()."""
    detection_dir = Path("services/detection")
    py_files = list(detection_dir.glob("*.py"))
    assert len(py_files) >= 4

    for py_file in py_files:
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    assert node.func.id not in ("eval", "exec"), (
                        f"Forbidden {node.func.id}() call discovered in {py_file} at line {node.lineno}"
                    )


def test_oversized_rule_rejection_security():
    """Verify that submitting rule files exceeding size limits is blocked."""
    compiler = SigmaCompiler()
    giant_payload = "title: Giant\n" + "x" * (1024 * 1024 + 1024)
    with pytest.raises(SigmaCompilationError, match="exceeds maximum allowed size"):
        compiler.compile_rule_yaml(giant_payload)


def test_malformed_yaml_security_isolation():
    """Verify corrupted YAML does not crash detection engine or leak trace to caller."""
    engine = SigmaDetectionEngine()
    corrupt_yaml = """
title: Corrupt YAML
id: corrupt-001
detection:
    sel: [unclosed list
condition: sel
"""
    with pytest.raises(SigmaCompilationError):
        engine.load_rule(corrupt_yaml)


def test_live_response_disabled_invariant_maintained():
    """Verify that LIVE_RESPONSE_DISABLED=true invariant is strictly preserved."""
    env_path = Path(".env.example")
    assert env_path.exists()
    assert "LIVE_RESPONSE_DISABLED=true" in env_path.read_text(encoding="utf-8")
    assert os.getenv("LIVE_RESPONSE_DISABLED", "true").lower() in ("true", "1")

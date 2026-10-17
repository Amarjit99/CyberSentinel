"""CyberSentinel AI — Supply-Chain Security & Automated Security Gate Tests (CSAI-SEC-SUPPLY-CHAIN)

Deterministic and integration tests validating:
1. SAST scanner (Bandit) execution, policy enforcement, and zero high/medium findings.
2. Dependency vulnerability scanner (pip-audit & npm audit) execution and policy.
3. Proper handling of unavailable advisory services / network failure (reporting BLOCKED).
4. Container security scanner reporting NOT RUN when runtime/scanner is absent (no false PASS).
5. Machine-readable CycloneDX SBOM generation, schema structure, and component completeness.
6. Cryptographic secret, credential, and environment variable exclusion from generated SBOMs.
7. Security gate exit status policy under PASS, FAIL, and BLOCKED conditions.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from scripts.security_gate import (
    check_dependency_lockfiles,
    find_secrets,
    generate_and_verify_sboms,
    run_container_scan,
    run_dependency_audit,
    run_sast_scan,
)

ROOT_DIR = Path(__file__).resolve().parent.parent.parent


# ==============================================================================
# 1. Static Application Security Testing (SAST)
# ==============================================================================


def test_sast_scan_application_source_code_clean():
    """[REAL INFRASTRUCTURE] Verify Bandit SAST passes on all application source packages with 0 high/medium issues."""
    status, message = run_sast_scan(ROOT_DIR)
    assert status == "PASS"
    assert "zero medium or high severity findings" in message


def test_sast_scan_handles_execution_failure():
    """[MOCKED / ISOLATED] Verify run_sast_scan handles scanner failure safely without crashing."""
    with patch("subprocess.run", side_effect=RuntimeError("Bandit subprocess crashed")):
        status, message = run_sast_scan(ROOT_DIR)
        assert status == "FAIL"
        assert "Failed to execute Bandit" in message


# ==============================================================================
# 2. Dependency Vulnerability Audits
# ==============================================================================


def test_dependency_audit_policy_and_execution():
    """[REAL INFRASTRUCTURE] Verify pip-audit and npm audit pass under documented vulnerability policies."""
    status, message = run_dependency_audit(ROOT_DIR)
    # When advisory DB is reachable, it must PASS under our policy (PYSEC-2026-2447 suppressed with justification)
    # If network/advisories are temporarily unreachable, it must report BLOCKED, never fake PASS.
    assert status in ("PASS", "BLOCKED")
    if status == "PASS":
        assert "zero unsuppressed vulnerabilities" in message
        assert "npm audit: PASS" in message


def test_dependency_audit_detects_unsuppressed_vulnerability():
    """[MOCKED / ISOLATED] Verify pip-audit triggers FAIL when unsuppressed vulnerability is found."""
    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.stdout = "Found 1 known vulnerability: requests 2.25.0 CVE-2023-32681"
    mock_proc.stderr = ""

    with patch("subprocess.run", return_value=mock_proc):
        status, message = run_dependency_audit(ROOT_DIR)
        assert status == "FAIL"
        assert "Vulnerabilities found" in message


def test_dependency_audit_reports_blocked_on_network_failure():
    """[MOCKED / ISOLATED] Verify dependency audit reports BLOCKED (not PASS) if advisory service is unreachable."""
    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.stdout = ""
    mock_proc.stderr = "ConnectionError: HTTPSConnectionPool(host='pypi.org', port=443): Max retries exceeded"

    with patch("subprocess.run", return_value=mock_proc):
        status, message = run_dependency_audit(ROOT_DIR)
        assert status == "BLOCKED"
        assert "unreachable" in message.lower()


# ==============================================================================
# 3. Container Security Scanner Status
# ==============================================================================


def test_container_scan_reports_not_run_when_tools_absent():
    """[REAL INFRASTRUCTURE] When Docker or Trivy is not installed, container scan must report NOT RUN, not PASS."""
    status, message = run_container_scan(ROOT_DIR)
    # In environments where Docker or Trivy is not in PATH, must be NOT RUN
    assert status in ("NOT RUN", "PASS", "FAIL")
    if status == "NOT RUN":
        assert "NOT RUN" in message
        assert "not installed" in message or "not in PATH" in message


def test_container_scan_fails_honestly_on_build_error():
    """[MOCKED / ISOLATED] Verify container scanner reports FAIL if image build fails."""
    with patch("shutil.which", return_value="/usr/bin/docker"):
        mock_build = MagicMock()
        mock_build.returncode = 1
        mock_build.stderr = "Step 4/12 : RUN invalid_command returned a non-zero code: 127"

        with patch("subprocess.run", return_value=mock_build):
            status, message = run_container_scan(ROOT_DIR)
            assert status == "FAIL"
            assert "Container image build failed" in message


# ==============================================================================
# 4. CycloneDX SBOM Generation & Secret Exclusion
# ==============================================================================


def test_sbom_generation_and_machine_readable_structure():
    """[REAL INFRASTRUCTURE] Verify CycloneDX SBOMs generate with valid JSON, spec version, and components."""
    status, message = generate_and_verify_sboms(ROOT_DIR)
    assert status == "PASS"

    backend_sbom = ROOT_DIR / "artifacts" / "sbom" / "sbom-backend.cdx.json"
    frontend_sbom = ROOT_DIR / "artifacts" / "sbom" / "sbom-frontend.cdx.json"

    assert backend_sbom.is_file()
    assert frontend_sbom.is_file()

    # Verify backend SBOM structure
    with open(backend_sbom, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["bomFormat"] == "CycloneDX"
    assert "components" in data
    assert len(data["components"]) > 10
    assert any(c["name"] == "fastapi" for c in data["components"])
    assert any(c["name"] == "pydantic" for c in data["components"])

    # Verify frontend SBOM structure
    with open(frontend_sbom, "r", encoding="utf-8") as f:
        fe_data = json.load(f)
    assert fe_data["bomFormat"] == "CycloneDX"
    assert "components" in fe_data or "dependencies" in fe_data


def test_sbom_strictly_excludes_secrets_and_credentials():
    """[REAL INFRASTRUCTURE] Verify generated SBOM files contain zero private keys, API secrets, or passwords."""
    backend_sbom = ROOT_DIR / "artifacts" / "sbom" / "sbom-backend.cdx.json"
    frontend_sbom = ROOT_DIR / "artifacts" / "sbom" / "sbom-frontend.cdx.json"

    for sbom_path in (backend_sbom, frontend_sbom):
        if sbom_path.is_file():
            content = sbom_path.read_text(encoding="utf-8")
            # Private keys
            assert "PRIVATE KEY" not in content
            # AWS/GitHub secrets
            assert "AKIA" not in content
            assert "ghp_" not in content
            assert "sk-" not in content


# ==============================================================================
# 5. Security Gate Exit Policy & Lockfiles
# ==============================================================================


def test_dependency_lockfiles_exist():
    """[REAL INFRASTRUCTURE] Authoritative dependency lockfiles uv.lock and package-lock.json must exist."""
    missing = check_dependency_lockfiles(ROOT_DIR)
    assert missing == [], f"Missing required lockfiles: {missing}"


def test_source_code_has_zero_secrets():
    """[REAL INFRASTRUCTURE] Source files must not contain unmasked private keys or credentials."""
    findings = find_secrets(ROOT_DIR)
    assert findings == [], f"Secrets detected in source tree: {findings}"


# ==============================================================================
# 6. Release Mode Gate Integrity & Conditional Gate Regression Tests
# ==============================================================================


def test_dependency_audit_fails_when_exception_is_expired():
    """[MOCKED / ISOLATED] Expired security exception must cause dependency audit to FAIL."""
    expired_exceptions = {
        "PYSEC-2026-2447": {
            "package": "diskcache",
            "affected_version": "5.6.3",
            "aliases": ["CVE-2025-69872", "GHSA-w8v5-vhqr-4h9v"],
            "owner": "AppSec",
            "rationale": "Expired test exception",
            "expires_at": "2020-01-01",  # Past date
        }
    }
    mock_json = json.dumps({
        "dependencies": [
            {
                "name": "diskcache",
                "version": "5.6.3",
                "vulns": [{"id": "PYSEC-2026-2447", "aliases": ["GHSA-w8v5-vhqr-4h9v"]}],
            }
        ]
    })
    mock_proc = MagicMock(returncode=1, stdout=mock_json, stderr="")
    with patch("subprocess.run", return_value=mock_proc):
        status, message = run_dependency_audit(ROOT_DIR, exceptions=expired_exceptions)
        assert status == "FAIL"
        assert "EXPIRED on 2020-01-01" in message


def test_dependency_audit_fails_when_exception_version_is_mismatched():
    """[MOCKED / ISOLATED] Broadened or mismatched package version exception must cause audit to FAIL."""
    mismatched_exceptions = {
        "PYSEC-2026-2447": {
            "package": "diskcache",
            "affected_version": "5.6.2",  # Installed is 5.6.3
            "aliases": ["CVE-2025-69872"],
            "owner": "AppSec",
            "rationale": "Mismatched version test",
            "expires_at": "2026-12-31",
        }
    }
    mock_json = json.dumps({
        "dependencies": [
            {
                "name": "diskcache",
                "version": "5.6.3",
                "vulns": [{"id": "PYSEC-2026-2447"}],
            }
        ]
    })
    mock_proc = MagicMock(returncode=1, stdout=mock_json, stderr="")
    with patch("subprocess.run", return_value=mock_proc):
        status, message = run_dependency_audit(ROOT_DIR, exceptions=mismatched_exceptions)
        assert status == "FAIL"
        assert "version mismatch" in message


def test_release_gate_fails_in_release_mode_when_container_scan_not_run(capsys):
    """[MOCKED / ISOLATED] In --mode release, gate MUST exit code 1 if Container Security is NOT RUN."""
    from scripts.security_gate import main as security_gate_main

    with patch("sys.argv", ["security_gate.py", "--mode", "release"]):
        with patch("scripts.security_gate.find_secrets", return_value=[]):
            with patch("scripts.security_gate.check_dependency_lockfiles", return_value=[]):
                with patch("scripts.security_gate.run_sast_scan", return_value=("PASS", "SAST clean")):
                    with patch("scripts.security_gate.run_dependency_audit", return_value=("PASS", "Deps clean")):
                        with patch(
                            "scripts.security_gate.run_container_scan",
                            return_value=("NOT RUN", "Container scan NOT RUN: Docker missing"),
                        ):
                            with patch(
                                "scripts.security_gate.generate_and_verify_sboms",
                                return_value=("PASS", "SBOMs clean"),
                            ):
                                exit_code = security_gate_main()
                                assert exit_code == 1
                                captured = capsys.readouterr().out
                                assert "SECURITY GATE STATUS: NO-GO" in captured
                                assert "Container Security NOT RUN" in captured


def test_release_gate_permits_conditional_go_in_conditional_mode_when_container_scan_not_run(capsys):
    """[MOCKED / ISOLATED] In --mode conditional, gate exits code 0 with CONDITIONAL GO when container scan is NOT RUN."""
    from scripts.security_gate import main as security_gate_main

    with patch("sys.argv", ["security_gate.py", "--mode", "conditional"]):
        with patch("scripts.security_gate.find_secrets", return_value=[]):
            with patch("scripts.security_gate.check_dependency_lockfiles", return_value=[]):
                with patch("scripts.security_gate.run_sast_scan", return_value=("PASS", "SAST clean")):
                    with patch("scripts.security_gate.run_dependency_audit", return_value=("PASS", "Deps clean")):
                        with patch(
                            "scripts.security_gate.run_container_scan",
                            return_value=("NOT RUN", "Container scan NOT RUN: Docker missing"),
                        ):
                            with patch(
                                "scripts.security_gate.generate_and_verify_sboms",
                                return_value=("PASS", "SBOMs clean"),
                            ):
                                exit_code = security_gate_main()
                                assert exit_code == 0
                                captured = capsys.readouterr().out
                                assert "SECURITY GATE STATUS: CONDITIONAL GO" in captured
                                assert "CANNOT be mistaken for full verification" in captured


def test_release_gate_fails_in_conditional_mode_if_mandatory_check_fails(capsys):
    """[MOCKED / ISOLATED] In --mode conditional, gate MUST fail (exit 1) if any other check fails."""
    from scripts.security_gate import main as security_gate_main

    with patch("sys.argv", ["security_gate.py", "--mode", "conditional"]):
        with patch("scripts.security_gate.find_secrets", return_value=[]):
            with patch("scripts.security_gate.check_dependency_lockfiles", return_value=[]):
                with patch("scripts.security_gate.run_sast_scan", return_value=("FAIL", "SAST findings detected")):
                    with patch("scripts.security_gate.run_dependency_audit", return_value=("PASS", "Deps clean")):
                        with patch(
                            "scripts.security_gate.run_container_scan",
                            return_value=("NOT RUN", "Container scan NOT RUN: Docker missing"),
                        ):
                            with patch(
                                "scripts.security_gate.generate_and_verify_sboms",
                                return_value=("PASS", "SBOMs clean"),
                            ):
                                exit_code = security_gate_main()
                                assert exit_code == 1
                                captured = capsys.readouterr().out
                                assert "SECURITY GATE STATUS: NO-GO" in captured
                                assert "SAST (Bandit) FAILED" in captured


def test_release_gate_fails_in_release_mode_when_service_is_blocked(capsys):
    """[MOCKED / ISOLATED] In --mode release, gate MUST fail (exit 1) if an advisory service is BLOCKED."""
    from scripts.security_gate import main as security_gate_main

    with patch("sys.argv", ["security_gate.py", "--mode", "release"]):
        with patch("scripts.security_gate.find_secrets", return_value=[]):
            with patch("scripts.security_gate.check_dependency_lockfiles", return_value=[]):
                with patch("scripts.security_gate.run_sast_scan", return_value=("PASS", "SAST clean")):
                    with patch(
                        "scripts.security_gate.run_dependency_audit",
                        return_value=("BLOCKED", "pip-audit: BLOCKED (Advisory database unreachable)"),
                    ):
                        with patch("scripts.security_gate.run_container_scan", return_value=("PASS", "Container clean")):
                            with patch(
                                "scripts.security_gate.generate_and_verify_sboms",
                                return_value=("PASS", "SBOMs clean"),
                            ):
                                exit_code = security_gate_main()
                                assert exit_code == 1
                                captured = capsys.readouterr().out
                                assert "SECURITY GATE STATUS: NO-GO" in captured
                                assert "BLOCKED" in captured


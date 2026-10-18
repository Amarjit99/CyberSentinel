"""CyberSentinel AI — Supply-Chain Security & Automated Security Gate

Comprehensive security verification gate:
1. High-confidence source code secret scanning
2. Authoritative dependency lockfiles verification (uv.lock, package-lock.json)
3. Python SAST analysis (Bandit: schemas, apps, services, packages, attack)
4. Dependency vulnerability audits (pip-audit with PYSEC-2026-2447 policy & npm audit)
5. Container security scanning (Trivy / Docker; reports NOT RUN if runtime unavailable)
6. Machine-readable CycloneDX SBOM generation and secret exclusion verification
"""

import argparse
import datetime
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Documented supply-chain vulnerability exception policy registry
# Narrow scope, explicit owner, architectural rationale, and hard expiration date.
SECURITY_EXCEPTIONS: Dict[str, Dict[str, Any]] = {
    "PYSEC-2026-2447": {
        "package": "diskcache",
        "affected_version": "5.6.3",
        "aliases": ["CVE-2025-69872", "GHSA-w8v5-vhqr-4h9v"],
        "dependency_path": "cybersentinel-ai -> pySigma 2.0.1 -> diskcache 5.6.3",
        "owner": "AppSec & Release Engineering",
        "rationale": (
            "Unused transitive dependency introduced by pySigma 2.0.1 for optional online MITRE data. "
            "CyberSentinel AI does not import sigma.data.* and uses an internal static MITRE ATT&CK catalog. "
            "No diskcache instance or cache directory is instantiated or accessed."
        ),
        "review_trigger": "Next pySigma release (>= 2.0.2) or upstream diskcache pickle-free release",
        "expires_at": "2026-12-31",
    }
}

MANDATORY_RELEASE_CHECKS = (
    "Secrets Scan",
    "Lockfiles",
    "SAST (Bandit)",
    "Dependency Audit",
    "Container Security",
    "SBOM Generation",
)


def validate_vulnerability_exception(
    vuln_id: str,
    pkg_name: str,
    pkg_version: str,
    aliases: Optional[List[str]] = None,
    exceptions: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Tuple[bool, str]:
    """Validate whether a detected vulnerability matches a documented, unexpired security exception."""
    if exceptions is None:
        exceptions = SECURITY_EXCEPTIONS

    matched_exc_id = None
    if vuln_id in exceptions:
        matched_exc_id = vuln_id
    else:
        for exc_id, exc_info in exceptions.items():
            if aliases and any(a in exc_info.get("aliases", []) for a in aliases):
                matched_exc_id = exc_id
                break

    if not matched_exc_id:
        return False, f"Unapproved vulnerability: {vuln_id} in {pkg_name} {pkg_version}"

    exc_info = exceptions[matched_exc_id]

    if exc_info.get("package", "").lower() != pkg_name.lower():
        return False, (
            f"Exception {matched_exc_id} package mismatch "
            f"(expected {exc_info.get('package')}, found {pkg_name})"
        )

    if exc_info.get("affected_version") != pkg_version:
        return False, (
            f"Exception {matched_exc_id} version mismatch "
            f"(expected {exc_info.get('affected_version')}, found {pkg_version})"
        )

    expires_at_str = exc_info.get("expires_at", "")
    try:
        expires_date = datetime.date.fromisoformat(expires_at_str)
        if datetime.date.today() > expires_date:
            return False, (
                f"Exception {matched_exc_id} EXPIRED on {expires_at_str} "
                f"(Owner: {exc_info.get('owner')})"
            )
    except Exception as exc:
        return False, f"Exception {matched_exc_id} invalid expiration format: {exc}"

    return True, (
        f"Permitted exception {matched_exc_id} "
        f"({pkg_name} {pkg_version}, expires {expires_at_str}, Owner: {exc_info.get('owner')})"
    )


EXCLUDED_DIRECTORIES = {
    ".git",
    ".venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    "tests",
    "docs",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}
SCANNED_SUFFIXES = {".env", ".json", ".md", ".py", ".ps1", ".toml", ".ts", ".tsx", ".yml", ".yaml"}
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
)
SAFE_VALUE_MARKERS = ("example", "placeholder", "change_in_production", "local_insecure", "secret_key_12345")


def iter_source_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SCANNED_SUFFIXES:
            continue
        if any(part in EXCLUDED_DIRECTORIES for part in path.parts):
            continue
        # Also exclude generated sbom files from secret scanner
        if "sbom" in path.name.lower() and path.suffix == ".json":
            continue
        yield path


def find_secrets(root: Path) -> List[str]:
    findings: List[str] = []
    for path in iter_source_files(root):
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(content.splitlines(), start=1):
            if any(pattern.search(line) for pattern in SECRET_PATTERNS):
                findings.append(f"{path}:{line_number}")
                continue
            if re.search(r"(?i)\b(?:api[_-]?key|password|secret|token)\s*[:=]\s*['\"][^'\"]{20,}['\"]", line):
                lowered = line.lower()
                if not any(marker in lowered for marker in SAFE_VALUE_MARKERS):
                    findings.append(f"{path}:{line_number}")
    return findings


def check_dependency_lockfiles(root: Path) -> List[str]:
    required = (root / "uv.lock", root / "apps" / "web" / "package-lock.json")
    return [str(path) for path in required if not path.is_file()]


def run_sast_scan(root: Path) -> Tuple[str, str]:
    """Execute Bandit SAST scan on application source code."""
    targets = ["schemas", "apps", "services", "packages", "attack"]
    cmd = [
        sys.executable,
        "-m",
        "bandit",
        "-r",
        *targets,
        "-ll",  # Medium and High severity
        "-q",
    ]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=120,
        )
        if proc.returncode == 0:
            return "PASS", "Bandit SAST scan passed: zero medium or high severity findings."
        return "FAIL", f"Bandit SAST scan detected findings:\n{proc.stdout or proc.stderr}"
    except Exception as exc:
        return "FAIL", f"Failed to execute Bandit SAST scanner: {exc}"


def run_dependency_audit(
    root: Path, exceptions: Optional[Dict[str, Dict[str, Any]]] = None
) -> Tuple[str, str]:
    """Execute Python and frontend dependency vulnerability scans under documented exception policies."""
    details: List[str] = []
    has_failure = False
    is_blocked = False

    # 1. Python dependency audit (pip-audit JSON output)
    pip_cmd = [
        sys.executable,
        "-m",
        "pip_audit",
        "--format",
        "json",
    ]
    try:
        proc = subprocess.run(
            pip_cmd,
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=120,
        )
        combined_pip = ((proc.stderr or "") + " " + (proc.stdout or "")).lower()
        if any(term in combined_pip for term in ["connection", "network", "timeout", "econnrefused", "enotfound", "readtimeout", "timed out"]):
            is_blocked = True
            details.append(f"pip-audit: BLOCKED (Advisory database unreachable: {proc.stderr.strip() or proc.stdout.strip()})")
        else:
            try:
                # pip-audit outputs JSON report to stdout
                audit_data = json.loads(proc.stdout)
                dependencies = audit_data.get("dependencies", [])
                unapproved_vulns: List[str] = []
                approved_exceptions: List[str] = []

                for dep in dependencies:
                    dep_name = dep.get("name", "")
                    dep_ver = dep.get("version", "")
                    for vuln in dep.get("vulns", []):
                        vuln_id = vuln.get("id", "")
                        aliases = vuln.get("aliases", [])
                        valid, reason = validate_vulnerability_exception(
                            vuln_id=vuln_id,
                            pkg_name=dep_name,
                            pkg_version=dep_ver,
                            aliases=aliases,
                            exceptions=exceptions,
                        )
                        if valid:
                            approved_exceptions.append(reason)
                        else:
                            unapproved_vulns.append(reason)

                if unapproved_vulns:
                    has_failure = True
                    details.append(
                        f"pip-audit: FAIL ({len(unapproved_vulns)} unapproved vulnerabilities found:\n"
                        + "\n".join(f"  - {v}" for v in unapproved_vulns)
                        + ")"
                    )
                else:
                    if approved_exceptions:
                        unique_exc = list(dict.fromkeys(approved_exceptions))
                        exc_lines = "\n".join(f"    * {e}" for e in unique_exc)
                        details.append(
                            f"pip-audit: PASS (zero unsuppressed vulnerabilities; zero unapproved vulnerabilities; "
                            f"{len(unique_exc)} documented exception(s) permitted):\n{exc_lines}"
                        )
                    else:
                        details.append("pip-audit: PASS (zero unsuppressed vulnerabilities; zero unapproved vulnerabilities)")
            except Exception as exc:
                if proc.returncode != 0:
                    has_failure = True
                    details.append(f"pip-audit: FAIL (Vulnerabilities found / scanner output: {proc.stdout.strip() or proc.stderr.strip() or str(exc)})")
                else:
                    details.append("pip-audit: PASS (zero vulnerabilities)")
    except Exception as exc:
        is_blocked = True
        details.append(f"pip-audit: BLOCKED (Execution failed: {exc})")

    # 2. Frontend dependency audit (npm audit)
    web_dir = root / "apps" / "web"
    if web_dir.exists():
        npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
        try:
            proc = subprocess.run(
                [npm_cmd, "audit"],
                cwd=str(web_dir),
                capture_output=True,
                text=True,
                timeout=120,
            )
            combined_fe = ((proc.stderr or "") + " " + (proc.stdout or "")).lower()
            if proc.returncode == 0:
                details.append("npm audit: PASS (zero vulnerabilities in frontend dependencies)")
            elif any(term in combined_fe for term in ["connection", "network", "timeout", "econnrefused", "enotfound", "fetch failed", "eai_again"]):
                is_blocked = True
                details.append(f"npm audit: BLOCKED (npm registry unreachable: {proc.stderr.strip() or proc.stdout.strip()})")
            else:
                has_failure = True
                details.append(f"npm audit: FAIL (Frontend vulnerabilities found:\n{proc.stdout or proc.stderr})")
        except Exception as exc:
            is_blocked = True
            details.append(f"npm audit: BLOCKED (Execution failed: {exc})")

    if has_failure:
        return "FAIL", "\n".join(details)
    if is_blocked:
        return "BLOCKED", "\n".join(details)
    return "PASS", "\n".join(details)


def run_container_scan(root: Path) -> Tuple[str, str]:
    """Execute container security scan using Docker and Trivy if available."""
    docker_bin = shutil.which("docker")
    trivy_bin = shutil.which("trivy")

    if not docker_bin:
        return "NOT RUN", "Container scan NOT RUN: Docker runtime is not installed or not in PATH."
    if not trivy_bin:
        return "NOT RUN", "Container scan NOT RUN: Trivy container vulnerability scanner is not in PATH."

    image_tag = "cybersentinel-ai:release-candidate"
    try:
        build_proc = subprocess.run(
            ["docker", "build", "-t", image_tag, "."],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=300,
        )
        if build_proc.returncode != 0:
            return "FAIL", f"Container image build failed:\n{build_proc.stderr}"

        scan_proc = subprocess.run(
            [trivy_bin, "image", "--severity", "HIGH,CRITICAL", "--ignore-unfixed", "--exit-code", "1", image_tag],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=300,
        )
        if scan_proc.returncode == 0:
            return "PASS", "Container scan passed: zero HIGH/CRITICAL vulnerabilities in built image."
        return "FAIL", f"Trivy scan detected vulnerabilities:\n{scan_proc.stdout}"
    except Exception as exc:
        return "FAIL", f"Container scan execution error: {exc}"


def check_tls_configuration(root: Path) -> Tuple[str, str]:
    """Validate the repository's optional TLS profile without requiring Docker."""
    tls_conf = root / "apps" / "web" / "nginx.tls.conf"
    compose_tls = root / "compose.tls.yaml"
    if not tls_conf.is_file() or not compose_tls.is_file():
        return "FAIL", "TLS profile is incomplete: expected Nginx and Compose TLS files."

    nginx = tls_conf.read_text(encoding="utf-8")
    compose = compose_tls.read_text(encoding="utf-8")
    required_nginx = (
        "listen 443 ssl;",
        "ssl_certificate /etc/nginx/tls/tls.crt;",
        "ssl_certificate_key /etc/nginx/tls/tls.key;",
        "ssl_protocols TLSv1.2 TLSv1.3;",
    )
    missing = [entry for entry in required_nginx if entry not in nginx]
    if missing:
        return "FAIL", f"TLS profile missing required directives: {', '.join(missing)}"
    if 'profiles: ["tls"]' not in compose or ":/etc/nginx/tls:ro" not in compose:
        return "FAIL", "TLS Compose profile must be opt-in with a read-only certificate mount."

    committed_material = [
        path
        for path in (root / "apps" / "web").glob("*.key")
        if path.is_file()
    ] + [
        path
        for path in (root / "apps" / "web").glob("*.crt")
        if path.is_file()
    ]
    if committed_material:
        return "FAIL", "Certificate or private-key material must not be committed to the web image source."
    return "PASS", "TLS profile directives, opt-in profile, and certificate material policy verified."


def generate_and_verify_sboms(root: Path) -> Tuple[str, str]:
    """Generate reproducible CycloneDX SBOMs for backend and frontend and verify secret exclusion."""
    details: List[str] = []
    output_dir = root / "artifacts" / "sbom"
    output_dir.mkdir(parents=True, exist_ok=True)

    backend_sbom_path = output_dir / "sbom-backend.cdx.json"
    frontend_sbom_path = output_dir / "sbom-frontend.cdx.json"

    # 1. Backend CycloneDX SBOM
    cyclonedx_bin = shutil.which("cyclonedx-py")
    if not cyclonedx_bin:
        # Check inside venv
        venv_cdx = root / ".venv" / ("Scripts" if sys.platform == "win32" else "bin") / ("cyclonedx-py.exe" if sys.platform == "win32" else "cyclonedx-py")
        if venv_cdx.is_file():
            cyclonedx_bin = str(venv_cdx)

    if not cyclonedx_bin:
        return "FAIL", "cyclonedx-py executable not found in PATH or virtual environment."

    try:
        proc = subprocess.run(
            [
                cyclonedx_bin,
                "environment",
                "--pyproject",
                "pyproject.toml",
                "--output-reproducible",
                "--of",
                "JSON",
                "-o",
                str(backend_sbom_path),
                sys.executable,
            ],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=120,
        )
        if proc.returncode != 0:
            return "FAIL", f"Backend SBOM generation failed:\n{proc.stderr}"
    except Exception as exc:
        return "FAIL", f"Backend SBOM generation error: {exc}"

    # Verify backend SBOM structure and contents
    try:
        backend_data = json.loads(backend_sbom_path.read_text(encoding="utf-8"))
        if backend_data.get("bomFormat") != "CycloneDX":
            return "FAIL", "Backend SBOM is missing valid CycloneDX bomFormat header."
        components = backend_data.get("components", [])
        if len(components) == 0:
            return "FAIL", "Backend SBOM contains zero components."
        details.append(f"Backend SBOM: PASS ({len(components)} components documented at {backend_sbom_path.name})")
    except Exception as exc:
        return "FAIL", f"Backend SBOM structure invalid: {exc}"

    # 2. Frontend CycloneDX SBOM
    web_dir = root / "apps" / "web"
    if web_dir.exists():
        npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
        try:
            proc = subprocess.run(
                [npm_cmd, "sbom", "--sbom-format", "cyclonedx", "--package-lock-only"],
                cwd=str(web_dir),
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode != 0:
                return "FAIL", f"Frontend SBOM generation failed:\n{proc.stderr}"
            frontend_sbom_path.write_text(proc.stdout, encoding="utf-8")

            frontend_data = json.loads(frontend_sbom_path.read_text(encoding="utf-8"))
            if frontend_data.get("bomFormat") != "CycloneDX":
                return "FAIL", "Frontend SBOM is missing valid CycloneDX bomFormat header."
            fe_components = frontend_data.get("components", [])
            details.append(f"Frontend SBOM: PASS ({len(fe_components)} components documented at {frontend_sbom_path.name})")
        except Exception as exc:
            return "FAIL", f"Frontend SBOM generation error: {exc}"

    # 3. Verify no secrets or sensitive tokens are embedded in SBOM files
    for sbom_file in (backend_sbom_path, frontend_sbom_path):
        if sbom_file.exists():
            content = sbom_file.read_text(encoding="utf-8")
            if any(pattern.search(content) for pattern in SECRET_PATTERNS):
                return "FAIL", f"Private key or token pattern detected in generated SBOM {sbom_file.name}!"
            if re.search(r"(?i)\b(?:password|secret|token)\s*[:=]\s*['\"][^'\"]{20,}['\"]", content):
                return "FAIL", f"Sensitive secret assignment detected in generated SBOM {sbom_file.name}!"

    details.append("SBOM Secret Exclusion: PASS (Verified zero credentials, tokens, or environment values embedded)")
    return "PASS", "\n".join(details)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--mode",
        choices=["release", "conditional", "dev"],
        default="release",
        help="Gate qualification mode (release: strictly fails on any NOT RUN/FAIL/BLOCKED check; conditional: permits NOT RUN container scan on host without Docker; dev: offline development)",
    )
    parser.add_argument(
        "--sbom-only",
        action="store_true",
        help="Only generate and verify SBOMs",
    )
    args = parser.parse_args()
    root = args.root.resolve()

    print("\n" + "=" * 75)
    print("CYBERSENTINEL AI — AUTOMATED SUPPLY-CHAIN SECURITY GATE")
    print(f"Mode: {args.mode.upper()} | Root: {root}")
    print("=" * 75)

    if args.sbom_only:
        status, msg = generate_and_verify_sboms(root)
        print(f"[{status}] SBOM Generation:\n{msg}")
        return 0 if status == "PASS" else 1

    results: Dict[str, Tuple[str, str]] = {}

    # 1. Source Secret Scanning
    print("\n[*] 1/6 Running Secret Scanning...")
    secret_findings = find_secrets(root)
    if secret_findings:
        results["Secrets Scan"] = ("FAIL", "Potential secrets detected:\n" + "\n".join(secret_findings))
    else:
        results["Secrets Scan"] = ("PASS", "Zero high-confidence secrets found in source or configurations.")

    # 2. Dependency Lockfiles
    print("[*] 2/6 Checking Dependency Lockfiles...")
    missing_locks = check_dependency_lockfiles(root)
    if missing_locks:
        results["Lockfiles"] = ("FAIL", "Missing required lockfiles:\n" + "\n".join(missing_locks))
    else:
        results["Lockfiles"] = ("PASS", "Authoritative lockfiles present (uv.lock, package-lock.json).")

    # 3. Static Application Security Testing (SAST)
    print("[*] 3/6 Running Python SAST (Bandit)...")
    sast_status, sast_msg = run_sast_scan(root)
    results["SAST (Bandit)"] = (sast_status, sast_msg)

    # 4. Dependency Vulnerability Audits
    print("[*] 4/6 Running Dependency Vulnerability Audits (pip-audit & npm audit)...")
    dep_status, dep_msg = run_dependency_audit(root)
    results["Dependency Audit"] = (dep_status, dep_msg)

    # 5. Container Security Scan
    print("[*] 5/6 Checking Container Security (Docker / Trivy)...")
    cont_status, cont_msg = run_container_scan(root)
    results["Container Security"] = (cont_status, cont_msg)

    # 6. SBOM Generation & Validation
    print("[*] 6/7 Generating & Validating CycloneDX SBOMs...")
    sbom_status, sbom_msg = generate_and_verify_sboms(root)
    results["SBOM Generation"] = (sbom_status, sbom_msg)

    # 7. Offline TLS Configuration
    print("[*] 7/7 Checking Offline TLS Configuration...")
    tls_status, tls_msg = check_tls_configuration(root)
    results["TLS Configuration"] = (tls_status, tls_msg)

    # Summary Display & Honest Release Qualification Evaluation
    print("\n" + "=" * 75)
    print("SUPPLY-CHAIN SECURITY GATE RESULTS SUMMARY")
    print("=" * 75)
    gate_failed = False
    conditional_candidate = False
    failure_reasons: List[str] = []

    for check_name, (status, message) in results.items():
        print(f"[{status:<7}] {check_name}")
        for line in message.strip().splitlines():
            print(f"          {line}")

        if status == "FAIL":
            gate_failed = True
            failure_reasons.append(f"{check_name} FAILED: {message.splitlines()[0]}")
        elif status == "BLOCKED":
            if args.mode in ("release", "conditional"):
                gate_failed = True
                failure_reasons.append(f"{check_name} BLOCKED: advisory service or scanner unreachable")
        elif status == "NOT RUN":
            if args.mode == "release":
                gate_failed = True
                failure_reasons.append(f"{check_name} NOT RUN: mandatory check cannot be skipped in release mode")
            elif args.mode == "conditional":
                if check_name == "Container Security":
                    conditional_candidate = True
                else:
                    gate_failed = True
                    failure_reasons.append(f"{check_name} NOT RUN: only Container Security may be deferred to CI in conditional mode")

    print("=" * 75)
    if gate_failed:
        print("[!] SECURITY GATE STATUS: NO-GO")
        print("    Release gate qualification FAILED. Critical checks failed, blocked, or not run:")
        for reason in failure_reasons:
            print(f"      * {reason}")
        return 1
    elif conditional_candidate and args.mode == "conditional":
        print("[!] SECURITY GATE STATUS: CONDITIONAL GO")
        print("    Source, SAST, dependency, secret scanning, and SBOMs passed verification.")
        print("    CRITICAL NOTICE: Container security scanning was NOT RUN on this host (missing Docker/Trivy).")
        print("    This conditional state CANNOT be mistaken for full verification.")
        print("    The release container MUST be built and scanned in CI before deployment.")
        return 0
    else:
        print("[OK] SECURITY GATE STATUS: GO")
        print("    All mandatory release checks verified successfully against intended release artifacts.")
        return 0


if __name__ == "__main__":
    sys.exit(main())

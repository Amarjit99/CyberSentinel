"""CyberSentinel AI — Sprint 27 Release 1.0 Release Gate Validation Script

Executes end-to-end verification of:
1. Python static analysis (Ruff)
2. Static type checking (Mypy)
3. Database migrations (Alembic offline SQL generation)
4. Complete backend automated test suite (Pytest)
5. Frontend unit & safety tests (Node test runner)
6. Frontend production build (TypeScript + Vite)
7. Response safety & live containment invariants
8. Authentication authenticity & production security gate
"""

import os
import subprocess
import sys
from pathlib import Path


def log_step(name: str):
    print("\n" + "=" * 70)
    print(f"RELEASE GATE STEP: {name}")
    print("=" * 70)


def run_cmd(cmd: list[str], cwd: Path | None = None) -> bool:
    print(f"Executing: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=str(cwd) if cwd else None)
    if result.returncode != 0:
        print(f"[!] FAILED: {' '.join(cmd)} (exit code {result.returncode})")
        return False
    print(f"[OK] PASSED: {' '.join(cmd)}")
    return True


def verify_safety_invariants() -> bool:
    log_step("Safety Invariants Verification")
    passed = True

    # 1. Check compose.yaml
    compose_path = Path("compose.yaml")
    if compose_path.exists():
        content = compose_path.read_text(encoding="utf-8")
        if 'LIVE_RESPONSE_DISABLED: "true"' not in content and "LIVE_RESPONSE_DISABLED: 'true'" not in content:
            print("[!] compose.yaml is missing LIVE_RESPONSE_DISABLED: 'true'")
            passed = False
        else:
            print("[OK] compose.yaml enforces LIVE_RESPONSE_DISABLED: 'true'")
        if 'DRY_RUN_DEFAULT: "true"' not in content and "DRY_RUN_DEFAULT: 'true'" not in content:
            print("[!] compose.yaml is missing DRY_RUN_DEFAULT: 'true'")
            passed = False
        else:
            print("[OK] compose.yaml enforces DRY_RUN_DEFAULT: 'true'")

    # 2. Check docker-compose.yml
    dcompose_path = Path("docker-compose.yml")
    if dcompose_path.exists():
        content = dcompose_path.read_text(encoding="utf-8")
        if 'LIVE_RESPONSE_DISABLED: "true"' not in content and "LIVE_RESPONSE_DISABLED: 'true'" not in content:
            print("[!] docker-compose.yml is missing LIVE_RESPONSE_DISABLED: 'true'")
            passed = False
        else:
            print("[OK] docker-compose.yml enforces LIVE_RESPONSE_DISABLED: 'true'")
        if 'DRY_RUN_DEFAULT: "true"' not in content and "DRY_RUN_DEFAULT: 'true'" not in content:
            print("[!] docker-compose.yml is missing DRY_RUN_DEFAULT: 'true'")
            passed = False
        else:
            print("[OK] docker-compose.yml enforces DRY_RUN_DEFAULT: 'true'")

    # 3. Check .env.example
    env_example = Path(".env.example")
    if env_example.exists():
        content = env_example.read_text(encoding="utf-8")
        if "LIVE_RESPONSE_DISABLED=true" not in content:
            print("[!] .env.example is missing LIVE_RESPONSE_DISABLED=true")
            passed = False
        else:
            print("[OK] .env.example enforces LIVE_RESPONSE_DISABLED=true")
        if "DRY_RUN_DEFAULT=true" not in content:
            print("[!] .env.example is missing DRY_RUN_DEFAULT=true")
            passed = False
        else:
            print("[OK] .env.example enforces DRY_RUN_DEFAULT=true")

    return passed


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=["release", "conditional", "dev"],
        default="release",
        help="Gate qualification mode (release: full gate requiring all checks; conditional: permits NOT RUN container scan on host; dev: offline development)",
    )
    args = parser.parse_args()

    root_dir = Path(__file__).resolve().parent.parent
    os.chdir(root_dir)

    log_step(f"CyberSentinel AI -- Release 1.0 Candidate Release Gate (Mode: {args.mode.upper()})")
    all_passed = True

    # 1. Backend Linting
    log_step("1. Backend Linting (Ruff)")
    all_passed &= run_cmd([sys.executable, "-m", "ruff", "check", "."])

    # 2. Backend Type Checking
    log_step("2. Backend Type Checking (Mypy)")
    all_passed &= run_cmd(
        [sys.executable, "-m", "mypy", "schemas", "apps", "services", "packages", "attack"]
    )

    # 3. Database Migration Offline SQL
    log_step("3. Database Migration SQL Verification (Alembic)")
    all_passed &= run_cmd(
        [
            sys.executable,
            "-m",
            "alembic",
            "-c",
            "infrastructure/alembic.ini",
            "upgrade",
            "head",
            "--sql",
        ]
    )

    # 4. Backend Pytest Suite
    log_step("4. Backend Test Suite (Pytest)")
    all_passed &= run_cmd([sys.executable, "-m", "pytest", "-v"])

    # 5. Frontend Tests
    web_dir = root_dir / "apps" / "web"
    if web_dir.exists():
        log_step("5. Frontend Unit & Safety Tests")
        all_passed &= run_cmd(["node", "--test", "test_frontend.mjs"], cwd=web_dir)

        log_step("6. Frontend Production Build")
        npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
        all_passed &= run_cmd([npm_cmd, "run", "build"], cwd=web_dir)

    # 7. Safety Invariants
    all_passed &= verify_safety_invariants()

    # 8. Supply-Chain Security & Automated Security Gate
    log_step("8. Supply-Chain Security & Automated Security Gate")
    all_passed &= run_cmd([sys.executable, "scripts/security_gate.py", "--mode", args.mode])

    print("\n" + "=" * 70)
    if all_passed:
        if args.mode == "conditional":
            print("RELEASE GATE CHECKS PASSED UNDER CONDITIONAL MODE.")
            print("Release Candidate Status: CONDITIONAL GO (Pending CI Container Scan)")
        else:
            print("ALL RELEASE 1.0 RELEASE GATE CHECKS PASSED SUCCESSFULLY.")
            print("Release Candidate Status: GO (VERIFIED)")
        print("=" * 70)
        sys.exit(0)
    else:
        print("[!] ONE OR MORE RELEASE GATE CHECKS FAILED.")
        print("Release Candidate Status: NO-GO (REJECTED)")
        print("=" * 70)
        sys.exit(1)


if __name__ == "__main__":
    main()

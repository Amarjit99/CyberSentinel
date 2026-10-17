"""CyberSentinel AI — Deterministic Developer Verification Script
Runs linting, type checks, unit/contract/integration tests, and migration checks.
"""

import subprocess
import sys


def run_command(desc: str, cmd: list[str]) -> bool:
    print("\n==================================================")
    print(f"RUNNING: {desc}")
    print(f"COMMAND: {' '.join(cmd)}")
    print("==================================================")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"FAILED: {desc} exited with code {result.returncode}")
        return False
    print(f"PASSED: {desc}")
    return True


def main():
    success = True

    # 1. Ruff linting
    success &= run_command("Ruff Linter", [sys.executable, "-m", "ruff", "check", "."])

    # 2. Mypy type checking
    success &= run_command(
        "Mypy Type Checker",
        [sys.executable, "-m", "mypy", "schemas", "apps", "services", "packages", "attack"],
    )

    # 3. Pytest test suite
    success &= run_command("Pytest Test Suite", [sys.executable, "-m", "pytest", "-v"])

    # 4. Alembic SQL generation
    success &= run_command(
        "Alembic Migration Verification (Offline SQL)",
        [
            sys.executable,
            "-m",
            "alembic",
            "-c",
            "infrastructure/alembic.ini",
            "upgrade",
            "head",
            "--sql",
        ],
    )

    if not success:
        print("\n[!] One or more verification checks failed.")
        sys.exit(1)

    print("\n[OK] All Phase 1 & Phase 2 foundation and ingestion checks PASSED successfully.")


if __name__ == "__main__":
    main()

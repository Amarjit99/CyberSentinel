.PHONY: help install lint format typecheck test check release-gate sast audit sbom

PYTHON ?= python
VENV_BIN ?= .venv/Scripts

help:
	@echo "CyberSentinel AI — Developer Commands"
	@echo "------------------------------------"
	@echo "make install      : Install package and development dependencies"
	@echo "make lint         : Run ruff linter check"
	@echo "make format       : Run ruff auto-formatter"
	@echo "make typecheck    : Run mypy static type checking"
	@echo "make test         : Run full pytest test suite"
	@echo "make check        : Run standard development checks"
	@echo "make sast         : Run bandit static application security testing"
	@echo "make audit        : Run dependency vulnerability audit (pip-audit & npm audit)"
	@echo "make sbom         : Generate machine-readable CycloneDX SBOMs"
	@echo "make release-gate : Run full end-to-end Release 1.0 release gate validation"

install:
	uv pip install -e ".[dev]"

lint:
	ruff check .

format:
	ruff format .

typecheck:
	mypy schemas apps services packages attack

test:
	pytest -v

sast:
	bandit -r schemas apps services packages attack -ll

audit:
	$(PYTHON) -m pip_audit --ignore-vuln PYSEC-2026-2447
	cd apps/web && npm audit

sbom:
	$(PYTHON) scripts/security_gate.py --sbom-only

check:
	$(PYTHON) scripts/run_checks.py

release-gate:
	$(PYTHON) scripts/run_release_gate.py

# 04 — Threat Landscape 2026

## Purpose and caveat
Maintain a dated, evidence-backed threat landscape for the detection and evaluation roadmap. “2026” is a snapshot label, not a prediction that all listed threats are equally prevalent. Re-check primary advisories and source dates at implementation and release time.

## Threat categories to monitor
- Identity compromise: credential theft, token theft, session abuse, MFA fatigue, suspicious privilege escalation.
- Endpoint execution and persistence: script abuse, living-off-the-land activity, persistence mechanisms, suspicious process trees.
- Network intrusion: scanning, command-and-control indicators, unusual DNS, lateral movement, exfiltration signals.
- Cloud and SaaS: anomalous API activity, exposed credentials, privilege changes, suspicious resource creation, audit-log gaps.
- Ransomware and destructive operations: staging, mass file modification, backup tampering, security-tool impairment.
- Supply chain: compromised dependencies, malicious package updates, CI/CD credential abuse.
- Data exposure: unusual access, bulk export, egress anomalies, sensitive-data handling violations.
- AI-specific abuse: prompt injection in logs/tickets/documents, malicious tool arguments, poisoned retrieved content, excessive agent permissions, secret leakage through model context.
- Detection/response failures: missing telemetry, disabled sensors, rule drift, delayed queues, unreviewed automated actions.

## Source hierarchy
Prefer primary advisories and frameworks from CISA, NIST, MITRE ATT&CK, vendor incident-response reports with disclosed methods, and original research. For every item store publisher, publication/update date, URL, affected products/versions if applicable, confidence, expiration/review date, and mapping to detections or controls.

## Threat intelligence record requirements
Separate observed fact from analyst inference. Preserve original source, retrieval timestamp, confidence, TLP/handling marking when provided, expiration, and any transformation. Never treat arbitrary retrieved text as instructions to an agent.

## Product implications
- Build identity, endpoint, network, and cloud event schemas with provenance.
- Detect sensor health gaps as first-class signals.
- Correlate behaviors across time and entities instead of relying only on single indicators.
- Treat model context and agent tools as attack surfaces.
- Evaluate both detection capability and platform abuse resistance.

## Update cadence
Review critical advisories during active incident response, conduct a monthly landscape refresh, and perform a release-time source check. This document must not be treated as live threat intelligence without a maintained update process.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.

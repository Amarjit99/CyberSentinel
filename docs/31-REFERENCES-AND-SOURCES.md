# 31 — References and Sources

## Source-handling rules
Use primary sources where possible. Record publisher, title, publication/update date, retrieval date, version, URL, relevant claim, and limitations. Recheck sources at release time. A URL alone is not proof that a claim is current or correctly interpreted.

## Initial source register
The following sources are referenced by the governing master specification and should be verified before publication or implementation:
- SANS, Security Operations Report: https://www.sans.org/research/security-operations-report
- Google Cloud, Agentic SOC: https://cloud.google.com/solutions/security/agentic-soc
- Microsoft Security Blog, “Reimagining the SOC for the agentic era”: https://www.microsoft.com/en-us/security/blog/2026/09/23/reimagining-the-soc-for-the-agentic-era-in-microsoft-defender/
- NIST, concept paper on identity and authority of software agents: https://www.nist.gov/news-events/news/2026/02/new-concept-paper-identity-and-authority-software-agents
- NIST NCCoE, Software and AI Agent Identity and Authorization: https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization
- NIST, analysis of responses on security considerations for AI: https://www.nist.gov/publications/summary-analysis-responses-request-information-regarding-security-considerations-ai
- MITRE ATT&CK Detection Strategies: https://attack.mitre.org/detectionstrategies/
- MITRE ATT&CK: https://attack.mitre.org/
- Sigma rule specification/project: https://github.com/SigmaHQ/sigma
- OASIS STIX/TAXII: https://oasis-open.github.io/cti-documentation/
- FastAPI documentation: https://fastapi.tiangolo.com/
- Pydantic documentation: https://docs.pydantic.dev/
- PostgreSQL documentation: https://www.postgresql.org/docs/
- OpenSearch documentation: https://opensearch.org/docs/latest/
- Docker Compose documentation: https://docs.docker.com/compose/
- OWASP Top 10 for LLM Applications: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- NIST AI Risk Management Framework: https://www.nist.gov/itl/ai-risk-management-framework

## Citation workflow
For each added claim, attach a citation at paragraph level or in a table. For quantitative claims, cite the original source and record its date and methodology. Do not cite a vendor page as independent validation of vendor performance. Clearly label preprints, marketing materials, standards, advisories, and peer-reviewed work.

## Research ledger template
| Field | Required value |
|---|---|
| Reference ID | Stable project identifier |
| Full citation | Author/organization, title, publication date |
| URL/DOI | Canonical source |
| Retrieved | Date checked |
| Source type | Standard, paper, advisory, vendor documentation, etc. |
| Claim supported | Exact claim or design decision |
| Limitations | Bias, scope, missing methodology, version caveat |
| Project usage | Requirement, design, test, or evaluation |

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.

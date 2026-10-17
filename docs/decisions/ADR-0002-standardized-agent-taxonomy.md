# ADR-0002: Standardized Multi-Agent Taxonomy & Bounded Tool Governance

**Status:** Accepted  
**Date:** 2026-10-16  
**Deciders:** Senior Software Architect, AI Security Architect, QA Lead  
**Governing Conflict:** [CONFL-002](../audit/CONFLICT_REGISTER.md#confl-002-agent-role-catalog-and-delegation-taxonomy-discrepancy) & [CONFL-008](../audit/CONFLICT_REGISTER.md#confl-008-ai-agent-tool-execution-boundaries-and-shell-access-prohibition)  

---

## 1. Context & Problem Statement

The master specification defined 8 specialized agents, whereas `docs/10-AGENT-ARCHITECTURE.md` introduced alternate role names (`Evidence collector`, `Investigation planner`, `Response advisor`, etc.). Additionally, ambiguous wording in the master spec suggested lab shell access might be permissible under container isolation, creating an unmitigated prompt-injection and code-execution risk.

## 2. Decision

### Authoritative 8-Agent Core System
We standardize on the following 8 canonical agent identities. Functional capabilities from Doc 10 are organized as sub-skills or workflows within these primary agents:

| Canonical Agent ID | Primary Role | Doc 10 Capability Mapping | Default Privilege Level |
|---|---|---|:---:|
| `triage-agent` | Initial alert classification, scoping & draft reporting | Triage agent, Report writer | Read-Only |
| `investigation-agent` | Investigation planning, graph traversal & correlation | Investigation planner, Correlation assistant | Read-Only |
| `threat-intel-agent` | IOC lookup, STIX/TAXII query & reputation assessment | Threat-intelligence analyst | Read-Only |
| `threat-hunting-agent` | Hypothesis-driven structured search over historical events | Query constructor, Log explorer | Read-Only |
| `evidence-agent` | Immutable artifact collection, provenance verification | Evidence collector | Read-Only |
| `attack-mapping-agent` | MITRE ATT&CK technique & detection strategy linking | ATT&CK mapper | Read-Only |
| `risk-agent` | Deterministic risk score calculation & uncertainty assessment | Risk calculator | Read-Only |
| `response-agent` | Response playbook proposal generation & impact analysis | Response advisor | Approval-Gated |

### Absolute Shell Prohibition
1. **Free-form shell tools (`bash`, `sh`, `powershell`, `cmd`, `exec`) are strictly prohibited** across all environments (production, staging, lab, and development).
2. All agent capabilities are mediated exclusively through **typed JSON tool contracts** adhering to strict OpenAPI/JSON schemas.
3. Tools operate over bounded REST/RPC microservice endpoints with object-level permission enforcement at the Policy Enforcement Point (PEP).
4. Raw telemetry, logs, and external documents are treated as **untrusted data**; the agent runtime environment never executes instructions or prompts embedded within log payloads.

## 3. Consequences

### Positive
- Eliminates prompt injection to remote code execution (RCE) vectors.
- Guarantees predictable tool calling and rigid parameter validation.
- SPIFFE/SPIRE workload identities can be assigned deterministically to the 8 canonical agents.

### Negative / Trade-offs
- Precludes autonomous ad-hoc script execution in lab environments; all lab interactions must use dedicated, pre-registered simulation adapters.

# Autonomous Agent Service (`services/agents`)

## Responsibility
Coordinates the 8 specialized agents defined in **ADR-0002**:
- `TriageAgent`: Alert verification and priority scoring.
- `InvestigationAgent`: Hypothesis formulation and forensic reasoning.
- `EnrichmentAgent`: Context gathering (WHOIS, DNS, asset inventory).
- `CorrelationAgent`: Cross-telemetry graph association.
- `ThreatIntelAgent`: Threat actor and campaign attribution.
- `PlaybookAgent`: Mitigation proposal formulation.
- `VerificationAgent`: Pre-execution safety and sanity checking.
- `CommunicationAgent`: Incident summaries and stakeholder reporting.

## Mandatory Safety Invariants
- **No generic shell execution tools.** Agents operate strictly through typed, deterministic domain APIs.
- **Read-Only Inspection:** In Phase 1 and 2, all agent analysis is non-destructive and read-only.

# CyberSentinel AI
## Agentic Security Operations & Threat Investigation Platform
### Master Research, Product Requirements, Security Architecture & Implementation Specification

**Research baseline:** September 2026  
**Document status:** Master Requirements / Pre-Implementation Specification  
**Purpose:** Single source of truth for architecture, engineering, security, research, testing, and deployment.

---

# 1. Executive Summary

CyberSentinel AI is a security operations platform designed to combine deterministic security detection, security telemetry correlation, threat intelligence, MITRE ATT&CK knowledge, machine-learning-assisted anomaly detection, and controlled multi-agent AI investigation.

The system is explicitly **not** an unrestricted autonomous hacking or response system. Its design principle is:

> Deterministic security controls establish facts; AI agents investigate and reason over those facts; humans retain authority over consequential actions.

The platform will ingest endpoint, network, identity, cloud, and application telemetry; normalize events; detect suspicious behavior; correlate related events into incidents; launch specialized investigation agents; collect evidence; map findings to ATT&CK; calculate explainable risk; recommend response playbooks; and, where authorized, execute bounded response actions in a controlled environment.

The project is intended to support:

- a working SOC/security product prototype
- a research project
- repeatable cybersecurity experiments
- academic publication
- security engineering demonstrations
- future extension into a production-grade platform

---

# 2. Research Baseline and Evidence

## 2.1 Current SOC landscape

The 2026 SANS SOC report surveyed 444 practitioners and 69 cyber leaders. It reports that 79% of SOCs use AI/ML tools while only 36% have integrated AI into a defined SOC workflow. It also identifies visibility, staffing, alert correlation, and workflow integration as continuing operational problems.

Source:
https://www.sans.org/research/security-operations-report

## 2.2 Agentic SOC direction

Google Security Operations currently describes agentic workflows for alert triage, investigation, threat hunting, and detection engineering.

Source:
https://cloud.google.com/solutions/security/agentic-soc

Microsoft's September 2026 security architecture describes an integrated security operations model built around sensors/signals, context, models, agents, a harness, and actuators, with humans defining priorities and outcomes.

Source:
https://www.microsoft.com/en-us/security/blog/2026/09/23/reimagining-the-soc-for-the-agentic-era-in-microsoft-defender/

## 2.3 AI-agent identity and authorization

NIST's 2026 work specifically identifies identity, authorization, auditing, non-repudiation, and prompt-injection controls as important security considerations for AI agents.

Sources:
https://www.nist.gov/news-events/news/2026/02/new-concept-paper-identity-and-authority-software-agents
https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd
https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization

## 2.4 AI-agent security

NIST's 2026 analysis reports broad agreement that AI agents create novel security threats and that conventional cybersecurity principles require adaptation.

Source:
https://www.nist.gov/publications/summary-analysis-responses-request-information-regarding-security-considerations-ai

## 2.5 ATT&CK detection model

MITRE ATT&CK now provides Detection Strategies as higher-level approaches that organize multiple platform-specific analytics.

Source:
https://attack.mitre.org/detectionstrategies/

## 2.6 Agent identity and credential protection

NIST's September 2026 IR 8587 provides implementation guidance for protecting identity tokens, access tokens, assertions, federation, API access, and key management.

Source:
https://csrc.nist.gov/pubs/ir/8587/final

## 2.7 Research implication

CyberSentinel must therefore treat:

- data quality
- visibility
- deterministic detection
- agent identity
- least privilege
- evidence traceability
- human oversight
- AI-specific threat modeling
- measurable SOC outcomes

as first-class requirements.

---

# 3. Product Vision

## 3.1 Vision

Build a practical, modular, explainable, secure, and testable Agentic SOC platform capable of assisting analysts from alert ingestion through investigation and controlled response.

## 3.2 Mission

Reduce repetitive SOC investigation work while improving evidence correlation, detection coverage, response consistency, and analyst visibility.

## 3.3 Core principles

1. Security first.
2. Human authority over high-impact actions.
3. Evidence before conclusion.
4. Deterministic controls before probabilistic AI.
5. Least privilege for every agent.
6. Every important action is auditable.
7. AI decisions must be explainable.
8. Model/provider agnostic architecture.
9. Production-style engineering practices.
10. Repeatable evaluation.
11. Fail closed for high-risk actions.
12. Never trust unvalidated telemetry or agent output.

---

# 4. Problem Statement

Modern SOCs receive high volumes of heterogeneous alerts from endpoints, networks, identity systems, cloud platforms, and applications.

Common challenges include:

- alert overload
- duplicate alerts
- fragmented telemetry
- weak event correlation
- investigation time
- shortage of experienced analysts
- inconsistent investigation procedures
- detection coverage gaps
- poor evidence traceability
- difficult threat-hunting workflows
- risky automation
- AI hallucination
- prompt injection
- excessive agent privileges
- insufficient auditability

CyberSentinel addresses these through a layered architecture rather than replacing the SIEM or analyst with an unrestricted LLM.

---

# 5. Goals

## 5.1 Primary goals

- Centralize security telemetry.
- Normalize heterogeneous events.
- Detect known suspicious behaviors.
- Detect behavioral anomalies.
- Correlate events.
- Group related alerts into incidents.
- Automatically investigate incidents.
- Enrich indicators.
- Map findings to ATT&CK.
- Build attack timelines.
- Produce explainable risk scores.
- Generate response recommendations.
- Require authorization for consequential actions.
- Maintain complete audit trails.
- Provide repeatable SOC benchmarking.

## 5.2 Secondary goals

- Detection engineering assistance.
- Threat hunting assistance.
- Investigation report generation.
- Analyst knowledge retrieval.
- Security training laboratory.
- Research dataset generation.
- AI-agent security testing.

## 5.3 Non-goals

- Unrestricted autonomous offensive operations.
- Automated destructive actions against production infrastructure.
- Credential harvesting.
- Real-world unauthorized exploitation.
- Replacing the analyst entirely.
- Treating LLM output as authoritative evidence.
- Sending sensitive telemetry to external AI systems without policy approval.

---

# 6. Target Users

## 6.1 SOC Analyst

Needs:

- alert triage
- investigation
- evidence
- timelines
- recommendations

## 6.2 Threat Hunter

Needs:

- query interface
- historical search
- behavioral correlation
- IOC investigation

## 6.3 Detection Engineer

Needs:

- rule management
- ATT&CK coverage
- rule testing
- detection-gap analysis

## 6.4 SOC Manager

Needs:

- incident metrics
- workload
- MTTA/MTTR
- coverage
- analyst performance
- AI performance

## 6.5 Security Engineer

Needs:

- integrations
- ingestion health
- parser status
- system health

## 6.6 Researcher

Needs:

- experiment configuration
- attack scenarios
- ground truth
- benchmark metrics
- reproducibility

## 6.7 Administrator

Needs:

- RBAC
- users
- permissions
- agents
- integrations
- policies
- audit logs

---

# 7. High-Level Architecture

```text
                         CYBERSENTINEL AI

 ┌─────────────────────────────────────────────────────────────┐
 │                        DATA SOURCES                          │
 │ Endpoint | Network | Identity | Cloud | Application | TI    │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │                    TELEMETRY INGESTION                      │
 │ Collectors | APIs | Agents | Syslog | Files | Streams       │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │                   NORMALIZATION / PARSING                   │
 │ Parser | Validation | Enrichment | Canonical Event Schema    │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │                    SECURITY DATA PLATFORM                   │
 │ OpenSearch | PostgreSQL | Object Storage | Vector DB        │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                    ┌───────────┴────────────┐
                    ▼                        ▼
          ┌──────────────────┐      ┌───────────────────┐
          │ Detection Engine │      │ Anomaly Engine    │
          │ Sigma/Rules      │      │ ML/UEBA           │
          └────────┬─────────┘      └────────┬──────────┘
                   └──────────────┬──────────┘
                                  ▼
                       ┌────────────────────┐
                       │ Correlation Engine │
                       └──────────┬─────────┘
                                  ▼
                       ┌────────────────────┐
                       │ Incident Engine   │
                       └──────────┬─────────┘
                                  ▼
                   ┌────────────────────────────┐
                   │   AGENT ORCHESTRATOR       │
                   └────────────┬───────────────┘
                                │
       ┌──────────┬─────────────┼─────────────┬──────────────┐
       ▼          ▼             ▼             ▼              ▼
     Triage   Investigation  Threat Intel   Hunting        Risk
     Agent       Agent         Agent         Agent         Agent
       │          │             │             │              │
       └──────────┴─────────────┼─────────────┴──────────────┘
                                ▼
                      ┌─────────────────────┐
                      │ Evidence Engine     │
                      │ ATT&CK Mapping      │
                      │ Attack Graph        │
                      │ Timeline            │
                      └──────────┬──────────┘
                                 ▼
                      ┌─────────────────────┐
                      │ Response Planner    │
                      └──────────┬──────────┘
                                 ▼
                         HUMAN APPROVAL
                                 │
                   ┌─────────────┴─────────────┐
                   ▼                           ▼
              APPROVED                     REJECTED
                   │
                   ▼
          CONTROLLED PLAYBOOK
                   │
                   ▼
             RESPONSE TOOL
```

---

# 8. Functional Requirements

## FR-001 Telemetry ingestion

The system shall ingest security events from:

- Windows Event Logs
- Sysmon
- Linux authentication/audit logs
- firewall logs
- IDS/IPS alerts
- DNS logs
- proxy logs
- authentication logs
- cloud audit logs
- application logs
- threat-intelligence feeds

## FR-002 Raw event preservation

Every ingested event shall retain the original raw representation.

## FR-003 Event normalization

Events shall be converted into a canonical internal schema.

## FR-004 Event validation

Invalid events shall be rejected or quarantined without crashing ingestion.

## FR-005 Event enrichment

Events may be enriched with:

- asset information
- identity information
- geolocation where appropriate
- IOC reputation
- threat intelligence
- ATT&CK references

## FR-006 Detection rules

The platform shall support:

- Sigma rules
- custom deterministic rules
- correlation rules
- threshold rules
- allow/deny lists

## FR-007 Detection execution

Rules shall execute against normalized telemetry.

## FR-008 Finding generation

A detection shall create a finding containing:

- rule
- event references
- severity
- timestamp
- host
- user
- source
- evidence

## FR-009 Alert management

Analysts shall be able to:

- acknowledge
- assign
- suppress
- escalate
- close
- reopen

alerts.

## FR-010 Correlation

The platform shall correlate events using:

- time
- user
- host
- IP
- domain
- process
- session
- IOC
- ATT&CK technique
- incident relationship

## FR-011 Incident creation

Multiple related alerts shall be grouped into incidents.

## FR-012 Incident timeline

Every incident shall have a chronological timeline.

## FR-013 AI triage

The Triage Agent shall classify an alert using available evidence.

## FR-014 AI investigation

The Investigation Agent shall generate and execute a bounded investigation plan.

## FR-015 Evidence collection

Each AI conclusion shall reference supporting evidence.

## FR-016 Threat intelligence enrichment

The Threat Intelligence Agent shall query configured intelligence sources.

## FR-017 Threat hunting

Authorized users shall be able to submit natural-language hunting requests.

## FR-018 Query translation

Natural-language requests shall be converted into validated structured queries.

## FR-019 ATT&CK mapping

Findings may be mapped to:

- tactic
- technique
- sub-technique
- detection strategy

## FR-020 Risk calculation

The platform shall calculate explainable incident risk.

## FR-021 Attack graph

The platform shall visualize relationships among:

- users
- hosts
- processes
- IPs
- domains
- incidents
- techniques

## FR-022 Response planning

The Response Agent shall generate structured response recommendations.

## FR-023 Human approval

High-impact response actions shall require explicit approval.

## FR-024 Playbooks

The system shall support versioned response playbooks.

## FR-025 Action execution

Approved playbooks shall execute only allowed actions against authorized targets.

## FR-026 Audit logging

All security-sensitive actions shall be logged.

## FR-027 Agent audit

Every agent execution shall record:

- agent ID
- model
- model version
- task
- inputs
- tools
- tool results
- output
- evidence
- policy decision
- approval
- action

## FR-028 Reporting

The system shall generate incident reports.

## FR-029 Metrics

The platform shall calculate:

- MTTD
- MTTA
- MTTR
- false-positive rate
- detection precision
- detection recall
- investigation duration
- AI investigation duration
- analyst intervention rate

## FR-030 Benchmarking

The system shall support controlled scenario-based evaluation.

---

# 9. Agent Requirements

## 9.1 Triage Agent

Inputs:

- alert
- related events
- rule
- asset
- identity
- threat intelligence

Outputs:

- severity
- confidence
- summary
- reason
- recommended next step

Must not:

- directly execute high-impact actions.

## 9.2 Investigation Agent

Responsibilities:

- build investigation plan
- retrieve evidence
- correlate events
- identify suspicious relationships
- summarize findings

Must operate through approved tools only.

## 9.3 Threat Intelligence Agent

Responsibilities:

- IOC enrichment
- reputation lookup
- related indicators
- campaign information

Must distinguish:

- confirmed intelligence
- source claim
- uncertain information

## 9.4 Threat Hunting Agent

Responsibilities:

- interpret hunting request
- construct query
- validate query
- execute read-only search
- explain findings

No arbitrary command execution.

## 9.5 Evidence Agent

Responsibilities:

- collect supporting evidence
- preserve references
- build evidence chain
- identify conflicting evidence

## 9.6 Risk Agent

Responsibilities:

- calculate risk
- explain risk factors
- identify uncertainty
- distinguish confidence from severity

## 9.7 Detection Engineering Agent

Responsibilities:

- identify detection gaps
- propose Sigma rules
- test proposed rules
- map rules to ATT&CK detection strategies
- estimate false-positive risk

Rules shall require validation before deployment.

## 9.8 Response Agent

Responsibilities:

- recommend response
- select playbook
- estimate impact
- request approval where required

It shall not bypass authorization policies.

---

# 10. Agent Identity and Authorization

Each agent shall have:

- unique identity
- unique credential
- explicit role
- tool permissions
- resource permissions
- action permissions
- audit identity

Avoid long-lived unrestricted API keys.

Recommended future integration:

- OAuth 2.0
- short-lived tokens
- workload identity
- SPIFFE/SPIRE
- JWT/X.509 where appropriate
- policy enforcement point

NIST's current agent-identity work emphasizes treating agents as identifiable entities with controlled authorization rather than simply sharing human credentials.

---

# 11. Agent Permission Matrix

| Agent | Read Logs | Query TI | Create Rule | Execute Response | Modify Config |
|---|---:|---:|---:|---:|---:|
| Triage | Yes | Yes | No | No | No |
| Investigation | Yes | Yes | No | No | No |
| Threat Intel | Limited | Yes | No | No | No |
| Hunting | Yes | Yes | No | No | No |
| Evidence | Yes | Yes | No | No | No |
| Risk | Yes | Yes | No | No | No |
| Detection Engineering | Yes | Yes | Draft | No | No |
| Response | Limited | Yes | No | Approval | No |
| Admin | Policy-based | Policy-based | Policy-based | Policy-based | Yes |

---

# 12. Human-in-the-Loop Policy

## Low-risk

May be automatically executed:

- create ticket
- enrich IOC
- tag incident
- update internal metadata
- generate report

## Medium-risk

Require analyst approval:

- block IP
- block domain
- quarantine file
- isolate host

## High-risk

Require explicit approval and potentially dual authorization:

- disable account
- revoke credentials
- reset privileged credentials
- modify security infrastructure
- delete data
- change production security policy

Avoid excessive approval prompts to reduce consent fatigue.

---

# 13. Canonical Event Schema

Minimum fields:

```json
{
  "event_id": "uuid",
  "timestamp": "ISO-8601",
  "ingest_timestamp": "ISO-8601",
  "source_type": "windows",
  "source_name": "sysmon",
  "event_type": "process_creation",
  "host_id": "asset-001",
  "hostname": "host-001",
  "user_id": "user-001",
  "username": "user",
  "src_ip": "10.0.0.10",
  "dst_ip": "10.0.0.20",
  "src_port": 1234,
  "dst_port": 443,
  "process_name": "powershell.exe",
  "process_id": 1234,
  "parent_process": "explorer.exe",
  "command_line": "...",
  "hash_sha256": "...",
  "domain": "...",
  "url": "...",
  "severity": "medium",
  "raw_event": {}
}
```

The schema must be extensible.

---

# 14. Database Model

Core tables:

```text
users
roles
permissions
user_roles
role_permissions

agents
agent_versions
agent_permissions
agent_runs
agent_tool_calls

assets
asset_groups
identities
accounts

raw_events
normalized_events
event_sources
parsers

rules
rule_versions
rule_tests
detections
findings

alerts
alert_events
incidents
incident_events
incident_assignments

iocs
threat_intelligence
ti_sources
ti_observations

attack_tactics
attack_techniques
attack_subtechniques
detection_strategies
attack_mappings

investigations
investigation_steps
evidence
evidence_relationships

risk_scores
risk_factors

playbooks
playbook_versions
response_actions
approvals

audit_logs
security_policies
system_settings

experiments
attack_scenarios
ground_truth
benchmark_runs
benchmark_results
```

---

# 15. Data Storage Architecture

## OpenSearch

Use for:

- high-volume event search
- detection queries
- security analytics
- investigation search

## PostgreSQL

Use for:

- users
- incidents
- workflows
- agents
- policies
- approvals
- configuration

## Object storage

Use for:

- raw logs
- reports
- large evidence artifacts
- experiment datasets

## Vector database

Use for:

- approved knowledge
- historical incident retrieval
- security documentation

Do not use vector similarity as the authoritative source for security decisions.

---

# 16. Threat Intelligence Architecture

Support:

- IOC feeds
- STIX
- TAXII
- internal IOC lists
- analyst observations
- vendor intelligence

Every intelligence item should contain:

```text
source
first_seen
last_seen
confidence
tlp
collection_time
indicator_type
indicator_value
relationships
```

Do not blindly trust external reputation data.

---

# 17. MITRE ATT&CK Architecture

Maintain:

```text
Tactic
  ↓
Technique
  ↓
Sub-technique
  ↓
Detection Strategy
  ↓
Analytics
  ↓
Evidence
  ↓
Finding
```

Store ATT&CK version metadata so results remain reproducible after ATT&CK updates.

---

# 18. Detection Engineering

Detection lifecycle:

```text
Idea
 ↓
Draft
 ↓
Unit Test
 ↓
Historical Test
 ↓
False Positive Review
 ↓
Peer/Analyst Review
 ↓
Staging
 ↓
Production
 ↓
Monitor
 ↓
Tune
 ↓
Retire
```

Every production rule must have:

- owner
- version
- test cases
- ATT&CK mapping
- expected data source
- false-positive guidance
- severity
- deployment status

---

# 19. ML / Anomaly Detection

Do not start with complex deep learning.

Initial models:

- statistical baselines
- isolation forest
- clustering
- frequency anomaly
- impossible travel
- rare process detection
- unusual authentication
- unusual network destination

Future:

- graph anomaly detection
- temporal models
- sequence models
- UEBA

Every model must be evaluated against a known baseline.

---

# 20. RAG Architecture

Approved knowledge sources:

- ATT&CK
- Sigma documentation
- internal security procedures
- incident-response procedures
- approved threat-intelligence reports
- vendor documentation
- previous resolved incidents

Pipeline:

```text
Source
 ↓
Validation
 ↓
Classification
 ↓
Chunking
 ↓
Embedding
 ↓
Index
 ↓
Retrieval
 ↓
Evidence filtering
 ↓
Agent
```

The agent must identify the source of retrieved knowledge.

---

# 21. AI Security Requirements

Protect against:

- prompt injection
- indirect prompt injection
- malicious logs
- poisoned documents
- RAG poisoning
- tool manipulation
- excessive agency
- data leakage
- unauthorized tool use
- credential theft
- model output injection
- malicious tool results

Controls:

- input sanitization
- trust boundaries
- tool allowlists
- parameter validation
- output validation
- sandboxing
- policy engine
- least privilege
- rate limiting
- audit logs
- human approval
- data redaction

---

# 22. Tool Security

Every agent tool must have:

```text
tool_id
description
input_schema
output_schema
permission
risk_level
allowed_agents
allowed_resources
timeout
rate_limit
audit_requirement
```

No free-form shell tool in production.

If shell access is ever required in the lab, use:

- isolated container
- non-root user
- resource limits
- network restrictions
- command allowlist
- filesystem restrictions
- timeout
- complete logging

---

# 23. API Requirements

Example APIs:

```text
POST /api/v1/events
GET  /api/v1/events
POST /api/v1/search

GET  /api/v1/alerts
GET  /api/v1/alerts/{id}
POST /api/v1/alerts/{id}/ack

GET  /api/v1/incidents
GET  /api/v1/incidents/{id}
POST /api/v1/incidents/{id}/investigate

POST /api/v1/hunting/query
POST /api/v1/agents/investigate

GET  /api/v1/evidence/{id}
GET  /api/v1/attack/{id}

POST /api/v1/playbooks/{id}/preview
POST /api/v1/actions/{id}/approve
POST /api/v1/actions/{id}/reject

GET  /api/v1/audit
GET  /api/v1/metrics
```

Use API versioning from the beginning.

---

# 24. Authentication and Authorization

Implement:

- OIDC/OAuth2
- RBAC
- optional ABAC
- MFA support
- session management
- token rotation
- refresh-token protection
- password policy if local auth is enabled
- account lockout/rate limiting
- audit logs

Roles:

```text
SOC_ANALYST
THREAT_HUNTER
DETECTION_ENGINEER
SOC_MANAGER
SECURITY_ENGINEER
ADMIN
RESEARCHER
VIEWER
```

---

# 25. Frontend Requirements

## Main dashboard

Display:

- critical incidents
- active investigations
- alert volume
- detection volume
- AI activity
- response approvals
- MTTD
- MTTA
- MTTR
- telemetry health

## Incident page

Display:

- incident summary
- severity
- confidence
- timeline
- attack graph
- evidence
- affected assets
- affected users
- IOCs
- ATT&CK mapping
- AI reasoning summary
- recommended actions
- approval history

## Investigation workspace

Provide:

- evidence panel
- query panel
- timeline
- agent activity
- source citations
- analyst notes

## AI Agent activity

Display:

- current task
- tools called
- tool results
- reasoning summary
- evidence
- policy checks
- blocked actions

Never expose hidden chain-of-thought. Show concise decision rationale and evidence instead.

---

# 26. Attack Graph

Graph nodes:

```text
User
Host
Process
IP
Domain
URL
File
Credential
Cloud Resource
Incident
Technique
```

Graph edges:

```text
logged_in_from
executed
connected_to
resolved
accessed
created
modified
authenticated_to
mapped_to
related_to
```

The graph must support time filtering.

---

# 27. Incident Lifecycle

```text
NEW
 ↓
TRIAGED
 ↓
INVESTIGATING
 ↓
CONFIRMED / BENIGN
 ↓
CONTAINMENT_PENDING
 ↓
CONTAINED
 ↓
ERADICATION
 ↓
RECOVERY
 ↓
CLOSED
 ↓
LESSONS_LEARNED
```

Every transition requires:

- actor
- timestamp
- reason
- previous state
- new state

---

# 28. Response Playbook Framework

Playbook example:

```yaml
name: Suspicious Endpoint Isolation
risk: high
requires_approval: true

steps:
  - verify_incident
  - validate_target
  - collect_final_evidence
  - request_approval
  - isolate_endpoint
  - verify_isolation
  - create_followup_task
```

Playbooks must be versioned.

---

# 29. Security Controls

Minimum:

- TLS
- encryption at rest
- secrets management
- RBAC
- audit logging
- input validation
- rate limiting
- CSRF protection where applicable
- secure headers
- dependency scanning
- container scanning
- SAST
- DAST
- SBOM
- backup
- disaster recovery
- log integrity protection

---

# 30. Privacy

Telemetry can contain sensitive information.

Requirements:

- data classification
- field-level redaction
- configurable retention
- access logging
- minimum necessary collection
- encryption
- tenant isolation
- configurable AI data policy

Before sending telemetry to an external model:

```text
Raw Event
 ↓
Classification
 ↓
Redaction
 ↓
Policy Check
 ↓
Allowed?
 ↓
Model
```

---

# 31. Reliability Requirements

Target:

- ingestion should tolerate malformed events
- queues should absorb spikes
- agents should have timeouts
- failed agents should retry safely
- response actions must be idempotent
- duplicate actions must be prevented
- system should degrade gracefully when AI is unavailable

If AI is unavailable:

```text
Detection continues.
SIEM continues.
Rules continue.
Incident management continues.
```

AI should be an enhancement, not a single point of failure.

---

# 32. Performance Targets

Initial engineering targets:

- event ingestion: >= 1,000 events/sec in development benchmark
- search response: < 3 seconds for common queries
- alert triage: < 30 seconds target
- investigation startup: < 10 seconds
- dashboard initial load: < 3 seconds
- API availability target: 99%+ for prototype deployment

Production targets should be recalculated from actual workload.

---

# 33. Scalability

Architecture should allow:

```text
Single node
 ↓
Docker Compose
 ↓
Multi-service deployment
 ↓
Kubernetes
 ↓
Horizontal ingestion
 ↓
Distributed search
 ↓
Distributed agents
```

Do not hard-code the system to one machine.

---

# 34. Testing Strategy

## Unit testing

- parsers
- normalization
- rules
- correlation
- risk
- authorization
- playbooks

## Integration testing

- ingestion → detection
- detection → incident
- incident → agent
- agent → evidence
- evidence → response
- approval → action

## Security testing

- authentication
- authorization
- injection
- SSRF
- command injection
- data leakage
- prompt injection
- tool abuse
- privilege escalation

## AI testing

- hallucination
- evidence grounding
- prompt injection
- tool selection
- invalid output
- conflicting evidence
- malicious telemetry
- RAG poisoning

---

# 35. Attack Simulation Laboratory

Create a safe isolated lab.

Recommended scenarios:

1. brute-force login
2. suspicious PowerShell
3. suspicious process tree
4. credential access simulation
5. lateral movement simulation
6. suspicious DNS
7. command-and-control simulation
8. account takeover
9. data-exfiltration simulation
10. multi-stage intrusion
11. malicious log prompt injection
12. poisoned knowledge-base document
13. malicious tool result
14. agent permission escalation attempt

All scenarios must run only against authorized lab assets.

---

# 36. Ground Truth

Every benchmark scenario must define:

```text
scenario_id
attack_steps
expected_events
expected_alerts
expected_techniques
expected_incident
expected evidence
expected response
```

This allows objective evaluation.

---

# 37. Evaluation Framework

Compare:

### Baseline

Traditional rule-driven workflow.

### AI-assisted

Rules + analyst + AI recommendations.

### Agentic

Rules + multiple agents + controlled orchestration.

Measure:

## Detection

- precision
- recall
- F1
- false-positive rate
- false-negative rate

## Investigation

- time to triage
- time to investigate
- evidence completeness
- ATT&CK mapping accuracy

## Operations

- MTTD
- MTTA
- MTTR
- alerts handled per analyst

## AI

- hallucination rate
- unsupported-claim rate
- tool-call accuracy
- unsafe-action rate
- policy violation rate

## Human factors

- approval rate
- analyst correction rate
- analyst workload
- analyst trust/calibration

---

# 38. Research Questions

RQ1:
Can agentic investigation reduce SOC investigation time?

RQ2:
Does evidence-grounded agent reasoning reduce unsupported security conclusions?

RQ3:
Can multi-agent investigation improve incident correlation compared with a single AI assistant?

RQ4:
How much analyst intervention is required before automated response becomes reliable?

RQ5:
What types of telemetry are most important for successful agentic investigation?

RQ6:
Can agent identity and least privilege reduce the impact of prompt-injection-driven tool abuse?

RQ7:
How does agentic detection engineering affect detection coverage and false positives?

---

# 39. Hypotheses

H1:
Agent-assisted investigation will reduce median investigation time compared with manual investigation.

H2:
Evidence-grounded agents will produce fewer unsupported conclusions than unconstrained LLM analysis.

H3:
Multi-source correlation will improve incident reconstruction compared with single-source analysis.

H4:
Human approval gates will reduce high-impact unsafe actions.

H5:
Least-privileged agent identities will reduce the blast radius of agent compromise.

---

# 40. Dataset Strategy

Use a combination of:

- public cybersecurity datasets
- controlled lab telemetry
- synthetic security events
- generated benchmark scenarios
- sanitized internal test data

Every dataset must record:

- source
- license
- timestamp
- schema
- transformation
- ground truth
- known limitations

Never use confidential organizational logs in the research dataset without authorization.

---

# 41. MVP Technology Stack

## Frontend

- React
- TypeScript
- Tailwind CSS
- ECharts/Recharts

## Backend

- Python
- FastAPI
- Pydantic

## Data

- OpenSearch
- PostgreSQL
- Redis

## Security telemetry

- Wazuh
- Sysmon
- Suricata
- Zeek

## Detection

- Sigma

## Threat intelligence

- STIX/TAXII-compatible design

## Knowledge

- Vector database

## AI

- model-agnostic provider abstraction
- structured tool calling
- RAG
- policy/guardrail layer

## Deployment

- Docker
- Docker Compose
- Linux

Kubernetes is a later stage.

---

# 42. Repository Structure

```text
cybersentinel-ai/
├── apps/
│   ├── web/
│   └── api/
├── services/
│   ├── ingestion/
│   ├── normalization/
│   ├── detection/
│   ├── correlation/
│   ├── incidents/
│   ├── threat-intel/
│   ├── agents/
│   ├── response/
│   └── reporting/
├── agents/
│   ├── triage/
│   ├── investigation/
│   ├── threat-intel/
│   ├── hunting/
│   ├── evidence/
│   ├── risk/
│   ├── detection-engineering/
│   └── response/
├── schemas/
├── rules/
│   ├── sigma/
│   └── correlation/
├── attack/
├── playbooks/
├── datasets/
├── scenarios/
├── benchmarks/
├── tests/
├── infrastructure/
│   ├── docker/
│   ├── opensearch/
│   └── postgres/
├── docs/
└── scripts/
```

---

# 43. Development Phases

## Phase 0 — Research and specification

Deliver:

- requirements
- threat model
- architecture
- schemas
- research questions
- evaluation design

## Phase 1 — Platform foundation

Deliver:

- authentication
- RBAC
- PostgreSQL
- OpenSearch
- API
- frontend shell
- logging

## Phase 2 — Telemetry

Deliver:

- event ingestion
- parsing
- normalization
- event search

## Phase 3 — Detection

Deliver:

- Sigma
- rules
- findings
- alerts

## Phase 4 — Correlation

Deliver:

- correlation engine
- incident engine
- timeline

## Phase 5 — Threat intelligence

Deliver:

- IOC model
- enrichment
- STIX/TAXII architecture

## Phase 6 — ATT&CK

Deliver:

- ATT&CK database
- technique mapping
- detection strategies
- coverage dashboard

## Phase 7 — First AI agents

Deliver:

- Triage Agent
- Investigation Agent
- Threat Intelligence Agent

## Phase 8 — Agentic orchestration

Deliver:

- orchestrator
- tool registry
- agent permissions
- agent memory
- RAG

## Phase 9 — Hunting and detection engineering

Deliver:

- Hunting Agent
- Detection Engineering Agent
- rule validation

## Phase 10 — Response

Deliver:

- playbooks
- approval engine
- safe lab actions
- response audit

## Phase 11 — AI security

Deliver:

- prompt injection defenses
- tool security
- sandbox
- agent identity
- least privilege

## Phase 12 — Benchmark

Deliver:

- attack scenarios
- ground truth
- baseline comparison
- metrics
- research report

---

# 44. Acceptance Criteria

The project is not considered complete because the UI works.

It is complete when:

- telemetry can be ingested
- raw events are preserved
- normalized events are searchable
- deterministic detection works
- alerts are generated
- events correlate into incidents
- agents can investigate using bounded tools
- evidence is linked to conclusions
- ATT&CK mapping works
- risk scoring is explainable
- response recommendations are generated
- high-impact actions require approval
- all actions are audited
- AI failure does not stop core detection
- prompt injection tests exist
- agent authorization tests exist
- attack scenarios can be replayed
- benchmark metrics can be generated
- deployment is reproducible

---

# 45. Security Acceptance Criteria

The system must pass:

- authentication tests
- RBAC tests
- authorization bypass tests
- injection tests
- API security tests
- secret scanning
- dependency scanning
- container scanning
- prompt injection tests
- tool abuse tests
- agent privilege tests
- audit integrity tests
- data leakage tests

---

# 46. Observability

Monitor:

- CPU
- memory
- disk
- ingestion rate
- dropped events
- parser failures
- queue depth
- rule execution time
- agent latency
- model failures
- tool failures
- response failures
- database health
- OpenSearch health

Agent observability:

```text
agent_run_id
agent_id
task
start_time
end_time
model
tools
tokens/cost if available
success
policy_decision
human_approval
```

---

# 47. Cost Controls

AI usage can become expensive.

Implement:

- token budgets
- per-agent budgets
- request limits
- caching
- model routing
- smaller model for simple tasks
- stronger model for complex investigation
- maximum investigation depth
- maximum tool calls
- timeout

Example:

```text
Simple classification → small/fast model
Evidence summarization → medium model
Complex investigation → stronger model
```

---

# 48. Model Abstraction

Never hard-code the application to one model vendor.

Use:

```text
ModelProvider
 ├── provider
 ├── model
 ├── capabilities
 ├── context_limit
 ├── cost
 ├── structured_output
 └── tool_calling
```

This enables future model changes.

---

# 49. Agent Orchestrator

The orchestrator should control:

```text
Task
 ↓
Agent selection
 ↓
Permission verification
 ↓
Tool selection
 ↓
Execution
 ↓
Evidence
 ↓
Policy validation
 ↓
Next agent
 ↓
Final result
```

The agent should never decide its own permissions.

---

# 50. Policy Engine

Example:

```yaml
agent: response-agent
action: isolate_host
resource_type: endpoint
risk: high
requires_approval: true
allowed_environment:
  - lab
  - staging
```

Policy decisions:

```text
ALLOW
DENY
REQUIRE_APPROVAL
```

---

# 51. Evidence Model

Evidence should have:

```text
evidence_id
source_event_id
source_type
timestamp
collector
hash
content_reference
confidence
relationship
```

Evidence should be immutable after collection where feasible.

---

# 52. Explainability

Do not expose hidden chain-of-thought.

Instead provide:

```text
Conclusion
Confidence
Evidence
Observed facts
Inference
Uncertainty
Recommended action
```

Example:

```text
Conclusion:
Potential credential misuse.

Confidence:
88%

Observed:
5 failed logins followed by successful login.

Observed:
Login originated from a previously unseen source.

Inference:
Activity is consistent with possible account compromise.

Uncertainty:
No endpoint evidence currently confirms malware.

Recommendation:
Investigate the account and source host.
```

---

# 53. Competitive/Industry Feature Benchmark

We should benchmark our architecture against:

- Google Security Operations agentic capabilities
- Microsoft Defender/agentic SOC direction
- OpenSearch Security Analytics
- Wazuh
- Elastic Security
- Splunk-style SIEM workflows
- open-source SOC automation platforms

The purpose is **feature-gap analysis**, not copying proprietary implementations.

---

# 54. Product Differentiation

CyberSentinel's intended differentiation:

1. Open/modular architecture.
2. Multi-agent investigation.
3. Explicit agent identity.
4. Evidence-grounded AI.
5. Explainable risk.
6. ATT&CK Detection Strategy mapping.
7. Human approval policy engine.
8. Built-in AI-agent security testing.
9. Reproducible benchmark laboratory.
10. Research-ready telemetry and evaluation.

---

# 55. Disaster Recovery

Requirements:

- configuration backup
- database backup
- OpenSearch snapshot
- playbook backup
- rule versioning
- ATT&CK version tracking
- audit-log retention
- recovery testing

Define:

```text
RPO
RTO
Backup frequency
Retention
Restore procedure
```

---

# 56. Multi-Tenant Future Architecture

Future version:

```text
Tenant
 ├── users
 ├── assets
 ├── telemetry
 ├── incidents
 ├── rules
 ├── agents
 ├── policies
 └── audit
```

All tenant identifiers must be enforced server-side.

Never rely on frontend filtering for tenant isolation.

---

# 57. Compliance-Oriented Design

The platform should support mapping to:

- NIST Cybersecurity Framework
- NIST AI RMF concepts
- NIST SP 800-series controls where applicable
- CIS Controls
- MITRE ATT&CK
- OWASP guidance
- organization-specific security policies

Compliance mappings should be stored as metadata rather than hard-coded business logic.

---

# 58. Research Deliverables

At the end of the project:

1. System architecture paper
2. Agent architecture paper
3. Threat model
4. Dataset documentation
5. Benchmark methodology
6. Experimental results
7. Security evaluation
8. AI-agent security evaluation
9. Performance evaluation
10. Limitations
11. Reproducibility guide
12. Demonstration environment

---

# 59. Required Documentation

```text
01_PROJECT_VISION.md
02_PROBLEM_STATEMENT.md
03_LITERATURE_REVIEW.md
04_2026_THREAT_LANDSCAPE.md
05_REQUIREMENTS_SPECIFICATION.md
06_FUNCTIONAL_REQUIREMENTS.md
07_NON_FUNCTIONAL_REQUIREMENTS.md
08_SYSTEM_ARCHITECTURE.md
09_DATA_ARCHITECTURE.md
10_AGENT_ARCHITECTURE.md
11_AGENT_IDENTITY_AUTHORIZATION.md
12_AI_SECURITY_ARCHITECTURE.md
13_THREAT_MODEL.md
14_MITRE_ATTACK_MAPPING.md
15_SIGMA_DETECTION_ARCHITECTURE.md
16_THREAT_INTELLIGENCE.md
17_RAG_ARCHITECTURE.md
18_DATABASE_SCHEMA.md
19_API_SPECIFICATION.md
20_UI_UX_SPECIFICATION.md
21_INCIDENT_LIFECYCLE.md
22_RESPONSE_PLAYBOOKS.md
23_SECURITY_CONTROLS.md
24_PRIVACY.md
25_TESTING_STRATEGY.md
26_ATTACK_SCENARIOS.md
27_DATASET_SPECIFICATION.md
28_BENCHMARK_SPECIFICATION.md
29_RESEARCH_METHODOLOGY.md
30_DEPLOYMENT.md
31_DEVOPS.md
32_MONITORING.md
33_DISASTER_RECOVERY.md
34_IMPLEMENTATION_ROADMAP.md
35_ACCEPTANCE_CRITERIA.md
36_REFERENCE_SOURCES.md
```

---

# 60. Recommended First Release Scope

Do not attempt every feature simultaneously.

### Release 0.1

- authentication
- RBAC
- telemetry ingestion
- normalization
- OpenSearch
- PostgreSQL
- Sigma detection
- alerts
- incidents
- dashboard

### Release 0.2

- ATT&CK
- threat intelligence
- correlation
- timeline
- evidence

### Release 0.3

- Triage Agent
- Investigation Agent
- Threat Intelligence Agent

### Release 0.4

- orchestrator
- tool registry
- agent permissions
- RAG
- hunting

### Release 0.5

- response planning
- approval workflow
- lab response

### Release 0.6

- AI security
- prompt injection tests
- agent identity
- sandbox
- policy engine

### Release 1.0

- benchmark
- attack scenarios
- performance tests
- security tests
- documentation
- deployment package
- research report

---

# 61. Definition of Done for Version 1.0

CyberSentinel AI v1.0 is considered ready only when:

### Detection

- [ ] Known attacks detected
- [ ] Rules tested
- [ ] False positives measured
- [ ] Detection coverage documented

### Investigation

- [ ] Agents gather evidence
- [ ] Evidence is traceable
- [ ] Multi-source correlation works
- [ ] ATT&CK mapping works

### AI

- [ ] Agents have identities
- [ ] Agents have least privilege
- [ ] Tool calls are validated
- [ ] Prompt injection tests pass
- [ ] AI output is grounded
- [ ] AI failures are handled

### Response

- [ ] Playbooks versioned
- [ ] Approval policy works
- [ ] High-impact actions are gated
- [ ] Actions are auditable
- [ ] Lab execution is safe

### Platform

- [ ] Authentication
- [ ] RBAC
- [ ] API security
- [ ] Encryption
- [ ] Logging
- [ ] Monitoring
- [ ] Backup

### Research

- [ ] Ground truth scenarios
- [ ] Baseline comparison
- [ ] Metrics
- [ ] Reproducible experiments
- [ ] Results
- [ ] Limitations

---

# 62. Final Architectural Principle

The final system should follow:

```text
             HUMAN STRATEGY
                   │
                   ▼
          ┌─────────────────┐
          │ POLICY & GOVERN │
          └────────┬────────┘
                   │
                   ▼
          ┌─────────────────┐
          │ AGENTIC LAYER   │
          │ Reason / Search  │
          │ Correlate       │
          │ Recommend       │
          └────────┬────────┘
                   │
                   ▼
          ┌─────────────────┐
          │ SECURITY LOGIC  │
          │ Rules / ML / TI │
          └────────┬────────┘
                   │
                   ▼
          ┌─────────────────┐
          │ SECURITY DATA   │
          │ Events / Assets │
          └─────────────────┘
```

The guiding rule is:

> **AI may reason over security data, but authorization, policy, evidence, and deterministic controls remain the foundation of security decisions.**

---

# 63. Primary References

1. SANS 2026 SOC Report  
   https://www.sans.org/research/security-operations-report

2. Google Cloud Agentic SOC  
   https://cloud.google.com/solutions/security/agentic-soc

3. Microsoft — Reimagining the SOC for the Agentic Era  
   https://www.microsoft.com/en-us/security/blog/2026/09/23/reimagining-the-soc-for-the-agentic-era-in-microsoft-defender/

4. NIST — AI Agent Security RFI Analysis  
   https://www.nist.gov/publications/summary-analysis-responses-request-information-regarding-security-considerations-ai

5. NIST — Software and AI Agent Identity and Authorization  
   https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization

6. NIST — AI Agent Standards Initiative  
   https://www.nist.gov/news-events/news/2026/02/announcing-ai-agent-standards-initiative-interoperable-and-secure

7. NIST — Token and Assertion Protection, IR 8587  
   https://csrc.nist.gov/pubs/ir/8587/final

8. MITRE ATT&CK Detection Strategies  
   https://attack.mitre.org/detectionstrategies/

9. OpenSearch Security Analytics  
   https://docs.opensearch.org/latest/security-analytics/

10. Sigma Specification  
    https://github.com/SigmaHQ/sigma-specification/

11. Wazuh Architecture  
    https://documentation.wazuh.com/current/getting-started/architecture.html

12. OASIS TAXII  
    https://www.oasis-open.org/standard/taxii2-1/

---

# 64. Status

**Research:** Initial comprehensive baseline complete  
**Requirements:** Defined  
**Architecture:** Defined  
**Security model:** Defined  
**Agent model:** Defined  
**Evaluation methodology:** Defined  
**Implementation:** Not started  
**Production readiness:** Not yet claimed

Next engineering step:

> Convert this master specification into implementation-ready epics, user stories, database migrations, API contracts, repository scaffolding, Docker architecture, telemetry schemas, Sigma test cases, agent tool contracts, security policies, and Phase-1 acceptance tests before writing production code.
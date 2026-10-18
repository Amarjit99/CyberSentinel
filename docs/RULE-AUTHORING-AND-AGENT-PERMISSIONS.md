# Rule Authoring and Agent Permission Guide

## Deterministic rule authoring

Rules are the primary detection mechanism. Store Sigma rules under `rules/sigma/` and
correlation rules under `rules/correlation/`. A rule should include:

- stable identifier and title;
- severity and confidence;
- supported log source and canonical fields;
- a narrow detection condition;
- analyst-facing rationale and false-positive notes;
- ATT&CK mapping only when behavior is observed or explicitly marked as inferred;
- a fixture or regression test;
- owner and review date.

Validate a new rule against representative positive, negative, malformed, and duplicate
events before loading it. Avoid broad conditions that turn missing telemetry into evidence.
Rule activation and rollback require an authorized detection-engineering workflow.

Every rule proposed for activation must also include:

- `falsepositives`: one or more concrete benign scenarios for analyst review;
- `data_sources`: one or more telemetry source/category pairs required to evaluate the rule.

The validator emits review diagnostics when either field is missing, and production activation
is blocked until both fields contain meaningful entries. This keeps false-positive expectations
and telemetry prerequisites beside the detection logic rather than in undocumented tribal
knowledge.

## Agent permissions

Agents are constrained by both identity and the central tool registry. Registered tools declare
their required permission, agent allowlist, read-only state, argument schema, quotas, and
result limits. Investigation tools are intended to be read-only.

Approved read-only capabilities include incident, detection, event, evidence, investigation,
threat-intelligence, risk, knowledge, and bounded hunting lookups. There is no unrestricted
shell, arbitrary SQL, or generic URL-fetch tool.

## Permission review checklist

Before enabling or changing a tool:

1. Define a typed input and output schema.
2. Assign the minimum required permission.
3. Mark the tool read-only unless a separate governance review approves otherwise.
4. Restrict the agent types allowed to invoke it.
5. Add query, timeout, result-size, and per-task quotas.
6. Add authorization-negative and malformed-input tests.
7. Verify audit records contain the caller, tool, incident scope, and outcome.
8. Review prompt-injection and sensitive-data handling behavior.

Delegated agents cannot exceed the permissions of their parent context. Tool failures,
authorization denials, quota exhaustion, and provider failures must remain explicit; they must
not be represented as successful empty results.

## Safe change process

Run focused unit/security tests, the full backend suite, Ruff, Mypy, and the frontend build
after changing a rule, tool schema, permission, or policy version. Record the change in the
release notes and retain the prior rule/tool version for rollback.

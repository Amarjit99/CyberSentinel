# Sigma Detection Rules (`rules/sigma`)

## Purpose
Repository of Sigma detection rules formatted according to the SigmaHQ v2 specification and mapped to MITRE ATT&CK techniques.

## Validation & Structure
- Rules are stored in YAML format.
- Every rule must specify:
  - `id`: Deterministic UUID.
  - `title`: Descriptive summary.
  - `status`: `experimental`, `test`, or `stable`.
  - `tags`: MITRE ATT&CK technique IDs (e.g., `attack.t1059.001`).
  - `logsource`: Category/product definition.
  - `detection`: Deterministic boolean logic.
  - `falsepositives`: Maintained benign scenarios that analysts should review.
  - `data_sources`: Explicit telemetry source/category pairs required by the rule.

Rules proposed for activation receive review diagnostics when either metadata field is
missing, and activation is blocked until both fields contain at least one meaningful entry.

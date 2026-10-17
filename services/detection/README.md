# Detection Service (`services/detection`)

## Responsibility
Applies deterministic Sigma rules, threshold detectors, and behavioural heuristics to normalized event streams.

## Rule Standards
- Rules are defined under `rules/sigma/` and versioned deterministically.
- All detections link directly to source events via the `detection_events` relational entity.

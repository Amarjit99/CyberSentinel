# Correlation Rules (`rules/correlation`)

## Purpose
Multi-event, stateful, and temporal correlation rules used by `services/correlation/`.

## Rule Definition
- YAML or declarative JSON schemas specifying sliding time windows, entity join keys, and alert promotion thresholds.
- Enforces suppression of duplicate alerts within configurable deduplication windows.

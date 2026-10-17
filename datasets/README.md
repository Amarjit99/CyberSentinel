# Telemetry & Evaluation Datasets (`datasets`)

## Purpose
Synthetic security event datasets, testing fixtures, and benign baseline telemetry.

## Invariants
- **No Production Telemetry:** Real customer or enterprise data must never be stored here.
- All fixtures must conform to the 23-field `CanonicalEvent` contract (ADR-0005) or recognized raw vendor formats for normalization tests.

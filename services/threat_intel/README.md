# Threat Intelligence Service (`services/threat_intel`)

## Responsibility
Manages threat intelligence enrichment, IOC normalization, MISP/OpenCTI feed ingestion, and indicator caching.

## Security Constraints
External lookups must not leak internal enterprise domains or sensitive internal IP ranges.

# Container Configurations (`infrastructure/docker`)

## Purpose
Docker build contexts, multi-stage Dockerfiles, and runtime container specifications.

## Production Container Standards
- Rootless container execution.
- Read-only root filesystem where feasible.
- Security options: `no-new-privileges:true`.
- Healthcheck probes configured on every service.

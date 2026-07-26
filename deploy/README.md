# `deploy/`

Deployment artifacts — Dockerfiles, Kubernetes manifests, and the CI/CD pipeline definitions
(EDS §15). The design is **cloud-agnostic**: containerized and orchestrator-portable to any
cloud or on-prem, honoring SOC data-sovereignty requirements.

> The local development stack lives at the repository root (`docker-compose.yml`). This folder
> holds **production** packaging and is populated in the **Deployment** sprint.

## Ownership
Security / Platform squad.

## Built in
The **Deployment** sprint (Dockerfiles, K8s manifests, CI/CD gates, progressive rollout +
rollback).

## Testing
Deploy/rollback rehearsal in staging; release gated on eval + security checks.

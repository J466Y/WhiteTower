# White Tower Helm Chart

A production-ready Helm chart for **White Tower**, the open-source, self-hosted control plane governing AI agents.

## Overview

White Tower provides:
- An authoritative inventory and identity provider for AI agents.
- Cedar policy distribution to PEP enforcement points.
- Tamper-evident append-only Merkle tree audit logging with signed checkpoints.
- A cryptographic kill switch and lease renewal mechanism.

This chart deploys White Tower following the **Restricted Pod Security Standard**, high availability best practices, and strict credential separation.

## Security Architecture

### Separation of Duties (ST-62, DC-3)
Database migrations require schema ownership (`whitetower_migrator`), while regular server operations require limited DML permissions (`whitetower_app`).
- Migrations run in a dedicated `migrate` init container. Only the init container mounts `db-migrator-secret` containing the migration role credentials.
- The `whitetower` application container mounts `db-app-secret` only and has no access to migration credentials.

### File-Based Secrets (ST-61, OPS-04, T-10, T-60)
- All secrets (database passwords, Ed25519 checkpoint signing keys, OIDC client secrets, TLS keys) are mounted as read-only files under `/run/secrets/` with strict permissions (`defaultMode: 0400`).
- No sensitive credentials or secrets are passed through environment variables.

### Network Isolation (ST-63, T-11, T-68)
Network policies isolate White Tower's three network listeners:
- **Console (`8443`):** Web console and public REST API, accessible only from Ingress controllers or designated management networks.
- **Machine (`9443`):** Token endpoint and module API (HTTP/2), accessible only from modules and enforcement points (`whitetower.io/module: "true"`, `whitetower.io/enforcement-point: "true"`).
- **Operations (`9090`):** Prometheus metrics (`/metrics`) and health checks (`/healthz`, `/readyz`), accessible only from Prometheus and cluster monitoring.

Egress is restricted to cluster DNS (`53`), PostgreSQL database (`5432`), and explicitly configured custom destinations (such as IdP or OTLP collectors).

### Hardened Execution Environment
- `runAsNonRoot: true`, `runAsUser: 65532`, `runAsGroup: 65532`, `fsGroup: 65532`.
- `readOnlyRootFilesystem: true` with a memory-backed tmpfs at `/tmp`.
- `allowPrivilegeEscalation: false`.
- All Linux capabilities dropped (`capabilities.drop: ["ALL"]`).
- `seccompProfile: { type: RuntimeDefault }`.

### High Availability and Resilience
- Minimum replica count of 2 by default.
- Pod anti-affinity across node hostnames.
- `PodDisruptionBudget` configured with `minAvailable: 1`.
- Rolling update strategy with `maxSurge: 1` and `maxUnavailable: 0`.
- `terminationGracePeriodSeconds: 70` ensures the core can drain active HTTP/2 streams and leases before shutting down.

## Prerequisites

- Kubernetes 1.28+
- Helm 3.10+
- A running PostgreSQL 16 or 17 instance (with `whitetower_migrator` and `whitetower_app` roles configured)
- TLS certificates for console and machine listeners (or existing secrets)

## Installing the Chart

### 1. Create Secrets

Create Kubernetes secrets for the database credentials and signing keys:

```bash
# Database runtime role password
kubectl create secret generic whitetower-db-app \
  --from-literal=password="runtime-secret-password"

# Database migration role password
kubectl create secret generic whitetower-db-migrator \
  --from-literal=password="migration-secret-password"

# Audit checkpoint Ed25519 private key
kubectl create secret generic whitetower-audit-checkpoint \
  --from-file=key.pem=/path/to/checkpoint-signing-key.pem

# TLS certificates
kubectl create secret tls whitetower-tls-console \
  --cert=/path/to/console.crt --key=/path/to/console.key
kubectl create secret tls whitetower-tls-machine \
  --cert=/path/to/machine.crt --key=/path/to/machine.key
```

### 2. Install Chart

```bash
helm install whitetower ./deploy/helm/whitetower \
  --set database.url="postgres://whitetower_app@postgres.default.svc.cluster.local:5432/whitetower?sslmode=verify-full" \
  --set database.migrationUrl="postgres://whitetower_migrator@postgres.default.svc.cluster.local:5432/whitetower?sslmode=verify-full" \
  --set secrets.databaseApp.existingSecret="whitetower-db-app" \
  --set secrets.databaseMigrator.existingSecret="whitetower-db-migrator" \
  --set secrets.auditCheckpointKey.existingSecret="whitetower-audit-checkpoint" \
  --set tls.console.existingSecret="whitetower-tls-console" \
  --set tls.machine.existingSecret="whitetower-tls-machine"
```

## Configuration Parameters

| Parameter | Description | Default |
| --- | --- | --- |
| `replicaCount` | Number of core replicas (minimum 2 for HA) | `2` |
| `image.repository` | Core image repository | `ghcr.io/j466y/whitetower` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `image.tag` | Image tag (defaults to `.Chart.AppVersion`) | `""` |
| `serviceAccount.create` | Whether to create a dedicated ServiceAccount | `true` |
| `serviceAccount.automountServiceAccountToken` | Automount service account token | `false` |
| `podSecurityContext.runAsNonRoot` | Enforce non-root execution | `true` |
| `securityContext.readOnlyRootFilesystem` | Read-only root filesystem | `true` |
| `terminationGracePeriodSeconds` | Drain grace period (> 60s lease TTL) | `70` |
| `strategy.rollingUpdate` | Max surge 1, max unavailable 0 | `{ maxSurge: 1, maxUnavailable: 0 }` |
| `podDisruptionBudget.minAvailable` | Minimum available pods during disruption | `1` |
| `service.console.port` | Port for the Console listener (HTTPS) | `8443` |
| `service.machine.port` | Port for the Machine listener (HTTP/2 HTTPS) | `9443` |
| `service.operations.port` | Port for the Operations listener (HTTP) | `9090` |
| `networkPolicy.enabled` | Enable NetworkPolicy isolation (ST-63) | `true` |
| `serviceMonitor.enabled` | Create Prometheus Operator ServiceMonitor | `false` |

# GuardAgent Gateway

GuardAgent Gateway is a security and privacy layer that sits between your applications and Large Language Models (LLMs). It inspects every request and response, blocks sensitive content, and records decisions for compliance. The project is inspired by commercial solutions like Lasso Security Gateway but is implemented entirely in Go with an emphasis on Brazilian data protection requirements.

## Key Features

- **HTTP and gRPC entrypoints** that proxy traffic to LLM providers.
- **Pattern detection pipeline** using regex, Bloom filters and optional ML models to find CPF, CNPJ and other Brazilian PII.
- **Policy engine** based on Rego rules that can allow, block or redact content.
- **Threat intelligence loader** fetching CVEs and malware indicators (NVD, abuse.ch) into PostgreSQL with a Redis cache.
- **Prometheus metrics** for every component and health endpoints for Kubernetes probes.
- **Container images and Helm charts** to deploy on Kubernetes or Cloud Run.
- **CI workflows** running lint, vet and tests, plus release pipelines that generate SBOMs and SLSA provenance.

## Architecture Overview

```
Client ──▶ HTTP/GRPC Gateway ──▶ Detection Pipeline ──▶ Policy Engine ──▶ LLM
                         │                        │
                         │                        └──▶ Metrics & Audit Logs
                         └──▶ Threat Intel Loader (CronJob) ──▶ PostgreSQL/Redis
```

The gateway exposes `/v1/filter` for REST and the `Filter` gRPC service. Incoming text is analysed by the detector which combines regex patterns and machine learning. Results are evaluated by the policy engine that can block or sanitize the content. Decisions and metrics are exported for observability.

## Quick Start

### Simple Local Development

For quick local development and testing:

```bash
go run ./cmd/guardagent
```

Metrics are available on `:9090/metrics`.

### Full Production Setup

1. **Run Postgres and Redis**, then start the gateway with full configuration:

```bash
export GA_DB_DSN="postgres://postgres:postgres@localhost:5432/guardagent?sslmode=disable"
export GA_REDIS_ADDR="localhost:6379"

go run ./cmd/guardagent --http-port 8080 --grpc-port 9090 \
    --policy-dir ./config/policies \
    --threat-sources ./config/threat_sources.yaml
```

2. **Invoke the HTTP API**:

```bash
curl -X POST http://localhost:8080/v1/filter -d "text=CPF 123.456.789-00" -H "X-Tenant-ID: demo"
```

3. **Build and run with Docker**:

```bash
docker build -t guardagent:latest .
docker run -p 8080:8080 -p 9090:9090 guardagent:latest
```

## Development

The repository uses Go modules. Static checks and tests can be run with:

```bash
go vet ./...
golangci-lint run ./...
go test ./...
```

End‑to‑end scripts in `tests/e2e` exercise the detector and policy engine once the service is running locally.

## Deployment

A `Dockerfile` builds a distroless image and `.github/workflows` contain CI pipelines. Kubernetes manifests live in `deploy/k8s` and a reusable Helm chart is under `deploy/helm/guardagent`.

To deploy the threat‑intelligence loader, apply `deploy/k8s/cronjob-loader.yaml`; it runs periodically and stores indicators in PostgreSQL while caching the most frequent lookups in Redis.

## Further Documentation

Detailed architecture notes, roadmap and threat intelligence feed configuration can be found in the `docs/` directory:

- `docs/guardagent-security-engine.md` – design of the detection and policy layers.
- `docs/threat-intelligence-feeds.md` – configuration and code snippets for feed management.
- `docs/implementation-roadmap.md` – milestones for versions 0.6 and beyond.

GuardAgent is under active development, and contributions are welcome.

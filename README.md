# GuardAgent Gateway

This project provides a lightweight HTTP and gRPC gateway that filters requests to LLM providers. It exposes a `/v1/filter` endpoint and integrates the enhanced pattern detector and policy engine.

## Quick Start

```bash
go run ./cmd/guardagent
```

Metrics are available on `:9090/metrics`.

Docker image can be built with:

```bash
docker build -t guardagent:latest .
```

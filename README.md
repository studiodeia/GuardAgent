# GuardAgent Gateway

This project provides an HTTP and gRPC gateway that filters requests to LLM providers. It contains an enhanced pattern detector and policy engine that block sensitive content.

## Quick Start

```bash
# Start the service with default ports
GA_DB_DSN="postgres://postgres:postgres@localhost:5432/guardagent?sslmode=disable" \
GA_REDIS_ADDR="localhost:6379" \
 go run ./cmd/guardagent --http-port 8080 --grpc-port 9090
```

Metrics are exported on `:9090/metrics`.

Docker images can be built and run locally:

```bash
docker build -t guardagent:latest .
docker run -p 8080:8080 -p 9090:9090 guardagent:latest
```

End-to-end tests live in `tests/e2e`. They assume the service is running locally:

```bash
bash tests/e2e/detection_flow.sh
bash tests/e2e/policy_flow.sh
```

The threat intelligence loader can be triggered with:

```bash
go run ./cmd/feed-loader --once
```


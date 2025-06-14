#!/bin/bash
set -e
BASE_URL="http://localhost:8080"

echo "🧪 Testing Enhanced Detection..."

response=$(curl -s -X POST "$BASE_URL/api/v1/analyze" \
  -H "Content-Type: application/json" \
  -d '{"text":"CPF: 123.456.789-01"}')

if echo "$response" | jq -e '.detected_pii[] | select(.type=="cpf")' > /dev/null; then
    echo "✅ CPF detection working"
else
    echo "❌ CPF detection failed"
    exit 1
fi

start_time=$(date +%s%N)
for i in {1..100}; do
    curl -s -X POST "$BASE_URL/api/v1/analyze" \
      -H "Content-Type: application/json" \
      -d '{"text":"Same text for cache test"}' > /dev/null
done
end_time=$(date +%s%N)

avg_latency=$(( (end_time - start_time) / 100000000 ))
if [ $avg_latency -lt 50 ]; then
    echo "✅ Cache performance: ${avg_latency}ms avg"
else
    echo "❌ Cache performance degraded: ${avg_latency}ms"
    exit 1
fi

echo "🎉 E2E tests passed!"

#!/bin/bash
set -e
BASE_URL="http://localhost:8080"

echo "🧪 Testing Policy Engine..."

response=$(curl -s -X POST "$BASE_URL/api/v1/policy/evaluate" \
  -H "Content-Type: application/json" \
  -d '{"threat_type":"pii","confidence":0.95,"risk_score":0.2}')

if echo "$response" | jq -e '.deny' > /dev/null; then
    echo "✅ Policy denial triggered"
else
    echo "❌ Policy denial failed"
    exit 1
fi

echo "🎉 Policy tests passed!"

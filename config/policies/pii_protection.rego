package guardagent.policies

import future.keywords.in

default allow = false
default sanitize = false

# Block high-confidence PII during business hours
deny[msg] {
    input.threat_type == "pii"
    input.confidence > 0.9
    is_business_hours
    msg := "PII detected during business hours"
}

# Sanitize medium-confidence PII
sanitize {
    input.threat_type == "pii"
    input.confidence > 0.7
    input.confidence <= 0.9
}

# Allow low-risk requests
allow {
    input.risk_score < 0.3
}

is_business_hours {
    hour := time.clock(time.now_ns())[0]
    hour >= 9
    hour <= 17
}

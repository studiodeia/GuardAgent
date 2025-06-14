package common

// ThreatType represents different categories of threats detected by the gateway.
type ThreatType string

const (
	ThreatPII             ThreatType = "pii"
	ThreatPromptInjection ThreatType = "prompt_injection"
	ThreatMalware         ThreatType = "malicious_code"
	ThreatAnomalous       ThreatType = "anomalous_behavior"
)

// SeverityLevel denotes the severity of a detection result.
type SeverityLevel int

const (
	SeverityLow SeverityLevel = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// RiskLevel represents calculated risk levels.
type RiskLevel int

const (
	RiskNone RiskLevel = iota
	RiskLow
	RiskMedium
	RiskHigh
	RiskCritical
)

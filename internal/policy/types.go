package policy

import (
	"context"
	"time"
)

// Engine defines the interface for policy evaluation engines.
type Engine interface {
	Evaluate(ctx context.Context, req *Request) (*Decision, error)
	LoadPolicies(ctx context.Context, policies []Policy) error
	GetMetrics() *EngineMetrics
}

	Rules           []string
	Timeout         time.Duration
// Request represents an incoming request to be evaluated by the policy engine.
type Request struct {
	ID        string
	TenantID  string
	Timestamp time.Time
	Content   string
	Metadata  map[string]interface{}
	Analysis  *ThreatAnalysis
}

// Policy represents a security policy with rules and actions.
type Policy struct {
	ID          string
	Name        string
	Description string
	TenantID    string
	Version     string
	Rules       []Rule
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Rule defines conditions and actions for policy evaluation.
type Rule struct {
	ID          string
	Name        string
	Description string
	Condition   string // Rego expression or similar
	Actions     []Action
	Priority    int
	Enabled     bool
}

// ThreatAnalysis contains the results of threat detection analysis.
type ThreatAnalysis struct {
	Score       float64
	Confidence  float64
	Threats     []DetectedThreat
	PIIMatches  []PIIMatch
	Indicators  []ThreatIndicator
}

// DetectedThreat represents a specific threat found in the content.
type DetectedThreat struct {
	Type        string
	Severity    string
	Description string
	Location    Location
	Confidence  float64
}

// PIIMatch represents detected personally identifiable information.
type PIIMatch struct {
	Type        string // CPF, CNPJ, Email, etc.
	Value       string
	Location    Location
	Confidence  float64
	Redacted    bool
}

// ThreatIndicator represents a threat intelligence indicator match.
type ThreatIndicator struct {
	Type        string // IP, Domain, Hash, etc.
	Value       string
	Source      string
	Severity    string
	Description string
	LastSeen    time.Time
}

// Location represents the position of a match in the content.
type Location struct {
	Start int
	End   int
	Line  int
	Column int
}

// Decision represents the policy engine's evaluation result.
type Decision struct {
	RequestID   string
	TenantID    string
	Timestamp   time.Time
	Action      Action
	Reasons     []string
	Score       float64
	Analysis    *ThreatAnalysis
	RulesApplied []string
}

// EngineMetrics contains operational metrics for the policy engine.
type EngineMetrics struct {
	RequestsProcessed   int64
	RequestsBlocked     int64
	RequestsAllowed     int64
	RequestsRedacted    int64
	AverageLatency      time.Duration
	PolicyViolations    int64
	ThreatDetections    int64
}

// RegoEngine implements the Engine interface using Open Policy Agent's Rego.
type RegoEngine struct {
	policies map[string]*Policy
	metrics  *EngineMetrics
}

// NewRegoEngine creates a new Rego-based policy engine.
func NewRegoEngine() *RegoEngine {
	return &RegoEngine{
		policies: make(map[string]*Policy),
		metrics:  &EngineMetrics{},
	}
}

// Evaluate processes a request through the policy engine.
func (e *RegoEngine) Evaluate(ctx context.Context, req *Request) (*Decision, error) {
	// Simplified implementation - would contain full Rego evaluation logic
	decision := &Decision{
		RequestID: req.ID,
		TenantID:  req.TenantID,
		Timestamp: time.Now(),
		Action:    Action{Type: ActionAllow},
		Analysis:  req.Analysis,
	}
	
	e.metrics.RequestsProcessed++
	e.metrics.RequestsAllowed++
	
	return decision, nil
}

// LoadPolicies loads policies into the engine.
func (e *RegoEngine) LoadPolicies(ctx context.Context, policies []Policy) error {
	for _, policy := range policies {
		e.policies[policy.ID] = &policy
	}
	return nil
}

// GetMetrics returns current engine metrics.
func (e *RegoEngine) GetMetrics() *EngineMetrics {
	return e.metrics
}

// ValidatePolicy validates a policy configuration.
func (e *RegoEngine) ValidatePolicy(policy *Policy) error {
	// Simplified validation - would contain full policy validation logic
	return nil
}

// CompileRules compiles policy rules for efficient evaluation.
func (e *RegoEngine) CompileRules(rules []Rule) error {
	// Simplified compilation - would contain full rule compilation logic
	return nil
}

/* ------------------------------------------------------------------ */
/* -------------------------  ACTIONS & DTOS  ---------------------- */
/* ------------------------------------------------------------------ */

// ActionType defines possible actions after policy decision.
type ActionType string

const (
	ActionAllow  ActionType = "allow"
	ActionBlock  ActionType = "block"
	ActionRedact ActionType = "redact"
	ActionLog    ActionType = "log"
	ActionAlert  ActionType = "alert"
)

// PolicyDecision represents the engine decision for a request.
type PolicyDecision struct {
	RequestID string
	TenantID  string
	Timestamp time.Time
	Analysis  *ThreatAnalysis
	Action    Action
}

// Action defines how the gateway should react.
type Action struct {
	Type         ActionType
	Parameters   map[string]string
	Fallback     *Action
	Webhook      *WebhookConfig
	Notification *NotificationConfig
}

// WebhookConfig for external webhook triggers.
type WebhookConfig struct {
	URL     string
	Method  string
	Headers map[string]string
	Timeout time.Duration
}

// NotificationConfig for notification channels (Slack, email, etc.).
type NotificationConfig struct {
	Channel string
	Target  string
	Message string
}
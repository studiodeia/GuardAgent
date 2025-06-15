package policy

import (
	"context"
	"time"
)

type SimpleEngine struct{}

func NewEnhancedPolicyEngine(config *PolicyConfig) *SimpleEngine { return &SimpleEngine{} }

func (pe *SimpleEngine) Evaluate(ctx context.Context, analysis *ThreatAnalysis, request *Request) (*PolicyDecision, error) {
	decision := &PolicyDecision{
		RequestID: request.ID,
		TenantID:  request.TenantID,
		Timestamp: time.Now(),
		Analysis:  analysis,
		Action:    Action{Type: ActionAllow},
	}
	return decision, nil
}

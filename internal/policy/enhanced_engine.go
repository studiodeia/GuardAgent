// internal/policy/enhanced_engine.go
package policy

import (
    "context"
    "encoding/json"
    "fmt"
    "sort"
    "time"
    "sync"
    "strings"
    "regexp"
)

// Enhanced PolicyEngine with Git-based policies and OPA-like evaluation
type EnhancedPolicyEngine struct {
    rules       []Rule
    cache       *PolicyCache
    metrics     *PolicyMetrics
    gitRepo     *GitPolicyRepo
    evaluator   *PolicyEvaluator
    mu          sync.RWMutex
}

type Rule struct {
    ID          string            `json:"id" yaml:"id"`
    Name        string            `json:"name" yaml:"name"`
    Version     string            `json:"version" yaml:"version"`
    Condition   Condition         `json:"condition" yaml:"condition"`
    Action      Action            `json:"action" yaml:"action"`
    Priority    int               `json:"priority" yaml:"priority"`
    Enabled     bool              `json:"enabled" yaml:"enabled"`
    TenantID    string            `json:"tenant_id,omitempty" yaml:"tenant_id,omitempty"`
    Environment string            `json:"environment,omitempty" yaml:"environment,omitempty"`
    Metadata    map[string]string `json:"metadata" yaml:"metadata"`
    CreatedAt   time.Time         `json:"created_at" yaml:"created_at"`
    UpdatedAt   time.Time         `json:"updated_at" yaml:"updated_at"`
}

type Condition struct {
    // Threat-based conditions
    ThreatTypes    []ThreatType `json:"threat_types,omitempty" yaml:"threat_types,omitempty"`
    MinRisk        float64      `json:"min_risk,omitempty" yaml:"min_risk,omitempty"`
    MaxRisk        float64      `json:"max_risk,omitempty" yaml:"max_risk,omitempty"`
    MinConfidence  float64      `json:"min_confidence,omitempty" yaml:"min_confidence,omitempty"`
    
    // Context-based conditions
    TenantID       string       `json:"tenant_id,omitempty" yaml:"tenant_id,omitempty"`
    Environment    string       `json:"environment,omitempty" yaml:"environment,omitempty"`
    UserAgent      string       `json:"user_agent,omitempty" yaml:"user_agent,omitempty"`
    SourceIP       string       `json:"source_ip,omitempty" yaml:"source_ip,omitempty"`
    
    // Time-based conditions
    TimeRange      *TimeRange   `json:"time_range,omitempty" yaml:"time_range,omitempty"`
    DayOfWeek      []string     `json:"day_of_week,omitempty" yaml:"day_of_week,omitempty"`
    
    // Content-based conditions
    PayloadSize    *SizeRange   `json:"payload_size,omitempty" yaml:"payload_size,omitempty"`
    ContentType    []string     `json:"content_type,omitempty" yaml:"content_type,omitempty"`
    
    // Advanced conditions (Rego-like)
    Expression     string       `json:"expression,omitempty" yaml:"expression,omitempty"`
}

type TimeRange struct {
    Start string `json:"start" yaml:"start"` // HH:MM format
    End   string `json:"end" yaml:"end"`     // HH:MM format
}

type SizeRange struct {
    Min int64 `json:"min,omitempty" yaml:"min,omitempty"`
    Max int64 `json:"max,omitempty" yaml:"max,omitempty"`
}

type Action struct {
    Type        ActionType        `json:"type" yaml:"type"`
    Parameters  map[string]string `json:"parameters,omitempty" yaml:"parameters,omitempty"`
    Fallback    *Action           `json:"fallback,omitempty" yaml:"fallback,omitempty"`
    Webhook     *WebhookConfig    `json:"webhook,omitempty" yaml:"webhook,omitempty"`
    Notification *NotificationConfig `json:"notification,omitempty" yaml:"notification,omitempty"`
}

type WebhookConfig struct {
    URL     string            `json:"url" yaml:"url"`
    Method  string            `json:"method" yaml:"method"`
    Headers map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
    Timeout time.Duration     `json:"timeout" yaml:"timeout"`
}

type NotificationConfig struct {
    Channel string `json:"channel" yaml:"channel"` // slack, email, pagerduty
    Target  string `json:"target" yaml:"target"`   // channel name, email, etc.
    Message string `json:"message" yaml:"message"`
}

type PolicyDecision struct {
    RequestID    string           `json:"request_id"`
    TenantID     string           `json:"tenant_id"`
    Timestamp    time.Time        `json:"timestamp"`
    Analysis     *ThreatAnalysis  `json:"analysis"`
    MatchedRule  *Rule            `json:"matched_rule,omitempty"`
    Action       Action           `json:"action"`
    Reason       string           `json:"reason"`
    Confidence   float64          `json:"confidence"`
    ProcessingTime time.Duration  `json:"processing_time"`
    Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

func NewEnhancedPolicyEngine(config *PolicyConfig) *EnhancedPolicyEngine {
    engine := &EnhancedPolicyEngine{
        rules:     make([]Rule, 0),
        cache:     NewPolicyCache(1000, 5*time.Minute),
        metrics:   NewPolicyMetrics(),
        gitRepo:   NewGitPolicyRepo(config.GitRepo),
        evaluator: NewPolicyEvaluator(),
    }
    
    // Load initial policies
    if err := engine.LoadPolicies(); err != nil {
        // Log error but continue
        fmt.Printf("Failed to load initial policies: %v\n", err)
    }
    
    // Start policy refresh goroutine
    go engine.refreshPolicies(config.RefreshInterval)
    
    return engine
}

func (pe *EnhancedPolicyEngine) Evaluate(ctx context.Context, analysis *ThreatAnalysis, request *Request) (*PolicyDecision, error) {
    start := time.Now()
    defer func() {
        pe.metrics.EvaluationDuration.Observe(time.Since(start).Seconds())
    }()
    
    // Create cache key
    cacheKey := pe.generateCacheKey(analysis, request)
    
    // Check cache first
    if cached, found := pe.cache.Get(cacheKey); found {
        pe.metrics.CacheHits.Inc()
        decision := cached.(*PolicyDecision)
        decision.ProcessingTime = time.Since(start)
        return decision, nil
    }
    
    pe.metrics.CacheMisses.Inc()
    
    decision := &PolicyDecision{
        RequestID:      request.ID,
        TenantID:       request.TenantID,
        Timestamp:      time.Now(),
        Analysis:       analysis,
        ProcessingTime: 0, // Will be set at the end
    }
    
    // Get applicable rules for tenant
    applicableRules := pe.getApplicableRules(request.TenantID, request.Environment)
    
    // Sort rules by priority (higher priority first)
    sort.Slice(applicableRules, func(i, j int) bool {
        return applicableRules[i].Priority > applicableRules[j].Priority
    })
    
    // Evaluate rules in order
    for _, rule := range applicableRules {
        if !rule.Enabled {
            continue
        }
        
        matches, confidence, err := pe.evaluateRule(rule, analysis, request)
        if err != nil {
            pe.metrics.EvaluationErrors.WithLabelValues(rule.ID).Inc()
            continue
        }
        
        if matches {
            decision.MatchedRule = &rule
            decision.Action = rule.Action
            decision.Reason = pe.generateReason(rule, analysis)
            decision.Confidence = confidence
            
            // Execute action
            if err := pe.executeAction(ctx, rule.Action, request, analysis); err != nil {
                // Try fallback if available
                if rule.Action.Fallback != nil {
                    decision.Action = *rule.Action.Fallback
                    err = pe.executeAction(ctx, *rule.Action.Fallback, request, analysis)
                }
                
                if err != nil {
                    pe.metrics.ActionErrors.WithLabelValues(string(rule.Action.Type)).Inc()
                    return nil, fmt.Errorf("failed to execute action: %w", err)
                }
            }
            
            pe.metrics.RulesMatched.WithLabelValues(rule.ID).Inc()
            break // First matching rule wins
        }
    }
    
    // If no rule matched, apply default policy
    if decision.MatchedRule == nil {
        decision.Action = pe.getDefaultAction(analysis, request)
        decision.Reason = "No specific rule matched, applying default policy"
        decision.Confidence = 0.5
    }
    
    decision.ProcessingTime = time.Since(start)
    
    // Cache the decision
    pe.cache.Set(cacheKey, decision)
    
    return decision, nil
}

func (pe *EnhancedPolicyEngine) evaluateRule(rule Rule, analysis *ThreatAnalysis, request *Request) (bool, float64, error) {
    condition := rule.Condition
    confidence := 1.0
    
    // Evaluate threat types
    if len(condition.ThreatTypes) > 0 {
        hasMatchingThreat := false
        for _, result := range analysis.Results {
            for _, threatType := range condition.ThreatTypes {
                if result.Type == threatType {
                    hasMatchingThreat = true
                    confidence = min(confidence, result.Confidence)
                    break
                }
            }
            if hasMatchingThreat {
                break
            }
        }
        if !hasMatchingThreat {
            return false, 0, nil
        }
    }
    
    // Evaluate risk range
    if condition.MinRisk > 0 && analysis.MaxRisk < condition.MinRisk {
        return false, 0, nil
    }
    if condition.MaxRisk > 0 && analysis.MaxRisk > condition.MaxRisk {
        return false, 0, nil
    }
    
    // Evaluate confidence threshold
    if condition.MinConfidence > 0 {
        maxConfidence := 0.0
        for _, result := range analysis.Results {
            if result.Confidence > maxConfidence {
                maxConfidence = result.Confidence
            }
        }
        if maxConfidence < condition.MinConfidence {
            return false, 0, nil
        }
    }
    
    // Evaluate tenant
    if condition.TenantID != "" && condition.TenantID != request.TenantID {
        return false, 0, nil
    }
    
    // Evaluate environment
    if condition.Environment != "" && condition.Environment != request.Environment {
        return false, 0, nil
    }
    
    // Evaluate user agent
    if condition.UserAgent != "" {
        matched, err := regexp.MatchString(condition.UserAgent, request.UserAgent)
        if err != nil || !matched {
            return false, 0, nil
        }
    }
    
    // Evaluate source IP
    if condition.SourceIP != "" {
        if !pe.matchesIPPattern(condition.SourceIP, request.SourceIP) {
            return false, 0, nil
        }
    }
    
    // Evaluate time range
    if condition.TimeRange != nil {
        if !pe.isInTimeRange(condition.TimeRange) {
            return false, 0, nil
        }
    }
    
    // Evaluate day of week
    if len(condition.DayOfWeek) > 0 {
        currentDay := time.Now().Weekday().String()
        found := false
        for _, day := range condition.DayOfWeek {
            if strings.EqualFold(day, currentDay) {
                found = true
                break
            }
        }
        if !found {
            return false, 0, nil
        }
    }
    
    // Evaluate payload size
    if condition.PayloadSize != nil {
        size := int64(len(request.Payload))
        if condition.PayloadSize.Min > 0 && size < condition.PayloadSize.Min {
            return false, 0, nil
        }
        if condition.PayloadSize.Max > 0 && size > condition.PayloadSize.Max {
            return false, 0, nil
        }
    }
    
    // Evaluate content type
    if len(condition.ContentType) > 0 {
        found := false
        for _, ct := range condition.ContentType {
            if strings.Contains(request.ContentType, ct) {
                found = true
                break
            }
        }
        if !found {
            return false, 0, nil
        }
    }
    
    // Evaluate advanced expression (Rego-like)
    if condition.Expression != "" {
        result, err := pe.evaluator.Evaluate(condition.Expression, analysis, request)
        if err != nil {
            return false, 0, err
        }
        if !result {
            return false, 0, nil
        }
    }
    
    return true, confidence, nil
}

func (pe *EnhancedPolicyEngine) executeAction(ctx context.Context, action Action, request *Request, analysis *ThreatAnalysis) error {
    switch action.Type {
    case ActionAllow:
        return nil // No action needed
        
    case ActionBlock:
        return &SecurityBlockError{
            Reason:    action.Parameters["reason"],
            RiskScore: analysis.MaxRisk,
            PolicyID:  action.Parameters["policy_id"],
        }
        
    case ActionRedact:
        return pe.redactSensitiveData(request, action.Parameters)
        
    case ActionSanitize:
        return pe.sanitizePayload(request, action.Parameters)
        
    case ActionLog:
        return pe.logSecurityEvent(request, analysis, action.Parameters)
        
    case ActionAlert:
        return pe.sendAlert(request, analysis, action)
        
    default:
        return fmt.Errorf("unknown action type: %s", action.Type)
    }
}

func (pe *EnhancedPolicyEngine) redactSensitiveData(request *Request, params map[string]string) error {
    // Implement PII redaction logic
    redactionType := params["type"]
    
    switch redactionType {
    case "pii":
        // Redact PII data
        request.Payload = pe.redactPII(request.Payload)
    case "secrets":
        // Redact secrets
        request.Payload = pe.redactSecrets(request.Payload)
    default:
        // Generic redaction
        request.Payload = pe.genericRedaction(request.Payload)
    }
    
    return nil
}

func (pe *EnhancedPolicyEngine) sanitizePayload(request *Request, params map[string]string) error {
    // Implement payload sanitization
    sanitizationType := params["type"]
    
    switch sanitizationType {
    case "html":
        request.Payload = pe.sanitizeHTML(request.Payload)
    case "sql":
        request.Payload = pe.sanitizeSQL(request.Payload)
    case "script":
        request.Payload = pe.sanitizeScript(request.Payload)
    }
    
    return nil
}

func (pe *EnhancedPolicyEngine) logSecurityEvent(request *Request, analysis *ThreatAnalysis, params map[string]string) error {
    event := SecurityEvent{
        Timestamp:   time.Now(),
        RequestID:   request.ID,
        TenantID:    request.TenantID,
        EventType:   params["event_type"],
        Severity:    params["severity"],
        Analysis:    analysis,
        SourceIP:    request.SourceIP,
        UserAgent:   request.UserAgent,
        Metadata:    params,
    }
    
    return pe.auditLogger.Log(event)
}

func (pe *EnhancedPolicyEngine) sendAlert(request *Request, analysis *ThreatAnalysis, action Action) error {
    if action.Notification != nil {
        alert := Alert{
            Channel:   action.Notification.Channel,
            Target:    action.Notification.Target,
            Message:   action.Notification.Message,
            Severity:  "high",
            Timestamp: time.Now(),
            Metadata: map[string]interface{}{
                "request_id": request.ID,
                "tenant_id":  request.TenantID,
                "risk_score": analysis.MaxRisk,
            },
        }
        
        return pe.notificationService.Send(alert)
    }
    
    if action.Webhook != nil {
        return pe.sendWebhook(action.Webhook, request, analysis)
    }
    
    return nil
}

func (pe *EnhancedPolicyEngine) sendWebhook(webhook *WebhookConfig, request *Request, analysis *ThreatAnalysis) error {
    payload := map[string]interface{}{
        "request_id": request.ID,
        "tenant_id":  request.TenantID,
        "timestamp":  time.Now(),
        "analysis":   analysis,
        "source_ip":  request.SourceIP,
    }
    
    jsonPayload, err := json.Marshal(payload)
    if err != nil {
        return err
    }
    
    // Send HTTP request to webhook URL
    // Implementation would use http.Client with timeout
    return pe.httpClient.SendWebhook(webhook.URL, webhook.Method, webhook.Headers, jsonPayload, webhook.Timeout)
}

func (pe *EnhancedPolicyEngine) getApplicableRules(tenantID, environment string) []Rule {
    pe.mu.RLock()
    defer pe.mu.RUnlock()
    
    var applicable []Rule
    for _, rule := range pe.rules {
        // Check if rule applies to this tenant
        if rule.TenantID != "" && rule.TenantID != tenantID {
            continue
        }
        
        // Check if rule applies to this environment
        if rule.Environment != "" && rule.Environment != environment {
            continue
        }
        
        applicable = append(applicable, rule)
    }
    
    return applicable
}

func (pe *EnhancedPolicyEngine) getDefaultAction(analysis *ThreatAnalysis, request *Request) Action {
    // Default policy based on risk level
    if analysis.MaxRisk >= 0.8 {
        return Action{Type: ActionBlock, Parameters: map[string]string{"reason": "High risk detected"}}
    } else if analysis.MaxRisk >= 0.5 {
        return Action{Type: ActionLog, Parameters: map[string]string{"event_type": "medium_risk"}}
    }
    
    return Action{Type: ActionAllow}
}

func (pe *EnhancedPolicyEngine) LoadPolicies() error {
    rules, err := pe.gitRepo.LoadRules()
    if err != nil {
        return err
    }
    
    pe.mu.Lock()
    pe.rules = rules
    pe.mu.Unlock()
    
    pe.metrics.PoliciesLoaded.Set(float64(len(rules)))
    return nil
}

func (pe *EnhancedPolicyEngine) refreshPolicies(interval time.Duration) {
    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    
    for range ticker.C {
        if err := pe.LoadPolicies(); err != nil {
            pe.metrics.PolicyLoadErrors.Inc()
            // Log error but continue
        }
    }
}

func (pe *EnhancedPolicyEngine) generateCacheKey(analysis *ThreatAnalysis, request *Request) string {
    // Generate a cache key based on relevant request attributes
    key := fmt.Sprintf("%s_%s_%s_%.2f", 
        request.TenantID, 
        request.Environment, 
        request.ContentType, 
        analysis.MaxRisk)
    
    return key
}

func (pe *EnhancedPolicyEngine) generateReason(rule Rule, analysis *ThreatAnalysis) string {
    reasons := []string{fmt.Sprintf("Rule '%s' matched", rule.Name)}
    
    for _, result := range analysis.Results {
        if result.Confidence > 0.7 {
            reasons = append(reasons, fmt.Sprintf("%s detected (confidence: %.2f)", 
                result.Type, result.Confidence))
        }
    }
    
    return strings.Join(reasons, "; ")
}

func (pe *EnhancedPolicyEngine) matchesIPPattern(pattern, ip string) bool {
    // Simple IP pattern matching (could be enhanced with CIDR support)
    if pattern == "*" {
        return true
    }
    
    matched, err := regexp.MatchString(pattern, ip)
    return err == nil && matched
}

func (pe *EnhancedPolicyEngine) isInTimeRange(timeRange *TimeRange) bool {
    now := time.Now()
    currentTime := now.Format("15:04")
    
    return currentTime >= timeRange.Start && currentTime <= timeRange.End
}

// Helper functions for data processing
func (pe *EnhancedPolicyEngine) redactPII(payload []byte) []byte {
    // Implement PII redaction
    return payload
}

func (pe *EnhancedPolicyEngine) redactSecrets(payload []byte) []byte {
    // Implement secrets redaction
    return payload
}

func (pe *EnhancedPolicyEngine) genericRedaction(payload []byte) []byte {
    // Implement generic redaction
    return payload
}

func (pe *EnhancedPolicyEngine) sanitizeHTML(payload []byte) []byte {
    // Implement HTML sanitization
    return payload
}

func (pe *EnhancedPolicyEngine) sanitizeSQL(payload []byte) []byte {
    // Implement SQL injection sanitization
    return payload
}

func (pe *EnhancedPolicyEngine) sanitizeScript(payload []byte) []byte {
    // Implement script sanitization
    return payload
}

func min(a, b float64) float64 {
    if a < b {
        return a
    }
    return b
}

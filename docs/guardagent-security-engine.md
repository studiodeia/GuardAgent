# GuardAgent Security Engine - Desenvolvimento Próprio

## 🎯 Análise da Arquitetura Lasso (Para Inspiração)

### Core Components do Lasso Security Gateway
```yaml
lasso_architecture:
  threat_intel_engine:
    - real_time_feeds: "CVE, malware signatures, IP reputation"
    - pattern_matching: "YARA rules + ML models"
    - risk_scoring: "Weighted threat indicators"
    
  policy_engine:
    - language: "Rego (Open Policy Agent)"
    - execution: "WebAssembly for performance"
    - versioning: "Git-based policy management"
    
  detection_pipeline:
    - preprocessing: "Tokenization, normalization"
    - parallel_analysis: "Multiple detection engines"
    - result_aggregation: "Confidence scoring"
    
  response_engine:
    - actions: "block, allow, monitor, quarantine"
    - notifications: "Real-time alerts"
    - forensics: "Detailed audit trails"
```

## 🏗️ Nossa Implementação - GuardAgent Security Engine

### 1. Threat Intelligence Engine Próprio

```go
// internal/threat/engine.go
package threat

type ThreatIntelEngine struct {
    sources   []ThreatSource
    store     ThreatStore
    cache     Cache
    processor *PatternProcessor
    ml        *MLEngine
}

type ThreatIndicator struct {
    ID          string            `json:"id"`
    Type        ThreatType        `json:"type"`
    Pattern     string            `json:"pattern"`
    Severity    SeverityLevel     `json:"severity"`
    Confidence  float64           `json:"confidence"`
    TTL         time.Duration     `json:"ttl"`
    Source      string            `json:"source"`
    Metadata    map[string]string `json:"metadata"`
    CreatedAt   time.Time         `json:"created_at"`
}

// Threat Sources (Feeds Públicos + Próprios)
type ThreatSource interface {
    Name() string
    Fetch(ctx context.Context) ([]ThreatIndicator, error)
    UpdateFrequency() time.Duration
}

// CVE Feed Implementation
type CVEFeed struct {
    URL    string
    APIKey string
}

func (c *CVEFeed) Fetch(ctx context.Context) ([]ThreatIndicator, error) {
    resp, err := http.Get(c.URL + "/cves/2.0?resultsPerPage=2000")
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var cveData CVEResponse
    if err := json.NewDecoder(resp.Body).Decode(&cveData); err != nil {
        return nil, err
    }
    
    indicators := make([]ThreatIndicator, 0, len(cveData.Vulnerabilities))
    for _, vuln := range cveData.Vulnerabilities {
        indicator := ThreatIndicator{
            ID:         vuln.CVE.ID,
            Type:       ThreatVulnerability,
            Pattern:    extractPattern(vuln.CVE.Description),
            Severity:   mapCVSSSeverity(vuln.CVE.Metrics),
            Confidence: 0.9,
            TTL:        24 * time.Hour,
            Source:     "nvd.nist.gov",
            Metadata: map[string]string{
                "cvss_score": fmt.Sprintf("%.1f", vuln.CVE.Metrics.CVSSV3.BaseScore),
                "vector":     vuln.CVE.Metrics.CVSSV3.VectorString,
            },
            CreatedAt: time.Now(),
        }
        indicators = append(indicators, indicator)
    }
    
    return indicators, nil
}

// Malware Signatures Feed
type MalwareFeed struct {
    URL string
}

func (m *MalwareFeed) Fetch(ctx context.Context) ([]ThreatIndicator, error) {
    // Fetch from abuse.ch, malware bazaar, etc.
    resp, err := http.Get("https://bazaar.abuse.ch/export/csv/recent/")
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    reader := csv.NewReader(resp.Body)
    records, err := reader.ReadAll()
    if err != nil {
        return nil, err
    }
    
    indicators := make([]ThreatIndicator, 0, len(records))
    for _, record := range records[1:] { // Skip header
        if len(record) >= 8 {
            indicator := ThreatIndicator{
                ID:         record[0], // SHA256
                Type:       ThreatMalware,
                Pattern:    record[1], // File signature
                Severity:   SeverityHigh,
                Confidence: 0.95,
                TTL:        7 * 24 * time.Hour,
                Source:     "abuse.ch",
                Metadata: map[string]string{
                    "file_type": record[2],
                    "file_size": record[3],
                    "signature": record[4],
                },
                CreatedAt: time.Now(),
            }
            indicators = append(indicators, indicator)
        }
    }
    
    return indicators, nil
}
```

### 2. Pattern Detection Engine

```go
// internal/detection/engine.go
package detection

type DetectionEngine struct {
    regexEngine    *RegexEngine
    mlEngine       *MLEngine
    yaraEngine     *YaraEngine
    bloomFilter    *BloomFilter
    cache          Cache
}

type DetectionResult struct {
    ThreatType   ThreatType  `json:"threat_type"`
    Confidence   float64     `json:"confidence"`
    Risk         RiskLevel   `json:"risk"`
    Indicators   []string    `json:"indicators"`
    Explanation  string      `json:"explanation"`
    Metadata     interface{} `json:"metadata"`
}

// PII Detection with ML + Regex
type PIIDetector struct {
    regexPatterns map[string]*regexp.Regexp
    mlModel       *transformers.Model
    confidence    float64
}

func NewPIIDetector() *PIIDetector {
    patterns := map[string]*regexp.Regexp{
        "cpf":     regexp.MustCompile(`\d{3}\.?\d{3}\.?\d{3}-?\d{2}`),
        "cnpj":    regexp.MustCompile(`\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}`),
        "email":   regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
        "phone":   regexp.MustCompile(`\(?(\d{2})\)?\s?9?\d{4}-?\d{4}`),
        "credit_card": regexp.MustCompile(`\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}`),
    }
    
    return &PIIDetector{
        regexPatterns: patterns,
        mlModel:       loadPIIModel(),
        confidence:    0.85,
    }
}

func (p *PIIDetector) Detect(ctx context.Context, payload []byte) DetectionResult {
    text := string(payload)
    
    // Regex detection (fast path)
    regexMatches := p.detectWithRegex(text)
    
    // ML detection for complex cases
    mlMatches := p.detectWithML(ctx, text)
    
    // Combine results
    allMatches := append(regexMatches, mlMatches...)
    
    if len(allMatches) == 0 {
        return DetectionResult{
            ThreatType: ThreatPII,
            Confidence: 0.0,
            Risk:       RiskNone,
        }
    }
    
    // Calculate overall confidence
    maxConfidence := 0.0
    for _, match := range allMatches {
        if match.Confidence > maxConfidence {
            maxConfidence = match.Confidence
        }
    }
    
    return DetectionResult{
        ThreatType:  ThreatPII,
        Confidence:  maxConfidence,
        Risk:        calculateRisk(maxConfidence),
        Indicators:  extractIndicators(allMatches),
        Explanation: generateExplanation(allMatches),
        Metadata:    allMatches,
    }
}

// Prompt Injection Detection
type PromptInjectionDetector struct {
    patterns    []InjectionPattern
    mlModel     *transformers.Model
    vectorizer  *tfidf.Vectorizer
}

type InjectionPattern struct {
    Name        string
    Pattern     *regexp.Regexp
    Severity    SeverityLevel
    Description string
}

func NewPromptInjectionDetector() *PromptInjectionDetector {
    patterns := []InjectionPattern{
        {
            Name:        "ignore_instructions",
            Pattern:     regexp.MustCompile(`(?i)(ignore|forget|disregard).*(previous|above|instruction|rule)`),
            Severity:    SeverityHigh,
            Description: "Attempt to ignore previous instructions",
        },
        {
            Name:        "role_manipulation",
            Pattern:     regexp.MustCompile(`(?i)(you are now|act as|pretend to be|roleplay)`),
            Severity:    SeverityMedium,
            Description: "Attempt to manipulate AI role",
        },
        {
            Name:        "system_prompt_leak",
            Pattern:     regexp.MustCompile(`(?i)(show|reveal|tell me).*(system prompt|instructions|rules)`),
            Severity:    SeverityHigh,
            Description: "Attempt to leak system prompt",
        },
        {
            Name:        "jailbreak_attempt",
            Pattern:     regexp.MustCompile(`(?i)(DAN|developer mode|unrestricted|no limitations)`),
            Severity:    SeverityCritical,
            Description: "Jailbreak attempt detected",
        },
    }
    
    return &PromptInjectionDetector{
        patterns:   patterns,
        mlModel:    loadInjectionModel(),
        vectorizer: loadVectorizer(),
    }
}

func (p *PromptInjectionDetector) Detect(ctx context.Context, payload []byte) DetectionResult {
    text := string(payload)
    
    // Pattern-based detection
    var matches []PatternMatch
    for _, pattern := range p.patterns {
        if pattern.Pattern.MatchString(text) {
            matches = append(matches, PatternMatch{
                Pattern:     pattern.Name,
                Severity:    pattern.Severity,
                Confidence:  0.9,
                Description: pattern.Description,
            })
        }
    }
    
    // ML-based detection
    features := p.vectorizer.Transform(text)
    prediction := p.mlModel.Predict(features)
    
    if prediction.Probability > 0.7 {
        matches = append(matches, PatternMatch{
            Pattern:     "ml_detection",
            Severity:    mapProbabilityToSeverity(prediction.Probability),
            Confidence:  prediction.Probability,
            Description: "ML model detected potential injection",
        })
    }
    
    if len(matches) == 0 {
        return DetectionResult{
            ThreatType: ThreatPromptInjection,
            Confidence: 0.0,
            Risk:       RiskNone,
        }
    }
    
    // Calculate overall risk
    maxSeverity := SeverityLow
    totalConfidence := 0.0
    for _, match := range matches {
        if match.Severity > maxSeverity {
            maxSeverity = match.Severity
        }
        totalConfidence += match.Confidence
    }
    
    avgConfidence := totalConfidence / float64(len(matches))
    
    return DetectionResult{
        ThreatType:  ThreatPromptInjection,
        Confidence:  avgConfidence,
        Risk:        mapSeverityToRisk(maxSeverity),
        Indicators:  extractPatternNames(matches),
        Explanation: generateInjectionExplanation(matches),
        Metadata:    matches,
    }
}
```

### 3. Policy Engine (Inspirado no OPA)

```go
// internal/policy/engine.go
package policy

type PolicyEngine struct {
    store    PolicyStore
    compiler *rego.Rego
    cache    Cache
}

type Policy struct {
    ID          string                 `json:"id"`
    Name        string                 `json:"name"`
    Version     string                 `json:"version"`
    Rules       string                 `json:"rules"` // Rego code
    Metadata    map[string]interface{} `json:"metadata"`
    CreatedAt   time.Time              `json:"created_at"`
    UpdatedAt   time.Time              `json:"updated_at"`
}

type PolicyDecision struct {
    Allow       bool                   `json:"allow"`
    Reason      string                 `json:"reason"`
    Actions     []string               `json:"actions"`
    Metadata    map[string]interface{} `json:"metadata"`
    PolicyID    string                 `json:"policy_id"`
    Confidence  float64                `json:"confidence"`
}

func (p *PolicyEngine) Evaluate(ctx context.Context, input PolicyInput) (*PolicyDecision, error) {
    // Load applicable policies
    policies, err := p.store.GetPoliciesForTenant(input.TenantID)
    if err != nil {
        return nil, err
    }
    
    // Evaluate each policy
    var decisions []PolicyDecision
    for _, policy := range policies {
        decision, err := p.evaluatePolicy(ctx, policy, input)
        if err != nil {
            continue // Log error but continue with other policies
        }
        decisions = append(decisions, *decision)
    }
    
    // Aggregate decisions (most restrictive wins)
    return p.aggregateDecisions(decisions), nil
}

// Example policy in Rego
const examplePolicy = `
package guardagent.security

import future.keywords.if
import future.keywords.in

# Default deny
default allow = false

# Allow if no threats detected
allow if {
    input.threat_analysis.max_risk == "none"
    input.tenant.tier in ["premium", "enterprise"]
}

# Allow with monitoring for low risk
allow if {
    input.threat_analysis.max_risk == "low"
    input.tenant.monitoring_enabled == true
}

# Block high risk requests
deny if {
    input.threat_analysis.max_risk in ["high", "critical"]
}

# Special handling for PII
actions[action] if {
    "pii" in input.threat_analysis.threat_types
    action := "mask_pii"
}

# Audit logging for all requests
actions[action] if {
    action := "audit_log"
}
`

## 4. Risk Scoring Engine

```go
// internal/risk/engine.go
package risk

type RiskEngine struct {
    weights    map[ThreatType]float64
    thresholds map[RiskLevel]float64
    ml         *MLRiskModel
}

type RiskScore struct {
    Overall     float64                `json:"overall"`
    Components  map[ThreatType]float64 `json:"components"`
    Level       RiskLevel              `json:"level"`
    Factors     []RiskFactor           `json:"factors"`
    Confidence  float64                `json:"confidence"`
}

type RiskFactor struct {
    Type        string  `json:"type"`
    Weight      float64 `json:"weight"`
    Score       float64 `json:"score"`
    Description string  `json:"description"`
}

func NewRiskEngine() *RiskEngine {
    return &RiskEngine{
        weights: map[ThreatType]float64{
            ThreatPII:             0.9,  // High weight for PII
            ThreatPromptInjection: 0.8,  // High weight for injections
            ThreatMalware:         1.0,  // Critical weight for malware
            ThreatAnomalous:       0.6,  // Medium weight for anomalies
        },
        thresholds: map[RiskLevel]float64{
            RiskNone:     0.0,
            RiskLow:      0.3,
            RiskMedium:   0.6,
            RiskHigh:     0.8,
            RiskCritical: 0.95,
        },
    }
}

func (r *RiskEngine) CalculateRisk(analysis *ThreatAnalysis) *RiskScore {
    components := make(map[ThreatType]float64)
    factors := make([]RiskFactor, 0)

    totalScore := 0.0
    totalWeight := 0.0

    for _, result := range analysis.Results {
        weight := r.weights[result.ThreatType]
        score := result.Confidence * weight

        components[result.ThreatType] = score
        totalScore += score
        totalWeight += weight

        factors = append(factors, RiskFactor{
            Type:        string(result.ThreatType),
            Weight:      weight,
            Score:       score,
            Description: result.Explanation,
        })
    }

    // Normalize score
    overallScore := totalScore / totalWeight
    if totalWeight == 0 {
        overallScore = 0
    }

    // Determine risk level
    level := r.determineRiskLevel(overallScore)

    return &RiskScore{
        Overall:    overallScore,
        Components: components,
        Level:      level,
        Factors:    factors,
        Confidence: r.calculateConfidence(analysis.Results),
    }
}
```

## 5. Response Engine

```go
// internal/response/engine.go
package response

type ResponseEngine struct {
    actions map[string]ActionHandler
    audit   AuditLogger
    notify  NotificationService
}

type ActionHandler interface {
    Execute(ctx context.Context, req *Request, decision *PolicyDecision) error
}

// Block Action
type BlockAction struct {
    reason string
}

func (b *BlockAction) Execute(ctx context.Context, req *Request, decision *PolicyDecision) error {
    return &SecurityBlockError{
        Reason:   b.reason,
        RiskScore: decision.Metadata["risk_score"].(float64),
        PolicyID: decision.PolicyID,
    }
}

// Mask PII Action
type MaskPIIAction struct {
    masker *PIIMasker
}

func (m *MaskPIIAction) Execute(ctx context.Context, req *Request, decision *PolicyDecision) error {
    maskedPayload, err := m.masker.Mask(req.Payload)
    if err != nil {
        return err
    }
    req.Payload = maskedPayload
    return nil
}

// Audit Log Action
type AuditLogAction struct {
    logger AuditLogger
}

func (a *AuditLogAction) Execute(ctx context.Context, req *Request, decision *PolicyDecision) error {
    event := AuditEvent{
        Timestamp:   time.Now(),
        TenantID:    req.TenantID,
        RequestID:   req.ID,
        Action:      "security_check",
        Decision:    decision.Allow,
        Reason:      decision.Reason,
        RiskScore:   decision.Metadata["risk_score"].(float64),
        PolicyID:    decision.PolicyID,
        UserAgent:   req.Headers["User-Agent"],
        SourceIP:    req.SourceIP,
    }

    return a.logger.Log(event)
}
```
```

Vou continuar com mais componentes na próxima parte. Quer que eu continue com o Risk Scoring Engine e a arquitetura de deployment?


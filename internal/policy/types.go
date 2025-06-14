package policy

import (
	"container/list"
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"guardagent/internal/common"
)

/* ------------------------------------------------------------------ */
/* -------------------------  TIPOS BÁSICOS  ------------------------ */
/* ------------------------------------------------------------------ */

// Request representa a chamada que será avaliada pelo motor de políticas.
type Request struct {
	ID          string
	TenantID    string
	Environment string
	Payload     []byte
	Headers     map[string]string
}

// ThreatAnalysis agrega os resultados dos detectores.
type ThreatAnalysis struct {
	Results []DetectionResult
	MaxRisk float64
}

// DetectionResult é o resumo de uma detecção feita pelo pipeline.
type DetectionResult struct {
	ThreatType common.ThreatType
	Confidence float64
}

/* ------------------------------------------------------------------ */
/* ------------------  CONFIG, CACHE E MÉTRICAS  -------------------- */
/* ------------------------------------------------------------------ */

// PolicyConfig define parâmetros de inicialização do motor.
type PolicyConfig struct {
	GitRepo         string
	RefreshInterval time.Duration
}

// PolicyCache implementa cache LRU com TTL para decisões de política.
type PolicyCache struct {
	maxSize int
	ttl     time.Duration
	items   map[string]*cacheItem
	lru     *list.List
	mu      sync.Mutex
}

type cacheItem struct {
	key       string
	value     interface{}
	expiresAt time.Time
	element   *list.Element
}

func NewPolicyCache(size int, ttl time.Duration) *PolicyCache {
	c := &PolicyCache{
		maxSize: size,
		ttl:     ttl,
		items:   make(map[string]*cacheItem),
		lru:     list.New(),
	}
	go c.cleanup()
	return c
}

func (c *PolicyCache) Get(key string) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if item, ok := c.items[key]; ok {
		if time.Now().After(item.expiresAt) {
			c.remove(item)
			return nil, false
		}
		c.lru.MoveToFront(item.element)
		return item.value, true
	}
	return nil, false
}

func (c *PolicyCache) Set(key string, val interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if item, ok := c.items[key]; ok {
		item.value = val
		item.expiresAt = time.Now().Add(c.ttl)
		c.lru.MoveToFront(item.element)
		return
	}
	item := &cacheItem{key: key, value: val, expiresAt: time.Now().Add(c.ttl)}
	item.element = c.lru.PushFront(item)
	c.items[key] = item
	if len(c.items) > c.maxSize {
		if oldest := c.lru.Back(); oldest != nil {
			c.remove(oldest.Value.(*cacheItem))
		}
	}
}

func (c *PolicyCache) remove(item *cacheItem) {
	delete(c.items, item.key)
	c.lru.Remove(item.element)
}

func (c *PolicyCache) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		c.mu.Lock()
		for _, it := range c.items {
			if time.Now().After(it.expiresAt) {
				c.remove(it)
			}
		}
		c.mu.Unlock()
	}
}

// PolicyMetrics expõe métricas Prometheus do motor de políticas.
type PolicyMetrics struct {
	CacheHits          prometheus.Counter
	CacheMisses        prometheus.Counter
	RulesMatched       *prometheus.CounterVec
	EvaluationDuration prometheus.Histogram
	EvaluationErrors   *prometheus.CounterVec
	ActionErrors       *prometheus.CounterVec
}

func NewPolicyMetrics() *PolicyMetrics {
	return &PolicyMetrics{
		CacheHits:   prometheus.NewCounter(prometheus.CounterOpts{Name: "ga_policy_cache_hits_total", Help: "Policy cache hits"}),
		CacheMisses: prometheus.NewCounter(prometheus.CounterOpts{Name: "ga_policy_cache_misses_total", Help: "Policy cache misses"}),
		RulesMatched: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ga_policy_rules_matched_total",
			Help: "Number of matched policy rules"}, []string{"rule"}),
		EvaluationDuration: prometheus.NewHistogram(prometheus.HistogramOpts{Name: "ga_policy_evaluation_seconds"}),
		EvaluationErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ga_policy_evaluation_errors_total",
			Help: "Errors during policy evaluation"}, []string{"rule"}),
		ActionErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ga_policy_action_errors_total",
			Help: "Errors executing policy actions"}, []string{"action"}),
	}
}

/* ------------------------------------------------------------------ */
/* ------------------  REPOSITÓRIO DE POLÍTICAS  -------------------- */
/* ------------------------------------------------------------------ */

// GitPolicyRepo é um stub para armazenar políticas em Git.
type GitPolicyRepo struct {
	Path string
}

func NewGitPolicyRepo(path string) *GitPolicyRepo { return &GitPolicyRepo{Path: path} }
func (g *GitPolicyRepo) Pull() error              { return nil }

/* ------------------------------------------------------------------ */
/* ---------------------  AVALIADOR / REGO  ------------------------- */
/* ------------------------------------------------------------------ */

// PolicyEvaluator orquestra a avaliação de políticas.
type PolicyEvaluator struct{}

func NewPolicyEvaluator() *PolicyEvaluator                               { return &PolicyEvaluator{} }
func (e *PolicyEvaluator) Evaluate(ctx context.Context, q string, in any) (any, error) {
	return nil, nil // implementação simplificada
}

/* ------------------------------------------------------------------ */
/* -------------------------  AÇÕES E DTOs  ------------------------- */
/* ------------------------------------------------------------------ */

// ActionType lista ações possíveis após decisão de política.
type ActionType string

const (
	ActionAllow  ActionType = "allow"
	ActionBlock  ActionType = "block"
	ActionRedact ActionType = "redact"
	ActionLog    ActionType = "log"
	ActionAlert  ActionType = "alert"
)

// PolicyDecision descreve o resultado final para um request.
type PolicyDecision struct {
	RequestID string
	TenantID  string
	Timestamp time.Time
	Analysis  *ThreatAnalysis
	Action    Action
}

// Action define como o gateway deve reagir.
type Action struct {
	Type         ActionType
	Parameters   map[string]string
	Fallback     *Action
	Webhook      *WebhookConfig
	Notification *NotificationConfig
}

// WebhookConfig para acionamento externo.
type WebhookConfig struct {
	URL     string
	Method  string
	Headers map[string]string
	Timeout time.Duration
}

// NotificationConfig para canais (Slack, e-mail etc.).
type NotificationConfig struct {
	Channel string
	Target  string
	Message string
}


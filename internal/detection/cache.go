// internal/detection/cache.go
package detection

import (
	"container/list"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// PatternCache implements an LRU cache with TTL for pattern detection results
type PatternCache struct {
	maxSize int
	ttl     time.Duration
	items   map[string]*cacheItem
	lruList *list.List
	mu      sync.RWMutex
}

type cacheItem struct {
	key       string
	value     interface{}
	element   *list.Element
	expiresAt time.Time
}

func NewPatternCache(maxSize int, ttl time.Duration) *PatternCache {
	cache := &PatternCache{
		maxSize: maxSize,
		ttl:     ttl,
		items:   make(map[string]*cacheItem),
		lruList: list.New(),
	}

	// Start cleanup goroutine
	go cache.cleanup()

	return cache
}

func (c *PatternCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, exists := c.items[key]
	if !exists {
		return nil, false
	}

	// Check if expired
	if time.Now().After(item.expiresAt) {
		c.mu.RUnlock()
		c.mu.Lock()
		c.removeItem(item)
		c.mu.Unlock()
		c.mu.RLock()
		return nil, false
	}

	// Move to front (most recently used)
	c.lruList.MoveToFront(item.element)

	return item.value, true
}

func (c *PatternCache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if item already exists
	if existingItem, exists := c.items[key]; exists {
		existingItem.value = value
		existingItem.expiresAt = time.Now().Add(c.ttl)
		c.lruList.MoveToFront(existingItem.element)
		return
	}

	// Create new item
	item := &cacheItem{
		key:       key,
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
	}

	// Add to front of LRU list
	item.element = c.lruList.PushFront(item)
	c.items[key] = item

	// Check if we need to evict
	if len(c.items) > c.maxSize {
		c.evictLRU()
	}
}

func (c *PatternCache) evictLRU() {
	// Remove least recently used item
	if c.lruList.Len() > 0 {
		oldest := c.lruList.Back()
		if oldest != nil {
			item := oldest.Value.(*cacheItem)
			c.removeItem(item)
		}
	}
}

func (c *PatternCache) removeItem(item *cacheItem) {
	delete(c.items, item.key)
	c.lruList.Remove(item.element)
}

func (c *PatternCache) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()

		// Collect expired items
		var expiredItems []*cacheItem
		for _, item := range c.items {
			if now.After(item.expiresAt) {
				expiredItems = append(expiredItems, item)
			}
		}

		// Remove expired items
		for _, item := range expiredItems {
			c.removeItem(item)
		}

		c.mu.Unlock()
	}
}

func (c *PatternCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

func (c *PatternCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[string]*cacheItem)
	c.lruList.Init()
}

// BloomFilter for fast negative lookups
type BloomFilter struct {
	bitArray  []bool
	size      uint
	hashFuncs int
}

func NewBloomFilter(expectedItems int, falsePositiveRate float64) *BloomFilter {
	// Calculate optimal size and hash functions
	size := uint(-float64(expectedItems) * math.Log(falsePositiveRate) / (math.Log(2) * math.Log(2)))
	hashFuncs := int(float64(size) / float64(expectedItems) * math.Log(2))

	if hashFuncs < 1 {
		hashFuncs = 1
	}
	if hashFuncs > 10 {
		hashFuncs = 10
	}

	return &BloomFilter{
		bitArray:  make([]bool, size),
		size:      size,
		hashFuncs: hashFuncs,
	}
}

func (bf *BloomFilter) Add(data []byte) {
	for i := 0; i < bf.hashFuncs; i++ {
		hash := bf.hash(data, uint(i))
		bf.bitArray[hash%bf.size] = true
	}
}

func (bf *BloomFilter) MightContain(data []byte) bool {
	for i := 0; i < bf.hashFuncs; i++ {
		hash := bf.hash(data, uint(i))
		if !bf.bitArray[hash%bf.size] {
			return false
		}
	}
	return true
}

func (bf *BloomFilter) hash(data []byte, seed uint) uint {
	// Simple hash function (in production, use a better one like murmur3)
	hash := seed
	for _, b := range data {
		hash = hash*31 + uint(b)
	}
	return hash
}

// DetectionMetrics for monitoring
type DetectionMetrics struct {
	DetectionDuration *prometheus.HistogramVec
	CacheHits         *prometheus.CounterVec
	CacheMisses       *prometheus.CounterVec
	PIIDetected       *prometheus.CounterVec
	FalsePositives    *prometheus.CounterVec
	TruePositives     *prometheus.CounterVec
}

func NewDetectionMetrics() *DetectionMetrics {
	return &DetectionMetrics{
		DetectionDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "ga_detection_duration_seconds",
				Help:    "Time spent in detection pipeline",
				Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
			},
			[]string{"detection_type"},
		),
		CacheHits: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ga_cache_hits_total",
				Help: "Total cache hits",
			},
			[]string{"cache_type"},
		),
		CacheMisses: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ga_cache_misses_total",
				Help: "Total cache misses",
			},
			[]string{"cache_type"},
		),
		PIIDetected: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ga_pii_detected_total",
				Help: "Total PII instances detected",
			},
			[]string{"pii_type"},
		),
		FalsePositives: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ga_false_positives_total",
				Help: "Total false positive detections",
			},
			[]string{"detection_type"},
		),
		TruePositives: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ga_true_positives_total",
				Help: "Total true positive detections",
			},
			[]string{"detection_type"},
		),
	}
}

// WorkerPool for parallel processing
type WorkerPool struct {
	workers    int
	jobQueue   chan Job
	resultChan chan Result
	quit       chan bool
	wg         sync.WaitGroup
}

type Job struct {
	ID   string
	Data interface{}
	Type string
}

type Result struct {
	JobID string
	Data  interface{}
	Error error
}

func NewWorkerPool(workers int, queueSize int) *WorkerPool {
	return &WorkerPool{
		workers:    workers,
		jobQueue:   make(chan Job, queueSize),
		resultChan: make(chan Result, queueSize),
		quit:       make(chan bool),
	}
}

func (wp *WorkerPool) Start() {
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker()
	}
}

func (wp *WorkerPool) Stop() {
	close(wp.quit)
	wp.wg.Wait()
	close(wp.jobQueue)
	close(wp.resultChan)
}

func (wp *WorkerPool) Submit(job Job) {
	wp.jobQueue <- job
}

func (wp *WorkerPool) Results() <-chan Result {
	return wp.resultChan
}

func (wp *WorkerPool) worker() {
	defer wp.wg.Done()

	for {
		select {
		case job := <-wp.jobQueue:
			result := wp.processJob(job)
			wp.resultChan <- result
		case <-wp.quit:
			return
		}
	}
}

func (wp *WorkerPool) processJob(job Job) Result {
	// Process job based on type
	switch job.Type {
	case "pii_detection":
		// Process PII detection job
		return Result{JobID: job.ID, Data: "processed", Error: nil}
	case "injection_detection":
		// Process injection detection job
		return Result{JobID: job.ID, Data: "processed", Error: nil}
	default:
		return Result{JobID: job.ID, Data: nil, Error: fmt.Errorf("unknown job type: %s", job.Type)}
	}
}

// CircuitBreaker for ML model fallback
type CircuitBreaker struct {
	maxFailures int
	timeout     time.Duration
	failures    int
	lastFailure time.Time
	state       CircuitState
	mu          sync.RWMutex
}

type CircuitState int

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
	CircuitHalfOpen
)

func NewCircuitBreaker(maxFailures int, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		maxFailures: maxFailures,
		timeout:     timeout,
		state:       CircuitClosed,
	}
}

func (cb *CircuitBreaker) Allow() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	switch cb.state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		if time.Since(cb.lastFailure) > cb.timeout {
			cb.mu.RUnlock()
			cb.mu.Lock()
			cb.state = CircuitHalfOpen
			cb.mu.Unlock()
			cb.mu.RLock()
			return true
		}
		return false
	case CircuitHalfOpen:
		return true
	default:
		return false
	}
}

func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures = 0
	cb.state = CircuitClosed
}

func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailure = time.Now()

	if cb.failures >= cb.maxFailures {
		cb.state = CircuitOpen
	}
}

func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

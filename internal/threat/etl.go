package threat

import (
	"context"
	"log/slog"
	"sync"
)

// ETLController coordinates fetching and storing threat intelligence.
type ETLController struct {
	fetchers []ThreatFetcher
	store    ThreatStore
}

// NewETLController creates a new controller.
func NewETLController(store ThreatStore) *ETLController {
	return &ETLController{store: store}
}

// Register adds a fetcher to the controller.
func (c *ETLController) Register(f ThreatFetcher) {
	c.fetchers = append(c.fetchers, f)
}

// Run executes all fetchers sequentially.
func (c *ETLController) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	for _, f := range c.fetchers {
		wg.Add(1)
		go func(fetcher ThreatFetcher) {
			defer wg.Done()
			indicators, err := fetcher.Fetch(ctx)
			if err != nil {
				slog.Error("fetch failed", "source", fetcher.Name(), "err", err)
				return
			}
			if err := c.store.SaveIndicators(ctx, indicators); err != nil {
				slog.Error("store failed", "err", err)
			}
		}(f)
	}
	wg.Wait()
	return nil
}

// MemoryStore is a simple in-memory implementation of ThreatStore.
type MemoryStore struct {
	mu   sync.Mutex
	data []ThreatIndicator
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{} }

func (m *MemoryStore) SaveIndicators(ctx context.Context, ind []ThreatIndicator) error {
	m.mu.Lock()
	m.data = append(m.data, ind...)
	m.mu.Unlock()
	slog.Info("stored indicators", "count", len(ind))
	return nil
}

func (m *MemoryStore) All() []ThreatIndicator {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]ThreatIndicator(nil), m.data...)
}

// NVDFetcher fetches CVE data from NVD. This is a stub that returns no data.
type NVDFetcher struct{}

func NewNVDFetcher() *NVDFetcher { return &NVDFetcher{} }

func (n *NVDFetcher) Name() string { return "nvd_cve" }

func (n *NVDFetcher) Fetch(ctx context.Context) ([]ThreatIndicator, error) {
	// In a full implementation, this would call the NVD API.
	slog.Info("NVD fetch stub")
	return []ThreatIndicator{}, nil
}

// AbuseFetcher fetches malware hashes from abuse.ch. Stub implementation.
type AbuseFetcher struct{}

func NewAbuseFetcher() *AbuseFetcher { return &AbuseFetcher{} }

func (a *AbuseFetcher) Name() string { return "abuse_ch" }

func (a *AbuseFetcher) Fetch(ctx context.Context) ([]ThreatIndicator, error) {
	slog.Info("abuse.ch fetch stub")
	return []ThreatIndicator{}, nil
}

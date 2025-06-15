package threat

import (
	"context"
	"time"
)

// ThreatIndicator represents a piece of threat intelligence.
type ThreatIndicator struct {
	ID         string
	Indicator  string
	Type       string
	Source     string
	Confidence float64
	Severity   string
	FirstSeen  time.Time
	LastSeen   time.Time
}

// ThreatFetcher fetches threat indicators from a source.
type ThreatFetcher interface {
	Name() string
	Fetch(ctx context.Context) ([]ThreatIndicator, error)
}

// ThreatStore persists indicators.
type ThreatStore interface {
	SaveIndicators(ctx context.Context, indicators []ThreatIndicator) error
}

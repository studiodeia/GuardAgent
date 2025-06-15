package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	BloomHitRatio = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ga_bloom_filter_hit_ratio",
			Help: "Bloom filter hit ratio",
		},
		[]string{"detector_type"},
	)

	CacheEvictions = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ga_cache_evictions_total",
			Help: "Cache evictions",
		},
		[]string{"cache_type"},
	)
)

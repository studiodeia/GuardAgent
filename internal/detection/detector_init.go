package detection

import (
	"time"

	"github.com/willf/bloom"
)

var (
	bf    = bloom.New(100000, 5) // ~1% false positive
	cache = NewPatternCache(1000, 5*time.Minute)
)

func init() {
	patterns := []string{
		"###.###.###-##",
		"##.###.###/####-##",
		`\d{3}\.\d{3}\.\d{3}-\d{2}`,
		`\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}`,
	}
	for _, p := range patterns {
		bf.Add([]byte(p))
	}
}

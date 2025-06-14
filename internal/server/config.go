package server

import "os"

// Config holds server configuration
type Config struct {
	HTTPAddr    string
	MetricsAddr string
	PolicyRepo  string
}

// LoadConfig reads environment variables and returns a Config
func LoadConfig() *Config {
	return &Config{
		HTTPAddr:    getEnv("GA_HTTP_ADDR", ":8080"),
		MetricsAddr: getEnv("GA_METRICS_ADDR", ":9090"),
		PolicyRepo:  getEnv("GA_POLICY_REPO", ""),
	}
}

func getEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

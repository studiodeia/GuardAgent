package main

import (
	"log/slog"
	"net/http"

	"guardagent/internal/detection"
	"guardagent/internal/policy"
	"guardagent/internal/server"
)

func main() {
	cfg := server.LoadConfig()
	det := detection.NewEnhancedPatternDetector()
	pol := policy.NewEnhancedPolicyEngine(&policy.PolicyConfig{})
	srv := server.New(det, pol, cfg)

	go srv.StartMetrics(cfg.MetricsAddr)

	slog.Info("listening", "addr", cfg.HTTPAddr)
	if err := http.ListenAndServe(cfg.HTTPAddr, srv.Router()); err != nil {
		slog.Error("server error", "err", err)
	}
}

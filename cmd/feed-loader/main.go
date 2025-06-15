package main

import (
	"context"
	"log/slog"
	"time"

	"guardagent/internal/threat"
)

func main() {
	slog.Info("starting threat intelligence feed loader")

	store := threat.NewMemoryStore()
	controller := threat.NewETLController(store)
	controller.Register(threat.NewNVDFetcher())
	controller.Register(threat.NewAbuseFetcher())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := controller.Run(ctx); err != nil {
		slog.Error("etl run failed", "err", err)
		return
	}

	slog.Info("threat intelligence feed loader completed successfully")
}
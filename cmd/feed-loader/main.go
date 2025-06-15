package main

import (
	"context"
	"log/slog"
	"time"

	"guardagent/internal/threat"
)

func main() {
	store := threat.NewMemoryStore()
	controller := threat.NewETLController(store)
	controller.Register(threat.NewNVDFetcher())
	controller.Register(threat.NewAbuseFetcher())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := controller.Run(ctx); err != nil {
		slog.Error("etl run failed", "err", err)
	}
}

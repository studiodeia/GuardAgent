package server

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"guardagent/internal/common"
	"net"

	"guardagent/api"
	"guardagent/internal/detection"
	"guardagent/internal/policy"
)

// Server wraps HTTP and gRPC servers
type Server struct {
	detector *detection.PatternDetector
	policy   *policy.SimpleEngine
	cfg      *Config
	router   *mux.Router
	grpcSrv  *grpc.Server
}

func New(det *detection.PatternDetector, pol *policy.SimpleEngine, cfg *Config) *Server {
	s := &Server{detector: det, policy: pol, cfg: cfg, router: mux.NewRouter()}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.router.HandleFunc("/v1/filter", s.handleFilter).Methods(http.MethodPost)
}

func (s *Server) Router() http.Handler { return s.router }

func (s *Server) StartMetrics(addr string) {
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		if err := http.ListenAndServe(addr, nil); err != nil && err != http.ErrServerClosed {
			slog.Error("metrics server error", "err", err)
		}
	}()
}

func (s *Server) handleFilter(w http.ResponseWriter, r *http.Request) {
	tenant := r.Header.Get("X-Tenant-ID")
	text := r.FormValue("text")

	matches, _ := s.detector.DetectPII(r.Context(), text)
	var results []policy.DetectionResult
	for range matches {
		results = append(results, policy.DetectionResult{ThreatType: common.ThreatPII, Confidence: 1})
	}
	analysis := &policy.ThreatAnalysis{Results: results}
	decision, _ := s.policy.Evaluate(r.Context(), analysis, &policy.Request{TenantID: tenant})

	if decision != nil && decision.Action.Type == policy.ActionBlock {
		w.WriteHeader(http.StatusForbidden)
	}
}

// gRPC service implementation
type filterService struct {
	api.UnimplementedFilterServiceServer
	srv *Server
}

func (f *filterService) Filter(ctx context.Context, req *api.FilterRequest) (*api.FilterResponse, error) {
	matches, _ := f.srv.detector.DetectPII(ctx, req.Text)
	var results []policy.DetectionResult
	for range matches {
		results = append(results, policy.DetectionResult{ThreatType: common.ThreatPII, Confidence: 1})
	}
	analysis := &policy.ThreatAnalysis{Results: results}
	decision, _ := f.srv.policy.Evaluate(ctx, analysis, &policy.Request{TenantID: req.TenantId})
	resp := &api.FilterResponse{Allowed: decision.Action.Type != policy.ActionBlock, Action: string(decision.Action.Type)}
	return resp, nil
}

func (s *Server) StartGRPC(addr string) error {
	s.grpcSrv = grpc.NewServer()
	api.RegisterFilterServiceServer(s.grpcSrv, &filterService{srv: s})
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.grpcSrv.Serve(ln)
}

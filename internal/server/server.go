package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/hartmann-it/ocsp-responder/internal/config"
	"github.com/hartmann-it/ocsp-responder/internal/responder"
	"github.com/hartmann-it/ocsp-responder/internal/signer"
	"github.com/hartmann-it/ocsp-responder/internal/source"
)

type Server struct {
	cfg       *config.Config
	responder *responder.Responder
	signer    *signer.Signer
	source    source.Source
	logger    *slog.Logger
}

func New(cfg *config.Config, r *responder.Responder, sgn *signer.Signer, src source.Source, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{cfg: cfg, responder: r, signer: sgn, source: src, logger: logger}
}

// Start registers routes and blocks until SIGTERM or SIGINT.
// Performs graceful shutdown with 10-second timeout.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /", ServeOCSP(s.responder, mustParseDuration(s.cfg.Cache.TTL), s.logger))
	mux.HandleFunc("GET /{request}", ServeOCSP(s.responder, mustParseDuration(s.cfg.Cache.TTL), s.logger))
	mux.HandleFunc("GET /health", ServeHealth(s.signer, s.source))
	mux.Handle("GET /metrics", promhttp.Handler())

	httpServer := &http.Server{Addr: s.cfg.Server.ListenAddr, Handler: mux}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		if s.cfg.Server.TLS.Enabled {
			if s.cfg.Server.TLS.CertFile == "" || s.cfg.Server.TLS.KeyFile == "" {
				errCh <- fmt.Errorf("ocsp-responder/server: TLS enabled but cert_file or key_file not set")
				return
			}
			tlsCfg := &tls.Config{
				MinVersion: tlsMinVersion(s.cfg.Server.TLS.MinVersion),
			}
			httpServer.TLSConfig = tlsCfg
			s.logger.Info("OCSP responder listening (TLS)", "addr", s.cfg.Server.ListenAddr)
			errCh <- httpServer.ListenAndServeTLS(s.cfg.Server.TLS.CertFile, s.cfg.Server.TLS.KeyFile)
		} else {
			s.logger.Info("OCSP responder listening", "addr", s.cfg.Server.ListenAddr)
			errCh <- httpServer.ListenAndServe()
		}
	}()

	select {
	case sig := <-stop:
		s.logger.Info("shutdown signal received", "signal", sig.String())
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("ocsp-responder/server: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("ocsp-responder/server: %w", err)
	}
	return nil
}

func tlsMinVersion(v string) uint16 {
	if v == "1.3" {
		return tls.VersionTLS13
	}
	return tls.VersionTLS12
}

func mustParseDuration(s string) time.Duration {
	d, _ := time.ParseDuration(s)
	return d
}

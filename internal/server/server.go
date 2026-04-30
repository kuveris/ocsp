package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

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
	metrics   *Metrics
	logger    *slog.Logger
}

func New(cfg *config.Config, r *responder.Responder, sgn *signer.Signer, src source.Source, metrics *Metrics, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{cfg: cfg, responder: r, signer: sgn, source: src, metrics: metrics, logger: logger}
}

// Start registers routes and blocks until ctx is cancelled.
// Performs graceful shutdown with 10-second timeout.
func (s *Server) Start(ctx context.Context) error {
	cacheTTL, err := time.ParseDuration(s.cfg.Cache.TTL)
	if err != nil {
		return fmt.Errorf("ocsp-responder/server: invalid cache ttl: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /", ServeOCSP(s.responder, cacheTTL, s.metrics, s.logger))
	mux.HandleFunc("GET /{request}", ServeOCSP(s.responder, cacheTTL, s.metrics, s.logger))
	mux.HandleFunc("GET /health", ServeHealth(s.signer, s.source))
	mux.Handle("GET /metrics", promhttp.Handler())

	httpServer := &http.Server{
		Addr:         s.cfg.Server.ListenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if s.cfg.Server.TLS.Enabled {
			if s.cfg.Server.TLS.CertFile != "" && s.cfg.Server.TLS.KeyFile != "" {
				tlsCfg := &tls.Config{
					MinVersion: tlsMinVersion(s.cfg.Server.TLS.MinVersion),
				}
				httpServer.TLSConfig = tlsCfg
				s.logger.Info("OCSP responder listening (TLS)", "addr", s.cfg.Server.ListenAddr)
				errCh <- httpServer.ListenAndServeTLS(s.cfg.Server.TLS.CertFile, s.cfg.Server.TLS.KeyFile)
			} else if s.cfg.Server.TLS.ACMEHost != "" {
				m := &autocert.Manager{
					Prompt:     autocert.AcceptTOS,
					HostPolicy: autocert.HostWhitelist(s.cfg.Server.TLS.ACMEHost),
					Cache:      autocert.DirCache("certs/acme"),
				}
				if s.cfg.Server.TLS.ACMECAUrl != "" {
					m.Client = &acme.Client{DirectoryURL: s.cfg.Server.TLS.ACMECAUrl}
				}
				httpServer.TLSConfig = m.TLSConfig()
				s.logger.Info("OCSP responder listening (ACME TLS)", "addr", s.cfg.Server.ListenAddr, "host", s.cfg.Server.TLS.ACMEHost)
				errCh <- httpServer.ListenAndServeTLS("", "")
			} else {
				errCh <- fmt.Errorf("ocsp-responder/server: TLS enabled but no cert or ACME config provided")
			}
		} else {
			s.logger.Info("OCSP responder listening", "addr", s.cfg.Server.ListenAddr)
			errCh <- httpServer.ListenAndServe()
		}
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("shutdown signal received")
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("ocsp-responder/server: %w", err)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return httpServer.Shutdown(shutdownCtx)
}

func tlsMinVersion(v string) uint16 {
	if v == "1.3" {
		return tls.VersionTLS13
	}
	return tls.VersionTLS12
}


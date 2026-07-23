package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/kuveris/ocsp/internal/config"
	"github.com/kuveris/ocsp/internal/responder"
	"github.com/kuveris/ocsp/internal/signer"
	"github.com/kuveris/ocsp/internal/source"
)

type Server struct {
	cfg       *config.Config
	registry  *prometheus.Registry
	responder *responder.Responder
	signer    *signer.Signer
	source    source.Source
	metrics   *Metrics
	logger    *slog.Logger
}

func New(cfg *config.Config, r *responder.Responder, sgn *signer.Signer, src source.Source, metrics *Metrics, registry *prometheus.Registry, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{cfg: cfg, responder: r, signer: sgn, source: src, metrics: metrics, registry: registry, logger: logger}
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
	// Serve this instance's registry rather than the global default, so
	// /metrics reflects the collectors this server actually owns.
	metricsHandler := promhttp.Handler()
	if s.registry != nil {
		metricsHandler = promhttp.HandlerFor(s.registry, promhttp.HandlerOpts{})
	}
	mux.Handle("GET /metrics", metricsHandler)

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
				cacheDir := s.cfg.Server.TLS.ACMECacheDir
				if cacheDir == "" {
					cacheDir = DefaultACMECacheDir
				}
				if err := ensureACMECacheDir(cacheDir); err != nil {
					errCh <- err
					return
				}
				m := &autocert.Manager{
					Prompt:     autocert.AcceptTOS,
					HostPolicy: autocert.HostWhitelist(s.cfg.Server.TLS.ACMEHost),
					Cache:      autocert.DirCache(cacheDir),
				}
				s.logger.Info("ACME certificate cache", "dir", cacheDir)
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

// DefaultACMECacheDir is where ACME-issued certificates are persisted when
// server.tls.acme_cache_dir is unset.
//
// Absolute by design. The previous relative "certs/acme" resolved against the
// process working directory, which in the shipped container is / — landing the
// cache inside the read-only /certs mount. autocert treats a failed cache write
// as non-fatal and falls back to in-memory, so the only visible symptom was a
// fresh certificate order on every restart, which is how a deployment walks
// into a CA rate limit and then cannot serve TLS at all.
const DefaultACMECacheDir = "/var/lib/ocsp-responder/acme"

// ensureACMECacheDir creates the cache directory and proves it is writable
// before the listener starts. Failing here is deliberate: a silent fallback to
// in-memory looks healthy and only manifests as rate-limit exhaustion days
// later.
func ensureACMECacheDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("ocsp-responder/server: acme cache directory %s: %w", dir, err)
	}
	// Probe with a unique temp name, not a fixed ".writable". Two responders
	// pointed at the same cache dir — or a blue/green restart briefly sharing
	// the volume — would otherwise race on the fixed name: one removes the file
	// the other is about to remove, and a spurious startup failure results.
	// autocert's own DirCache is safe for concurrent use, so this validator
	// must not be the thing that isn't.
	f, err := os.CreateTemp(dir, ".writable-*")
	if err != nil {
		return fmt.Errorf("ocsp-responder/server: acme cache directory %s is not writable: %w", dir, err)
	}
	probe := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(probe)
		return fmt.Errorf("ocsp-responder/server: acme cache directory %s: %w", dir, err)
	}
	// A concurrent probe may have already removed an identically named file;
	// treat "already gone" as success rather than a startup failure.
	if err := os.Remove(probe); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("ocsp-responder/server: acme cache directory %s: %w", dir, err)
	}
	return nil
}

func tlsMinVersion(v string) uint16 {
	if v == "1.3" {
		return tls.VersionTLS13
	}
	return tls.VersionTLS12
}

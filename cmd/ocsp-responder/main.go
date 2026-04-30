package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hartmann-it/ocsp-responder/internal/config"
	"github.com/hartmann-it/ocsp-responder/internal/responder"
	"github.com/hartmann-it/ocsp-responder/internal/server"
	"github.com/hartmann-it/ocsp-responder/internal/signer"
	"github.com/hartmann-it/ocsp-responder/internal/source"
)

func main() {
	configPath := flag.String("config", "config/ocsp-responder.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ocsp-responder: %v\n", err)
		os.Exit(1)
	}

	logger := buildLogger(cfg.Logging.Level, cfg.Logging.Format)

	src, err := newSource(cfg)
	if err != nil {
		logger.Error("failed to create source", "err", err)
		os.Exit(1)
	}

	validity, err := time.ParseDuration(cfg.Signer.ResponseValidity)
	if err != nil {
		logger.Error("invalid signer response validity", "value", cfg.Signer.ResponseValidity, "err", err)
		os.Exit(1)
	}
	sgn, err := signer.NewSigner(cfg.Signer.CertFile, cfg.Signer.KeyFile, cfg.Signer.IssuerCertFile, validity)
	if err != nil {
		logger.Error("failed to create signer", "err", err)
		os.Exit(1)
	}

	// Start expiry monitor with a context that is cancelled on SIGTERM/SIGINT.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	metrics := server.NewMetrics()
	if httpSource, ok := src.(*source.HTTPSource); ok {
		httpSource.SetObserver(metrics)
	}

	sgn.StartExpiryMonitor(ctx, logger, metrics.SignerDaysLeft)

	cacheTTL, err := time.ParseDuration(cfg.Cache.TTL)
	if err != nil {
		logger.Error("invalid cache ttl", "value", cfg.Cache.TTL, "err", err)
		os.Exit(1)
	}
	resp := responder.NewResponder(src, sgn, cacheTTL, cfg.Cache.MaxEntries, cfg.Cache.Enabled, metrics, metrics.CacheEntries, logger)

	srv := server.New(cfg, resp, sgn, src, metrics, logger)
	if err := srv.Start(ctx); err != nil {
		logger.Error("server error", "err", err)
		os.Exit(1)
	}
}

func buildLogger(level, format string) *slog.Logger {
	var logLevel slog.Level
	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: logLevel}
	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(handler)
}

func newSource(cfg *config.Config) (source.Source, error) {
	switch cfg.Source.Type {
	case "file":
		interval, err := time.ParseDuration(cfg.Source.File.ReloadInterval)
		if err != nil {
			return nil, fmt.Errorf("ocsp-responder: invalid file reload interval: %w", err)
		}
		return source.NewFileSource(cfg.Source.File.CRLPath, interval)
	case "static":
		return source.NewStaticSource(cfg.Source.Static.Status)
	case "http":
		timeout, err := time.ParseDuration(cfg.Source.HTTP.Timeout)
		if err != nil {
			return nil, fmt.Errorf("ocsp-responder: invalid HTTP source timeout: %w", err)
		}
		retryBackoff := 500 * time.Millisecond
		if cfg.Source.HTTP.RetryBackoff != "" {
			retryBackoff, err = time.ParseDuration(cfg.Source.HTTP.RetryBackoff)
			if err != nil {
				return nil, fmt.Errorf("ocsp-responder: invalid HTTP source retry backoff: %w", err)
			}
		}
		cacheTTL := time.Duration(0)
		if cfg.Source.HTTP.CacheTTL != "" {
			cacheTTL, err = time.ParseDuration(cfg.Source.HTTP.CacheTTL)
			if err != nil {
				return nil, fmt.Errorf("ocsp-responder: invalid HTTP source cache ttl: %w", err)
			}
		}
		mapping := source.ResponseMapping{
			PathTemplate:  cfg.Source.HTTP.Mapping.PathTemplate,
			StatusField:   cfg.Source.HTTP.Mapping.StatusField,
			GoodValues:    cfg.Source.HTTP.Mapping.GoodValues,
			RevokedValues: cfg.Source.HTTP.Mapping.RevokedValues,
		}
		return source.NewHTTPSource(
			cfg.Source.HTTP.BaseURL,
			cfg.Source.HTTP.RootCertFile,
			timeout,
			mapping,
			cfg.Source.HTTP.RetryMax,
			retryBackoff,
			cacheTTL,
		)
	default:
		return nil, fmt.Errorf("ocsp-responder: unknown source type %q", cfg.Source.Type)
	}
}

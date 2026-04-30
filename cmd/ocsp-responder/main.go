package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
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

	validity, _ := time.ParseDuration(cfg.Signer.ResponseValidity)
	sgn, err := signer.NewSigner(cfg.Signer.CertFile, cfg.Signer.KeyFile, cfg.Signer.IssuerCertFile, validity)
	if err != nil {
		logger.Error("failed to create signer", "err", err)
		os.Exit(1)
	}

	cacheTTL, _ := time.ParseDuration(cfg.Cache.TTL)
	resp := responder.NewResponder(src, sgn, cacheTTL, cfg.Cache.MaxEntries, cfg.Cache.Enabled, logger)

	srv := server.New(cfg, resp, sgn, src, logger)
	if err := srv.Start(); err != nil {
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
		interval, _ := time.ParseDuration(cfg.Source.File.ReloadInterval)
		return source.NewFileSource(cfg.Source.File.CRLPath, interval)
	case "static":
		return source.NewStaticSource(cfg.Source.Static.Status)
	case "http":
		return nil, fmt.Errorf("ocsp-responder: http source is not yet implemented (Phase 2)")
	default:
		return nil, fmt.Errorf("ocsp-responder: unknown source type %q", cfg.Source.Type)
	}
}

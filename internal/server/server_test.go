package server

import (
	"context"
	"crypto/tls"
	"testing"

	"github.com/hartmann-it/ocsp-responder/internal/config"
)

func TestServerStart_RejectsInvalidCacheTTL(t *testing.T) {
	s := &Server{
		cfg: &config.Config{
			Cache: config.CacheConfig{
				TTL: "definitely-not-a-duration",
			},
		},
	}

	err := s.Start(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid cache ttl")
	}
}

func TestTLSMinVersion_DefaultsToTLS12(t *testing.T) {
	if got := tlsMinVersion("not-a-version"); got != tls.VersionTLS12 {
		t.Fatalf("expected TLS1.2 fallback, got %d", got)
	}
}

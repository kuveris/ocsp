package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_RejectsInvalidCacheTTL(t *testing.T) {
	cfgPath := writeTempConfig(t, `
server:
  listen_addr: "127.0.0.1:18080"
signer:
  cert_file: "certs/ocsp.crt"
  key_file: "certs/ocsp.key"
  issuer_cert_file: "certs/issuer.crt"
  response_validity: "1h"
source:
  type: "static"
  static:
    status: "good"
cache:
  enabled: true
  ttl: "not-a-duration"
  max_entries: 100
`)

	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("expected invalid cache ttl error")
	}
	if !strings.Contains(err.Error(), "invalid cache.ttl") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoad_RejectsInvalidHTTPRetryBackoff(t *testing.T) {
	cfgPath := writeTempConfig(t, `
server:
  listen_addr: "127.0.0.1:18080"
signer:
  cert_file: "certs/ocsp.crt"
  key_file: "certs/ocsp.key"
  issuer_cert_file: "certs/issuer.crt"
  response_validity: "1h"
source:
  type: "http"
  http:
    base_url: "https://ca.example.com"
    timeout: "5s"
    retry_backoff: "bad"
cache:
  enabled: true
  ttl: "1m"
  max_entries: 100
`)

	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("expected invalid retry backoff error")
	}
	if !strings.Contains(err.Error(), "invalid source.http.retry_backoff") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return p
}

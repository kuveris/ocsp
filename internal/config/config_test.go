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

func validBaseConfig() Config {
	return Config{
		Signer: SignerConfig{
			CertFile:         "x.crt",
			KeyFile:          "x.key",
			IssuerCertFile:   "issuer.crt",
			ResponseValidity: "24h",
		},
		Source: SourceConfig{
			Type:   "static",
			Static: StaticSourceConfig{Status: "good"},
		},
		Cache: CacheConfig{TTL: "1h"},
	}
}

func TestValidate_ValidBaseConfig(t *testing.T) {
	cfg := validBaseConfig()
	if err := cfg.validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_MissingSignerCertFile(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Signer.CertFile = ""
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "signer.cert_file") {
		t.Fatalf("expected signer.cert_file error, got %v", err)
	}
}

func TestValidate_MissingSignerKeyFile(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Signer.KeyFile = ""
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "signer.key_file") {
		t.Fatalf("expected signer.key_file error, got %v", err)
	}
}

func TestValidate_MissingIssuerCertFile(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Signer.IssuerCertFile = ""
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "signer.issuer_cert_file") {
		t.Fatalf("expected signer.issuer_cert_file error, got %v", err)
	}
}

func TestValidate_UnknownSourceType(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Source.Type = "ftp"
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "invalid source.type") {
		t.Fatalf("expected invalid source.type error, got %v", err)
	}
}

func TestValidate_StaticEmptyStatus(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Source.Static.Status = ""
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for empty static status")
	}
}

func TestValidate_StaticInvalidStatus(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Source.Static.Status = "maybe"
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "invalid source.static.status") {
		t.Fatalf("expected invalid source.static.status error, got %v", err)
	}
}

func TestValidate_HTTPMissingBaseURL(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Source.Type = "http"
	cfg.Source.HTTP = HTTPSourceConfig{Timeout: "5s"}
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "source.http.base_url") {
		t.Fatalf("expected source.http.base_url error, got %v", err)
	}
}

func TestValidate_HTTPMissingTimeout(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Source.Type = "http"
	cfg.Source.HTTP = HTTPSourceConfig{BaseURL: "https://ca.example.com"}
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "source.http.timeout") {
		t.Fatalf("expected source.http.timeout error, got %v", err)
	}
}

func TestValidate_HTTPInvalidTimeout(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Source.Type = "http"
	cfg.Source.HTTP = HTTPSourceConfig{BaseURL: "https://ca.example.com", Timeout: "bad"}
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "invalid source.http.timeout") {
		t.Fatalf("expected invalid source.http.timeout error, got %v", err)
	}
}

func TestValidate_HTTPInvalidCacheTTL(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Source.Type = "http"
	cfg.Source.HTTP = HTTPSourceConfig{BaseURL: "https://ca.example.com", Timeout: "5s", CacheTTL: "bad"}
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "invalid source.http.cache_ttl") {
		t.Fatalf("expected invalid source.http.cache_ttl error, got %v", err)
	}
}

func TestValidate_HTTPDefaults(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Source.Type = "http"
	cfg.Source.HTTP = HTTPSourceConfig{BaseURL: "https://ca.example.com", Timeout: "5s"}
	if err := cfg.validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Source.HTTP.RetryMax != 3 {
		t.Errorf("expected RetryMax=3, got %d", cfg.Source.HTTP.RetryMax)
	}
	if cfg.Source.HTTP.RetryBackoff != "500ms" {
		t.Errorf("expected RetryBackoff='500ms', got %q", cfg.Source.HTTP.RetryBackoff)
	}
}

func TestValidate_FileMissingCRLPath(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Source.Type = "file"
	cfg.Source.File = FileSourceConfig{ReloadInterval: "5m"}
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "source.file.crl_path") {
		t.Fatalf("expected source.file.crl_path error, got %v", err)
	}
}

func TestValidate_FileMissingReloadInterval(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Source.Type = "file"
	cfg.Source.File = FileSourceConfig{CRLPath: "ca.crl"}
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "source.file.reload_interval") {
		t.Fatalf("expected source.file.reload_interval error, got %v", err)
	}
}

func TestValidate_FileInvalidReloadInterval(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Source.Type = "file"
	cfg.Source.File = FileSourceConfig{CRLPath: "ca.crl", ReloadInterval: "bad"}
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "invalid source.file.reload_interval") {
		t.Fatalf("expected invalid source.file.reload_interval error, got %v", err)
	}
}

func TestValidate_FileZeroReloadInterval(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Source.Type = "file"
	cfg.Source.File = FileSourceConfig{CRLPath: "ca.crl", ReloadInterval: "0s"}
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for zero reload interval")
	}
}

func TestValidate_ValidFileConfig(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Source.Type = "file"
	cfg.Source.File = FileSourceConfig{CRLPath: "ca.crl", ReloadInterval: "5m"}
	if err := cfg.validate(); err != nil {
		t.Fatalf("unexpected error for valid file config: %v", err)
	}
}

func TestValidate_InvalidResponseValidity(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Signer.ResponseValidity = "bad"
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "invalid signer.response_validity") {
		t.Fatalf("expected invalid signer.response_validity error, got %v", err)
	}
}

func TestValidate_ZeroResponseValidity(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Signer.ResponseValidity = "0s"
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for zero response validity")
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

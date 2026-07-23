package config

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
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

func TestLoad_ValidConfig(t *testing.T) {
	cfgPath := writeTempConfig(t, `
signer:
  cert_file: "certs/ocsp.crt"
  key_file: "certs/ocsp.key"
  issuer_cert_file: "certs/issuer.crt"
  response_validity: "24h"
source:
  type: "static"
  static:
    status: "good"
cache:
  enabled: true
  ttl: "1h"
  max_entries: 1000
`)
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("expected valid load, got: %v", err)
	}
	if cfg.Signer.CertFile != "certs/ocsp.crt" {
		t.Fatalf("unexpected cert_file: %q", cfg.Signer.CertFile)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent config file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	// A YAML document with a tab used for root-level indentation is a parse error.
	cfgPath := writeTempConfig(t, "\tkey: value")
	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

// TestValidate_DefaultsListenAddr covers the case where server.listen_addr is
// omitted. Without a default, an empty Addr reaches http.Server, which binds
// :80 — a privileged port, and not what the field reference documents.
func TestValidate_DefaultsListenAddr(t *testing.T) {
	cases := []struct {
		name string
		addr string
		want string
	}{
		{"omitted gets the default", "", DefaultListenAddr},
		{"explicit value is preserved", "127.0.0.1:19999", "127.0.0.1:19999"},
		{"port-only value is preserved", ":9999", ":9999"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{
				Server: ServerConfig{ListenAddr: tc.addr},
				Signer: SignerConfig{
					CertFile:         "cert.pem",
					KeyFile:          "key.pem",
					IssuerCertFile:   "issuer.pem",
					ResponseValidity: "24h",
				},
				Source: SourceConfig{
					Type:   "static",
					Static: StaticSourceConfig{Status: "good"},
				},
				Cache: CacheConfig{TTL: "1h"},
			}
			if err := c.validate(); err != nil {
				t.Fatalf("validate: %v", err)
			}
			if c.Server.ListenAddr != tc.want {
				t.Fatalf("ListenAddr = %q, want %q", c.Server.ListenAddr, tc.want)
			}
		})
	}
}

func TestDefaultListenAddr_IsNotPrivileged(t *testing.T) {
	_, port, err := net.SplitHostPort(DefaultListenAddr)
	if err != nil {
		t.Fatalf("DefaultListenAddr %q is not a valid host:port: %v", DefaultListenAddr, err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("port %q is not numeric: %v", port, err)
	}
	if n < 1024 {
		t.Fatalf("default port %d is privileged; binding it requires root", n)
	}
}

func TestValidate_ExpiryGrace(t *testing.T) {
	base := func(grace string) *Config {
		return &Config{
			Server: ServerConfig{ListenAddr: "127.0.0.1:18080"},
			Signer: SignerConfig{
				CertFile: "c", KeyFile: "k", IssuerCertFile: "i", ResponseValidity: "24h",
			},
			Source: SourceConfig{
				Type: "file",
				File: FileSourceConfig{CRLPath: "ca.crl", ReloadInterval: "5m", ExpiryGrace: grace},
			},
			Cache: CacheConfig{TTL: "1h"},
		}
	}
	cases := []struct {
		name    string
		grace   string
		wantErr bool
	}{
		{"empty is allowed and means strict", "", false},
		{"zero is allowed", "0s", false},
		{"positive duration", "10m", false},
		{"negative is rejected", "-5m", true},
		{"unparseable is rejected", "soon", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := base(tc.grace).validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected an error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestLoad_RejectsUnknownKeys pins that a misspelled field is an error rather
// than silently ignored. Silent acceptance is worse than it sounds for a
// security service: `cache.enabeld: true` means the cache is off, and a
// misspelled crl_path means the configured CRL is not the one in use, with
// nothing in the logs distinguishing "unset" from "set and discarded".
func TestLoad_RejectsUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "typo.yaml")
	if err := os.WriteFile(path, []byte(`
server:
  lissten_addr: "127.0.0.1:18080"
signer:
  cert_file: "c"
  key_file: "k"
  issuer_cert_file: "i"
  response_validity: "24h"
source:
  type: "static"
  static:
    status: "good"
cache:
  ttl: "1h"
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected a misspelled field name to be rejected")
	}
	if !strings.Contains(err.Error(), "lissten_addr") {
		t.Fatalf("expected the error to name the offending key, got %v", err)
	}
}

// TestLoad_ShippedExampleConfig guards the strictness above against
// over-rejecting: the config we tell users to start from must still load.
func TestLoad_ShippedExampleConfig(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "config", "ocsp-responder.yaml"))
	if err != nil {
		t.Fatalf("the shipped example config must load: %v", err)
	}
	if cfg.Server.ListenAddr == "" {
		t.Fatal("expected the example config to set a listen address")
	}
}

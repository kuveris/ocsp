package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kuveris/ocsp/internal/config"
)

// main() itself is not tested — it reads flags, wires dependencies and calls
// os.Exit, which is the boilerplate rule 17 allows excluding. The two helpers
// below carry real branching logic and are tested directly.

func TestBuildLogger(t *testing.T) {
	cases := []struct {
		name      string
		level     string
		format    string
		wantDebug bool
		wantInfo  bool
	}{
		{"debug json", "debug", "json", true, true},
		{"info json", "info", "json", false, true},
		{"warn text", "warn", "text", false, false},
		{"error text", "error", "text", false, false},
		{"unrecognised level falls back to info", "shout", "json", false, true},
		{"unrecognised format falls back to text", "info", "yaml", false, true},
		{"empty values fall back", "", "", false, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := buildLogger(tc.level, tc.format)
			if l == nil {
				t.Fatal("expected a logger")
			}
			if got := l.Enabled(context.Background(), slog.LevelDebug); got != tc.wantDebug {
				t.Errorf("debug enabled = %v, want %v", got, tc.wantDebug)
			}
			if got := l.Enabled(context.Background(), slog.LevelInfo); got != tc.wantInfo {
				t.Errorf("info enabled = %v, want %v", got, tc.wantInfo)
			}
			// Error is enabled at every level this function can produce.
			if !l.Enabled(context.Background(), slog.LevelError) {
				t.Error("error level should always be enabled")
			}
		})
	}
}

func TestNewSource_Static(t *testing.T) {
	cfg := &config.Config{Source: config.SourceConfig{
		Type:   "static",
		Static: config.StaticSourceConfig{Status: "revoked"},
	}}
	src, err := newSource(cfg, nil)
	if err != nil {
		t.Fatalf("newSource: %v", err)
	}
	if src.Name() != "static" {
		t.Fatalf("expected static source, got %q", src.Name())
	}
}

func TestNewSource_File(t *testing.T) {
	issuerCert, crlPath := writeTestCRL(t)
	cfg := &config.Config{Source: config.SourceConfig{
		Type: "file",
		File: config.FileSourceConfig{CRLPath: crlPath, ReloadInterval: "1m"},
	}}
	src, err := newSource(cfg, issuerCert)
	if err != nil {
		t.Fatalf("newSource: %v", err)
	}
	if src.Name() != "file" {
		t.Fatalf("expected file source, got %q", src.Name())
	}
	if closer, ok := src.(interface{ Stop() }); ok {
		closer.Stop()
	}
}

func TestNewSource_HTTP(t *testing.T) {
	cfg := &config.Config{Source: config.SourceConfig{
		Type: "http",
		HTTP: config.HTTPSourceConfig{
			BaseURL:      "https://ca.example.invalid",
			Timeout:      "10s",
			RetryBackoff: "500ms",
			CacheTTL:     "5m",
			Mapping: config.ResponseMapping{
				PathTemplate: "/certs/{serial}",
				StatusField:  "status",
				GoodValues:   []string{"valid"},
			},
		},
	}}
	src, err := newSource(cfg, nil)
	if err != nil {
		t.Fatalf("newSource: %v", err)
	}
	if src.Name() != "http" {
		t.Fatalf("expected http source, got %q", src.Name())
	}
}

// TestNewSource_Errors covers every malformed-duration branch. These are
// reachable in production despite config validation, because validate() does
// not parse every duration newSource re-parses.
func TestNewSource_Errors(t *testing.T) {
	_, crlPath := writeTestCRL(t)
	cases := []struct {
		name    string
		cfg     config.SourceConfig
		wantErr string
	}{
		{
			name: "unknown source type",
			cfg:  config.SourceConfig{Type: "carrier-pigeon"},
			// newSource falls through to the default branch.
			wantErr: "",
		},
		{
			name: "bad file reload interval",
			cfg: config.SourceConfig{Type: "file", File: config.FileSourceConfig{
				CRLPath: crlPath, ReloadInterval: "not-a-duration",
			}},
			wantErr: "invalid file reload interval",
		},
		{
			name: "bad http timeout",
			cfg: config.SourceConfig{Type: "http", HTTP: config.HTTPSourceConfig{
				BaseURL: "https://x.invalid", Timeout: "soon",
			}},
			wantErr: "invalid HTTP source timeout",
		},
		{
			name: "bad http retry backoff",
			cfg: config.SourceConfig{Type: "http", HTTP: config.HTTPSourceConfig{
				BaseURL: "https://x.invalid", Timeout: "10s", RetryBackoff: "a bit",
			}},
			wantErr: "invalid HTTP source retry backoff",
		},
		{
			name: "bad http cache ttl",
			cfg: config.SourceConfig{Type: "http", HTTP: config.HTTPSourceConfig{
				BaseURL: "https://x.invalid", Timeout: "10s", CacheTTL: "ages",
			}},
			wantErr: "invalid HTTP source cache ttl",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newSource(&config.Config{Source: tc.cfg}, nil)
			if err == nil {
				t.Fatal("expected an error")
			}
			if tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

// writeTestCRL builds a throwaway CA and an empty CRL signed by it.
func writeTestCRL(t *testing.T) (*x509.Certificate, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
	}, cert, key)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}

	path := filepath.Join(t.TempDir(), "ca.crl")
	if err := os.WriteFile(path, crlDER, 0o600); err != nil {
		t.Fatalf("write CRL: %v", err)
	}
	return cert, path
}

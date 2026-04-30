//go:build integration

package main_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hartmann-it/ocsp-responder/internal/config"
	"github.com/hartmann-it/ocsp-responder/internal/responder"
	"github.com/hartmann-it/ocsp-responder/internal/server"
	"github.com/hartmann-it/ocsp-responder/internal/signer"
	"github.com/hartmann-it/ocsp-responder/internal/source"
	xocsp "golang.org/x/crypto/ocsp"
)

// setupPKI creates a minimal test CA + OCSP signer in tmpDir and returns a CRL DER with
// the given revoked serials.
func setupPKI(t *testing.T, tmpDir string, revokedSerials []*big.Int) (
	issuerCert *x509.Certificate,
	issuerKey *rsa.PrivateKey,
	ocspCert *x509.Certificate,
	ocspKey *rsa.PrivateKey,
	crlPath string,
) {
	t.Helper()

	// Generate issuer key + cert.
	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("issuer key: %v", err)
	}
	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Integration CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("issuer cert: %v", err)
	}
	issuerCert, err = x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("parse issuer: %v", err)
	}

	// Generate OCSP signer key + cert.
	ocspKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("ocsp key: %v", err)
	}
	ocspTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Integration OCSP"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	ocspDER, err := x509.CreateCertificate(rand.Reader, ocspTmpl, issuerCert, &ocspKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("ocsp cert: %v", err)
	}
	ocspCert, err = x509.ParseCertificate(ocspDER)
	if err != nil {
		t.Fatalf("parse ocsp: %v", err)
	}

	// Write certs and keys to tmpDir.
	writePEM := func(name, typ string, b []byte) string {
		path := filepath.Join(tmpDir, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return path
	}
	writePEM("issuer.crt", "CERTIFICATE", issuerDER)
	writePEM("ocsp.crt", "CERTIFICATE", ocspDER)
	writePEM("ocsp.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(ocspKey))

	// Build CRL.
	var revEntries []pkix.RevokedCertificate
	for _, s := range revokedSerials {
		revEntries = append(revEntries, pkix.RevokedCertificate{
			SerialNumber:   s,
			RevocationTime: time.Now().Add(-time.Minute),
		})
	}
	rl := &x509.RevocationList{
		Number:              big.NewInt(1),
		ThisUpdate:          time.Now().Add(-time.Minute),
		NextUpdate:          time.Now().Add(time.Hour),
		RevokedCertificates: revEntries,
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, rl, issuerCert, issuerKey)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	crlPath = filepath.Join(tmpDir, "ca.crl")
	if err := os.WriteFile(crlPath, crlDER, 0o600); err != nil {
		t.Fatalf("write CRL: %v", err)
	}

	return issuerCert, issuerKey, ocspCert, ocspKey, crlPath
}

// startServer builds and starts an OCSP responder server on the given address.
// Returns a cancel func that shuts it down.
func startServer(t *testing.T, tmpDir, listenAddr string, cacheEnabled bool) (cancel context.CancelFunc, issuerCert *x509.Certificate) {
	t.Helper()

	revokedSerial := big.NewInt(42)
	issuerCert, _, _, _, crlPath := setupPKI(t, tmpDir, []*big.Int{revokedSerial})

	cfg := &config.Config{
		Server: config.ServerConfig{ListenAddr: listenAddr},
		Signer: config.SignerConfig{
			CertFile:         filepath.Join(tmpDir, "ocsp.crt"),
			KeyFile:          filepath.Join(tmpDir, "ocsp.key"),
			IssuerCertFile:   filepath.Join(tmpDir, "issuer.crt"),
			ResponseValidity: "1h",
		},
		Source: config.SourceConfig{
			Type: "file",
			File: config.FileSourceConfig{
				CRLPath:        crlPath,
				ReloadInterval: "1m",
			},
		},
		Cache: config.CacheConfig{
			Enabled:    cacheEnabled,
			TTL:        "1h",
			MaxEntries: 100,
		},
	}

	fileSrc, err := source.NewFileSource(cfg.Source.File.CRLPath, time.Minute)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}

	validity, _ := time.ParseDuration(cfg.Signer.ResponseValidity)
	sgn, err := signer.NewSigner(cfg.Signer.CertFile, cfg.Signer.KeyFile, cfg.Signer.IssuerCertFile, validity)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	cacheTTL, _ := time.ParseDuration(cfg.Cache.TTL)
	resp := responder.NewResponder(fileSrc, sgn, cacheTTL, cfg.Cache.MaxEntries, cfg.Cache.Enabled, nil, nil, nil)

	srv := server.New(cfg, resp, sgn, fileSrc, nil, nil)

	ctx, cancelFn := context.WithCancel(context.Background())
	go func() {
		if err := srv.Start(ctx); err != nil {
			t.Logf("server stopped: %v", err)
		}
	}()

	// Wait for server to be ready.
	deadline := time.Now().Add(3 * time.Second)
	for {
		r, err := http.Get("http://" + listenAddr + "/health")
		if err == nil {
			r.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start in time")
		}
		time.Sleep(20 * time.Millisecond)
	}

	return cancelFn, issuerCert
}

func makeOCSPRequest(t *testing.T, issuerCert *x509.Certificate, serial *big.Int) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: serial}
	der, err := xocsp.CreateRequest(tmpl, issuerCert, &xocsp.RequestOptions{Hash: crypto.SHA1})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	return der
}

func postOCSP(t *testing.T, addr string, reqDER []byte) *xocsp.Response {
	t.Helper()
	resp, err := http.Post("http://"+addr+"/", "application/ocsp-request", bytes.NewReader(reqDER))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	parsed, err := xocsp.ParseResponse(buf.Bytes(), nil)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	return parsed
}

func getOCSP(t *testing.T, addr string, reqDER []byte) *xocsp.Response {
	t.Helper()
	encoded := base64.RawURLEncoding.EncodeToString(reqDER)
	resp, err := http.Get("http://" + addr + "/" + encoded)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	parsed, err := xocsp.ParseResponse(buf.Bytes(), nil)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	return parsed
}

func TestOCSPIntegration_FileSource(t *testing.T) {
	tmpDir := t.TempDir()
	addr := "127.0.0.1:18080"
	cancel, issuerCert := startServer(t, tmpDir, addr, true)
	defer cancel()

	// Revoked serial.
	resp := postOCSP(t, addr, makeOCSPRequest(t, issuerCert, big.NewInt(42)))
	if resp.Status != xocsp.Revoked {
		t.Fatalf("expected revoked, got %d", resp.Status)
	}

	// Unknown (good — not in CRL) serial.
	resp = postOCSP(t, addr, makeOCSPRequest(t, issuerCert, big.NewInt(999)))
	if resp.Status != xocsp.Good {
		t.Fatalf("expected good, got %d", resp.Status)
	}

	// Malformed request body.
	httpResp, err := http.Post("http://"+addr+"/", "application/ocsp-request", bytes.NewReader([]byte("not-an-ocsp-request")))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", httpResp.StatusCode)
	}
}

func TestOCSPIntegration_CacheDisabled(t *testing.T) {
	tmpDir := t.TempDir()
	addr := "127.0.0.1:18081"
	cancel, issuerCert := startServer(t, tmpDir, addr, false)
	defer cancel()

	reqDER := makeOCSPRequest(t, issuerCert, big.NewInt(999))
	postOCSP(t, addr, reqDER)
	postOCSP(t, addr, reqDER)
	// With cache disabled both requests go through to the source without error.
}

func TestOCSPIntegration_HTTPSourceDegradedBehavior(t *testing.T) {
	tmpDir := t.TempDir()
	addr := "127.0.0.1:18082"

	var failUpstream atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failUpstream.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"active"}`))
	}))
	defer upstream.Close()

	issuerCert, _, _, _, _ := setupPKI(t, tmpDir, nil)
	cfg := &config.Config{
		Server: config.ServerConfig{ListenAddr: addr},
		Signer: config.SignerConfig{
			CertFile:         filepath.Join(tmpDir, "ocsp.crt"),
			KeyFile:          filepath.Join(tmpDir, "ocsp.key"),
			IssuerCertFile:   filepath.Join(tmpDir, "issuer.crt"),
			ResponseValidity: "1h",
		},
		Source: config.SourceConfig{
			Type: "http",
			HTTP: config.HTTPSourceConfig{
				BaseURL:      upstream.URL,
				Timeout:      "1s",
				RetryMax:     1,
				RetryBackoff: "10ms",
			},
		},
		Cache: config.CacheConfig{
			Enabled:    false,
			TTL:        "1h",
			MaxEntries: 100,
		},
	}

	httpSrc, err := source.NewHTTPSource(
		cfg.Source.HTTP.BaseURL,
		"",
		time.Second,
		source.ResponseMapping{},
		cfg.Source.HTTP.RetryMax,
		10*time.Millisecond,
		0,
	)
	if err != nil {
		t.Fatalf("NewHTTPSource: %v", err)
	}
	validity, err := time.ParseDuration(cfg.Signer.ResponseValidity)
	if err != nil {
		t.Fatalf("ParseDuration signer validity: %v", err)
	}
	sgn, err := signer.NewSigner(cfg.Signer.CertFile, cfg.Signer.KeyFile, cfg.Signer.IssuerCertFile, validity)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	cacheTTL, err := time.ParseDuration(cfg.Cache.TTL)
	if err != nil {
		t.Fatalf("ParseDuration cache ttl: %v", err)
	}
	resp := responder.NewResponder(httpSrc, sgn, cacheTTL, cfg.Cache.MaxEntries, cfg.Cache.Enabled, nil, nil, nil)
	srv := server.New(cfg, resp, sgn, httpSrc, nil, nil)

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()
	go func() {
		if err := srv.Start(ctx); err != nil {
			t.Logf("server stopped: %v", err)
		}
	}()

	deadline := time.Now().Add(3 * time.Second)
	for {
		r, err := http.Get("http://" + addr + "/health")
		if err == nil {
			r.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start in time")
		}
		time.Sleep(20 * time.Millisecond)
	}

	healthyResp := postOCSP(t, addr, makeOCSPRequest(t, issuerCert, big.NewInt(999)))
	if healthyResp.Status != xocsp.Good {
		t.Fatalf("expected good while upstream healthy, got %d", healthyResp.Status)
	}

	healthOK, err := http.Get("http://" + addr + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	healthOK.Body.Close()
	if healthOK.StatusCode != http.StatusOK {
		t.Fatalf("expected /health 200 while upstream healthy, got %d", healthOK.StatusCode)
	}

	failUpstream.Store(true)

	degradedResp := postOCSP(t, addr, makeOCSPRequest(t, issuerCert, big.NewInt(1000)))
	if degradedResp.Status != xocsp.Unknown {
		t.Fatalf("expected unknown when upstream degraded, got %d", degradedResp.Status)
	}

	healthDegraded, err := http.Get("http://" + addr + "/health")
	if err != nil {
		t.Fatalf("GET /health degraded: %v", err)
	}
	healthDegraded.Body.Close()
	if healthDegraded.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected /health 503 when upstream degraded, got %d", healthDegraded.StatusCode)
	}
}

func TestOCSPIntegration_HTTPSourceDegradedBehavior_GETEndpoint(t *testing.T) {
	tmpDir := t.TempDir()
	addr := "127.0.0.1:18083"

	var failUpstream atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failUpstream.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"active"}`))
	}))
	defer upstream.Close()

	issuerCert, _, _, _, _ := setupPKI(t, tmpDir, nil)
	cfg := &config.Config{
		Server: config.ServerConfig{ListenAddr: addr},
		Signer: config.SignerConfig{
			CertFile:         filepath.Join(tmpDir, "ocsp.crt"),
			KeyFile:          filepath.Join(tmpDir, "ocsp.key"),
			IssuerCertFile:   filepath.Join(tmpDir, "issuer.crt"),
			ResponseValidity: "1h",
		},
		Source: config.SourceConfig{
			Type: "http",
			HTTP: config.HTTPSourceConfig{
				BaseURL:      upstream.URL,
				Timeout:      "1s",
				RetryMax:     1,
				RetryBackoff: "10ms",
			},
		},
		Cache: config.CacheConfig{
			Enabled:    false,
			TTL:        "1h",
			MaxEntries: 100,
		},
	}

	httpSrc, err := source.NewHTTPSource(cfg.Source.HTTP.BaseURL, "", time.Second, source.ResponseMapping{}, cfg.Source.HTTP.RetryMax, 10*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewHTTPSource: %v", err)
	}
	validity, err := time.ParseDuration(cfg.Signer.ResponseValidity)
	if err != nil {
		t.Fatalf("ParseDuration signer validity: %v", err)
	}
	sgn, err := signer.NewSigner(cfg.Signer.CertFile, cfg.Signer.KeyFile, cfg.Signer.IssuerCertFile, validity)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	cacheTTL, err := time.ParseDuration(cfg.Cache.TTL)
	if err != nil {
		t.Fatalf("ParseDuration cache ttl: %v", err)
	}
	resp := responder.NewResponder(httpSrc, sgn, cacheTTL, cfg.Cache.MaxEntries, cfg.Cache.Enabled, nil, nil, nil)
	srv := server.New(cfg, resp, sgn, httpSrc, nil, nil)

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()
	go func() {
		if err := srv.Start(ctx); err != nil {
			t.Logf("server stopped: %v", err)
		}
	}()

	deadline := time.Now().Add(3 * time.Second)
	for {
		r, err := http.Get("http://" + addr + "/health")
		if err == nil {
			r.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start in time")
		}
		time.Sleep(20 * time.Millisecond)
	}

	healthyResp := getOCSP(t, addr, makeOCSPRequest(t, issuerCert, big.NewInt(2001)))
	if healthyResp.Status != xocsp.Good {
		t.Fatalf("expected good while upstream healthy, got %d", healthyResp.Status)
	}

	failUpstream.Store(true)

	degradedResp := getOCSP(t, addr, makeOCSPRequest(t, issuerCert, big.NewInt(2002)))
	if degradedResp.Status != xocsp.Unknown {
		t.Fatalf("expected unknown when upstream degraded, got %d", degradedResp.Status)
	}
}

func TestOCSPIntegration_HTTPSourceIntermittentFailures(t *testing.T) {
	tmpDir := t.TempDir()
	addr := "127.0.0.1:18084"

	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n%2 == 0 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"active"}`))
	}))
	defer upstream.Close()

	issuerCert, _, _, _, _ := setupPKI(t, tmpDir, nil)
	cfg := &config.Config{
		Server: config.ServerConfig{ListenAddr: addr},
		Signer: config.SignerConfig{
			CertFile:         filepath.Join(tmpDir, "ocsp.crt"),
			KeyFile:          filepath.Join(tmpDir, "ocsp.key"),
			IssuerCertFile:   filepath.Join(tmpDir, "issuer.crt"),
			ResponseValidity: "1h",
		},
		Source: config.SourceConfig{
			Type: "http",
			HTTP: config.HTTPSourceConfig{
				BaseURL:      upstream.URL,
				Timeout:      "1s",
				RetryMax:     1,
				RetryBackoff: "10ms",
			},
		},
		Cache: config.CacheConfig{
			Enabled:    false,
			TTL:        "1h",
			MaxEntries: 100,
		},
	}

	httpSrc, err := source.NewHTTPSource(cfg.Source.HTTP.BaseURL, "", time.Second, source.ResponseMapping{}, cfg.Source.HTTP.RetryMax, 10*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewHTTPSource: %v", err)
	}
	validity, err := time.ParseDuration(cfg.Signer.ResponseValidity)
	if err != nil {
		t.Fatalf("ParseDuration signer validity: %v", err)
	}
	sgn, err := signer.NewSigner(cfg.Signer.CertFile, cfg.Signer.KeyFile, cfg.Signer.IssuerCertFile, validity)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	cacheTTL, err := time.ParseDuration(cfg.Cache.TTL)
	if err != nil {
		t.Fatalf("ParseDuration cache ttl: %v", err)
	}
	resp := responder.NewResponder(httpSrc, sgn, cacheTTL, cfg.Cache.MaxEntries, cfg.Cache.Enabled, nil, nil, nil)
	srv := server.New(cfg, resp, sgn, httpSrc, nil, nil)

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()
	go func() {
		if err := srv.Start(ctx); err != nil {
			t.Logf("server stopped: %v", err)
		}
	}()

	deadline := time.Now().Add(3 * time.Second)
	for {
		r, err := http.Get("http://" + addr + "/health")
		if err == nil {
			r.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start in time")
		}
		time.Sleep(20 * time.Millisecond)
	}

	statuses := []int{
		postOCSP(t, addr, makeOCSPRequest(t, issuerCert, big.NewInt(3001))).Status,
		postOCSP(t, addr, makeOCSPRequest(t, issuerCert, big.NewInt(3002))).Status,
		postOCSP(t, addr, makeOCSPRequest(t, issuerCert, big.NewInt(3003))).Status,
		postOCSP(t, addr, makeOCSPRequest(t, issuerCert, big.NewInt(3004))).Status,
	}

	for i, st := range statuses {
		if st != xocsp.Good && st != xocsp.Unknown {
			t.Fatalf("unexpected status at idx %d: %d", i, st)
		}
	}
}

package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kuveris/ocsp/internal/config"
	"github.com/kuveris/ocsp/internal/responder"
	"github.com/kuveris/ocsp/internal/signer"
	"github.com/kuveris/ocsp/internal/source"
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

func TestNew_DefaultLogger(t *testing.T) {
	srv := New(nil, nil, nil, nil, nil, nil, nil)
	if srv == nil {
		t.Fatal("expected non-nil *Server")
	}
	if srv.logger == nil {
		t.Fatal("expected default logger when nil passed")
	}
}

func TestTLSMinVersion_DefaultsToTLS12(t *testing.T) {
	if got := tlsMinVersion("not-a-version"); got != tls.VersionTLS12 {
		t.Fatalf("expected TLS1.2 fallback, got %d", got)
	}
}

func TestTLSMinVersion_TLS13(t *testing.T) {
	if got := tlsMinVersion("1.3"); got != tls.VersionTLS13 {
		t.Fatalf("expected TLS1.3 (%d), got %d", tls.VersionTLS13, got)
	}
}

// newTestServer builds a fully wired Server on a free loopback port and
// returns it with the address it will listen on.
func newTestServer(t *testing.T, tlsCfg config.TLSConfig) (*Server, string) {
	t.Helper()
	pki := setupTestPKI(t, time.Now().Add(24*time.Hour))
	sgn, err := signer.NewSigner(pki.ocspCertPath, pki.ocspKeyPath, pki.issuerCertPath, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	src, err := source.NewStaticSource("good")
	if err != nil {
		t.Fatalf("NewStaticSource: %v", err)
	}
	r := responder.NewResponder(src, sgn, time.Minute, 100, true, nil, nil, nil)

	addr := freeLoopbackAddr(t)
	cfg := &config.Config{
		Server: config.ServerConfig{ListenAddr: addr, TLS: tlsCfg},
		Cache:  config.CacheConfig{TTL: "1h"},
	}
	return New(cfg, r, sgn, src, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil))), addr
}

// freeLoopbackAddr reserves a port from the kernel and releases it, so tests
// bind somewhere unused instead of a hardcoded port that may be taken.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("release port: %v", err)
	}
	return addr
}

// startAsync runs Start in a goroutine and returns its cancel func plus a
// channel carrying the eventual error.
func startAsync(t *testing.T, s *Server) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- s.Start(ctx) }()
	return cancel, errCh
}

// waitForListener polls until the address accepts a connection.
func waitForListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never started listening on %s", addr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestServerStart_ServesAndShutsDownGracefully(t *testing.T) {
	s, addr := newTestServer(t, config.TLSConfig{})
	cancel, errCh := startAsync(t, s)
	waitForListener(t, addr)

	// Every registered route should be reachable.
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/health", http.StatusOK},
		{"/metrics", http.StatusOK},
	} {
		resp, err := http.Get("http://" + addr + tc.path)
		if err != nil {
			t.Fatalf("GET %s: %v", tc.path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Fatalf("GET %s = %d, want %d", tc.path, resp.StatusCode, tc.want)
		}
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("graceful shutdown returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}

	// Start returning nil is not evidence the server stopped — it would also
	// return nil if Shutdown were never called and the listener leaked. Assert
	// the address has actually stopped serving.
	deadline := time.Now().Add(5 * time.Second)
	for {
		r, err := (&http.Client{Timeout: time.Second}).Get("http://" + addr + "/health")
		if err != nil {
			break
		}
		_ = r.Body.Close()
		if time.Now().After(deadline) {
			t.Fatal("server still serving after Start returned; Shutdown did not take effect")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestServerStart_TLSWithCertAndKey(t *testing.T) {
	certFile, keyFile := writeSelfSignedTLSPair(t)
	s, addr := newTestServer(t, config.TLSConfig{
		Enabled:    true,
		CertFile:   certFile,
		KeyFile:    keyFile,
		MinVersion: "1.3",
	})
	cancel, errCh := startAsync(t, s)
	waitForListener(t, addr)

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed test cert
	}}
	resp, err := client.Get("https://" + addr + "/health")
	if err != nil {
		t.Fatalf("GET over TLS: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 over TLS, got %d", resp.StatusCode)
	}
	if resp.TLS == nil {
		t.Fatal("expected a TLS connection")
	}

	// Asserting the negotiated version is 1.3 proves nothing: Go's client and
	// server both prefer 1.3 regardless of MinVersion, so that assertion holds
	// even if the configured min_version never reaches the listener. Pin a
	// client to 1.2 instead — with min_version "1.3" the handshake must fail.
	tls12Client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // self-signed test cert
			MaxVersion:         tls.VersionTLS12,
		},
	}}
	if r, err := tls12Client.Get("https://" + addr + "/health"); err == nil {
		_ = r.Body.Close()
		t.Fatal("a TLS 1.2 client succeeded against a server configured with min_version 1.3")
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("shutdown returned %v", err)
	}
}

func TestServerStart_TLSEnabledWithoutCertOrACME(t *testing.T) {
	s, _ := newTestServer(t, config.TLSConfig{Enabled: true})
	_, errCh := startAsync(t, s)

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected an error when TLS is enabled with no cert and no ACME host")
		}
		if !strings.Contains(err.Error(), "no cert or ACME config") {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Start did not return for misconfigured TLS")
	}
}

func TestServerStart_TLSWithACMEHost(t *testing.T) {
	s, addr := newTestServer(t, config.TLSConfig{
		Enabled:   true,
		ACMEHost:  "ocsp.test.invalid",
		ACMECAUrl: "https://acme.test.invalid/directory",
	})
	cancel, errCh := startAsync(t, s)
	waitForListener(t, addr)

	// No certificate can be issued against an unreachable directory, so ACME
	// itself cannot be exercised. What is checkable is that the branch built a
	// TLS listener at all: a plaintext HTTP request must not succeed against
	// it. Without this the whole branch could be replaced by a plain
	// ListenAndServe and the test would still pass.
	// A plaintext request to a Go TLS listener does not error at the client —
	// crypto/tls replies with a plain "400 Client sent an HTTP request to an
	// HTTPS server". So assert on the status: a plaintext /health must not
	// return 200, which it would if this branch built a non-TLS listener.
	if r, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + addr + "/health"); err == nil {
		defer func() { _ = r.Body.Close() }()
		if r.StatusCode == http.StatusOK {
			t.Fatal("ACME listener answered plaintext /health with 200; expected a TLS listener")
		}
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("shutdown returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Start did not return after cancellation")
	}
}

func TestServerStart_ListenError(t *testing.T) {
	// Occupy the port first so ListenAndServe fails immediately.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	pki := setupTestPKI(t, time.Now().Add(24*time.Hour))
	sgn, err := signer.NewSigner(pki.ocspCertPath, pki.ocspKeyPath, pki.issuerCertPath, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	src, _ := source.NewStaticSource("good")
	r := responder.NewResponder(src, sgn, time.Minute, 100, true, nil, nil, nil)
	cfg := &config.Config{
		Server: config.ServerConfig{ListenAddr: l.Addr().String()},
		Cache:  config.CacheConfig{TTL: "1h"},
	}
	s := New(cfg, r, sgn, src, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	err = s.Start(context.Background())
	if err == nil {
		t.Fatal("expected an error when the port is already bound")
	}
}

// writeSelfSignedTLSPair generates a throwaway localhost certificate.
func writeSelfSignedTLSPair(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certFile = filepath.Join(dir, "tls.crt")
	keyFile = filepath.Join(dir, "tls.key")
	writeFile := func(path string, blk *pem.Block) {
		if err := os.WriteFile(path, pem.EncodeToMemory(blk), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	writeFile(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	writeFile(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, key)})
	return certFile, keyFile
}

func mustPKCS8(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return b
}

package source

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func jsonResponse(w http.ResponseWriter, status int, body map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func newTestHTTPSource(t *testing.T, baseURL string) *HTTPSource {
	t.Helper()
	s, err := NewHTTPSource(baseURL, "", 5*time.Second, ResponseMapping{}, 3, 10*time.Millisecond, time.Minute)
	if err != nil {
		t.Fatalf("NewHTTPSource: %v", err)
	}
	return s
}

func TestHTTPSource_Good(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, map[string]interface{}{"status": "active"})
	}))
	defer srv.Close()

	s := newTestHTTPSource(t, srv.URL)
	cs, err := s.GetStatus(big.NewInt(123), nil)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if cs.Status != StatusGood {
		t.Fatalf("expected good, got %v", cs.Status)
	}
	if !s.Healthy() {
		t.Fatal("expected Healthy() = true")
	}
}

func TestHTTPSource_Revoked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, map[string]interface{}{"status": "revoked"})
	}))
	defer srv.Close()

	s := newTestHTTPSource(t, srv.URL)
	cs, err := s.GetStatus(big.NewInt(42), nil)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if cs.Status != StatusRevoked {
		t.Fatalf("expected revoked, got %v", cs.Status)
	}
	if cs.RevocationInfo == nil {
		t.Fatal("expected RevocationInfo for revoked status")
	}
}

func TestHTTPSource_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	s := newTestHTTPSource(t, srv.URL)
	cs, err := s.GetStatus(big.NewInt(999), nil)
	if err != nil {
		t.Fatalf("expected no error on 404, got %v", err)
	}
	if cs.Status != StatusUnknown {
		t.Fatalf("expected unknown on 404, got %v", cs.Status)
	}
}

func TestHTTPSource_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	s, _ := NewHTTPSource(srv.URL, "", 5*time.Second, ResponseMapping{}, 2, time.Millisecond, 0)
	_, err := s.GetStatus(big.NewInt(1), nil)
	if err == nil {
		t.Fatal("expected error after all retries fail")
	}
	if s.Healthy() {
		t.Fatal("expected Healthy() = false after error")
	}
}

func TestHTTPSource_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, _ := NewHTTPSource(srv.URL, "", 50*time.Millisecond, ResponseMapping{}, 1, time.Millisecond, 0)
	_, err := s.GetStatus(big.NewInt(1), nil)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestHTTPSource_RetrySuccess(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		jsonResponse(w, http.StatusOK, map[string]interface{}{"status": "valid"})
	}))
	defer srv.Close()

	s, _ := NewHTTPSource(srv.URL, "", 5*time.Second, ResponseMapping{}, 3, time.Millisecond, 0)
	cs, err := s.GetStatus(big.NewInt(7), nil)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if cs.Status != StatusGood {
		t.Fatalf("expected good after retry, got %v", cs.Status)
	}
	if callCount.Load() != 3 {
		t.Fatalf("expected 3 calls, got %d", callCount.Load())
	}
}

func TestHTTPSource_CustomMapping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, map[string]interface{}{"state": "issued"})
	}))
	defer srv.Close()

	mapping := ResponseMapping{
		PathTemplate:  "/certs/{serial}",
		StatusField:   "state",
		GoodValues:    []string{"issued"},
		RevokedValues: []string{"suspended"},
	}
	s, _ := NewHTTPSource(srv.URL, "", 5*time.Second, mapping, 1, time.Millisecond, 0)
	cs, err := s.GetStatus(big.NewInt(55), nil)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if cs.Status != StatusGood {
		t.Fatalf("expected good with custom mapping, got %v", cs.Status)
	}
}

func TestHTTPSource_CacheHit(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		jsonResponse(w, http.StatusOK, map[string]interface{}{"status": "active"})
	}))
	defer srv.Close()

	s, _ := NewHTTPSource(srv.URL, "", 5*time.Second, ResponseMapping{}, 1, time.Millisecond, time.Minute)
	serial := big.NewInt(99)

	for i := 0; i < 3; i++ {
		if _, err := s.GetStatus(serial, nil); err != nil {
			t.Fatalf("GetStatus attempt %d: %v", i+1, err)
		}
	}
	if callCount.Load() != 1 {
		t.Fatalf("expected server called once (cache), got %d calls", callCount.Load())
	}
}

func TestHTTPSource_TLSPinning(t *testing.T) {
	// Create a self-signed TLS certificate for the test server.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	// Write root cert PEM to temp file.
	tmpDir := t.TempDir()
	rootCertFile := filepath.Join(tmpDir, "root.crt")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err := os.WriteFile(rootCertFile, certPEM, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Start TLS server using the self-signed cert.
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, map[string]interface{}{"status": "active"})
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	srv.StartTLS()
	defer srv.Close()

	// With correct root cert → success.
	s, err := NewHTTPSource(srv.URL, rootCertFile, 5*time.Second, ResponseMapping{}, 1, time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewHTTPSource with root cert: %v", err)
	}
	cs, err := s.GetStatus(big.NewInt(1), nil)
	if err != nil {
		t.Fatalf("GetStatus with pinned cert: %v", err)
	}
	if cs.Status != StatusGood {
		t.Fatalf("expected good, got %v", cs.Status)
	}

	// Without root cert (using system trust store) → TLS error.
	s2, err := NewHTTPSource(srv.URL, "", 5*time.Second, ResponseMapping{}, 1, time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewHTTPSource without root cert: %v", err)
	}
	_, err = s2.GetStatus(big.NewInt(1), nil)
	if err == nil {
		t.Fatal("expected TLS error without pinned cert")
	}
}

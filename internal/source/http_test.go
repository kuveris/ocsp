package source

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
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

type testHTTPObserver struct {
	retries int
	errors  int
	latency int
	classes []string
}

func (o *testHTTPObserver) RecordSourceLatency(sourceName string, durationSeconds float64) {
	_ = sourceName
	_ = durationSeconds
	o.latency++
}

func (o *testHTTPObserver) RecordSourceRetry(sourceName string) {
	_ = sourceName
	o.retries++
}

func (o *testHTTPObserver) RecordSourceError(sourceName, class string) {
	_ = sourceName
	o.errors++
	o.classes = append(o.classes, class)
}

func (o *testHTTPObserver) hasClass(c string) bool {
	for _, x := range o.classes {
		if x == c {
			return true
		}
	}
	return false
}

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
	cs, err := s.GetStatus(context.Background(), big.NewInt(123), nil)
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
	cs, err := s.GetStatus(context.Background(), big.NewInt(42), nil)
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
	cs, err := s.GetStatus(context.Background(), big.NewInt(999), nil)
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
	_, err := s.GetStatus(context.Background(), big.NewInt(1), nil)
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
	_, err := s.GetStatus(context.Background(), big.NewInt(1), nil)
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
	cs, err := s.GetStatus(context.Background(), big.NewInt(7), nil)
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
	cs, err := s.GetStatus(context.Background(), big.NewInt(55), nil)
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
		if _, err := s.GetStatus(context.Background(), serial, nil); err != nil {
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
	cs, err := s.GetStatus(context.Background(), big.NewInt(1), nil)
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
	_, err = s2.GetStatus(context.Background(), big.NewInt(1), nil)
	if err == nil {
		t.Fatal("expected TLS error without pinned cert")
	}
}

func TestHTTPSource_ContextCanceled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		jsonResponse(w, http.StatusOK, map[string]interface{}{"status": "active"})
	}))
	defer srv.Close()

	s := newTestHTTPSource(t, srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := s.GetStatus(ctx, big.NewInt(123), nil); err == nil {
		t.Fatal("expected context cancellation error")
	}
}

func TestHTTPSource_ObserverTracksRetryAndError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	s, err := NewHTTPSource(srv.URL, "", 5*time.Second, ResponseMapping{}, 2, time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewHTTPSource: %v", err)
	}
	observer := &testHTTPObserver{}
	s.SetObserver(observer)

	if _, err := s.GetStatus(context.Background(), big.NewInt(9), nil); err == nil {
		t.Fatal("expected source error")
	}
	if observer.retries == 0 {
		t.Fatal("expected retry metric to be recorded")
	}
	if observer.errors == 0 {
		t.Fatal("expected error metric to be recorded")
	}
	if observer.latency == 0 {
		t.Fatal("expected latency metric to be recorded")
	}
}

func TestClassifyHTTPSourceError(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, "none"},
		{context.DeadlineExceeded, "timeout"},
		{context.Canceled, "canceled"},
		{fmt.Errorf("connection refused"), "transport_or_upstream"},
	}
	for _, tc := range cases {
		if got := classifyHTTPSourceError(tc.err); got != tc.want {
			t.Errorf("classifyHTTPSourceError(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

// TestHTTPSource_HealthyBeforeFirstLookup covers the deadlock: /health gated a
// load balancer, the source only became healthy after a successful lookup, and
// the lookup could only arrive once the balancer added the backend.
func TestHTTPSource_HealthyBeforeFirstLookup(t *testing.T) {
	s, err := NewHTTPSource("https://ca.example.invalid", "", time.Second,
		ResponseMapping{PathTemplate: "/c/{serial}", StatusField: "status", GoodValues: []string{"ok"}},
		1, time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewHTTPSource: %v", err)
	}
	if !s.Healthy() {
		t.Fatal("a freshly constructed HTTP source must report healthy; " +
			"otherwise a health-gated deployment can never receive the request that would make it healthy")
	}
}

// TestHTTPSource_UnhealthyAfterFailedLookup is the other half: optimism must
// not survive contact with a broken CA.
func TestHTTPSource_UnhealthyAfterFailedLookup(t *testing.T) {
	s, err := NewHTTPSource("http://127.0.0.1:1", "", 200*time.Millisecond,
		ResponseMapping{PathTemplate: "/c/{serial}", StatusField: "status", GoodValues: []string{"ok"}},
		1, time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewHTTPSource: %v", err)
	}
	if !s.Healthy() {
		t.Fatal("expected healthy before any lookup")
	}

	if _, err := s.GetStatus(context.Background(), big.NewInt(1), nil); err == nil {
		t.Fatal("expected the lookup against a dead endpoint to fail")
	}
	if s.Healthy() {
		t.Fatal("expected unhealthy after a failed lookup")
	}
}

// TestHTTPSource_RecoversAfterSuccessfulLookup confirms health is not a
// one-way latch.
func TestHTTPSource_RecoversAfterSuccessfulLookup(t *testing.T) {
	var up atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	s, err := NewHTTPSource(srv.URL, "", time.Second,
		ResponseMapping{PathTemplate: "/c/{serial}", StatusField: "status", GoodValues: []string{"ok"}},
		1, time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewHTTPSource: %v", err)
	}

	if _, err := s.GetStatus(context.Background(), big.NewInt(1), nil); err == nil {
		t.Fatal("expected failure while the upstream is down")
	}
	if s.Healthy() {
		t.Fatal("expected unhealthy after the failure")
	}

	up.Store(true)
	if _, err := s.GetStatus(context.Background(), big.NewInt(2), nil); err != nil {
		t.Fatalf("expected success once the upstream recovered: %v", err)
	}
	if !s.Healthy() {
		t.Fatal("expected healthy again after a successful lookup")
	}
}

// TestHTTPSource_RecoversAfterCADownUnderCacheHit covers MXS-1808 defect 2: a
// source demoted by a CA failure must recover once the CA is back, even when
// the requested serial is still cached. Without the cache bypass while
// unhealthy, the cached answer is served without a lookup and /health stays 503
// forever.
func TestHTTPSource_RecoversAfterCADownUnderCacheHit(t *testing.T) {
	var up atomic.Bool
	up.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		jsonResponse(w, http.StatusOK, map[string]interface{}{"status": "good"})
	}))
	defer srv.Close()

	s, err := NewHTTPSource(srv.URL, "", time.Second, ResponseMapping{
		PathTemplate: "/c/{serial}", StatusField: "status", GoodValues: []string{"good"},
	}, 1, time.Millisecond, time.Hour) // long cache TTL so entries do not expire during the test
	if err != nil {
		t.Fatalf("NewHTTPSource: %v", err)
	}

	// Prime the cache for serial 1 while the CA is up.
	if _, err := s.GetStatus(context.Background(), big.NewInt(1), nil); err != nil {
		t.Fatalf("initial lookup: %v", err)
	}
	if !s.Healthy() {
		t.Fatal("expected healthy after a good lookup")
	}

	// CA goes down; a different serial forces a lookup that fails and demotes.
	up.Store(false)
	if _, err := s.GetStatus(context.Background(), big.NewInt(2), nil); err == nil {
		t.Fatal("expected failure while the CA is down")
	}
	if s.Healthy() {
		t.Fatal("expected unhealthy after the CA failed")
	}

	// CA recovers. A request for the STILL-CACHED serial 1 must re-promote,
	// which only happens if the cache is bypassed while unhealthy.
	up.Store(true)
	if _, err := s.GetStatus(context.Background(), big.NewInt(1), nil); err != nil {
		t.Fatalf("lookup after recovery: %v", err)
	}
	if !s.Healthy() {
		t.Fatal("expected health to recover on a cached serial once the CA is back")
	}
}

// TestHTTPSource_RecordsUnmappedStatus covers MXS-1808 defect 1: a well-formed
// 200 whose status maps to neither good nor revoked is the misconfiguration
// signal. It stays healthy (the CA is reachable) but records an "unmapped"
// source error, distinct from a clean 404.
func TestHTTPSource_RecordsUnmappedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, map[string]interface{}{"status": "banana"})
	}))
	defer srv.Close()

	s, err := NewHTTPSource(srv.URL, "", time.Second, ResponseMapping{
		PathTemplate: "/c/{serial}", StatusField: "status", GoodValues: []string{"good"}, RevokedValues: []string{"revoked"},
	}, 1, time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewHTTPSource: %v", err)
	}
	obs := &testHTTPObserver{}
	s.SetObserver(obs)

	cs, err := s.GetStatus(context.Background(), big.NewInt(1), nil)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if cs.Status != StatusUnknown {
		t.Fatalf("expected unknown for an unmapped value, got %v", cs.Status)
	}
	if !s.Healthy() {
		t.Fatal("a reachable CA answering an unmapped value is still operational; health must stay true")
	}
	if !obs.hasClass("unmapped") {
		t.Fatalf("expected an 'unmapped' source error to be recorded, got classes %v", obs.classes)
	}
}

// TestHTTPSource_NotFoundIsCleanUnknown guards against over-recording: a 404 is
// the CA legitimately saying "I don't have this cert", not a misconfiguration,
// so it must NOT record an unmapped error.
func TestHTTPSource_NotFoundIsCleanUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	s, err := NewHTTPSource(srv.URL, "", time.Second, ResponseMapping{
		PathTemplate: "/c/{serial}", StatusField: "status", GoodValues: []string{"good"},
	}, 1, time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewHTTPSource: %v", err)
	}
	obs := &testHTTPObserver{}
	s.SetObserver(obs)

	cs, _ := s.GetStatus(context.Background(), big.NewInt(1), nil)
	if cs.Status != StatusUnknown {
		t.Fatalf("expected unknown for 404, got %v", cs.Status)
	}
	if obs.hasClass("unmapped") {
		t.Fatal("a 404 is a clean unknown, not an unmapped misconfiguration")
	}
}

package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kuveris/ocsp/internal/responder"
	"github.com/kuveris/ocsp/internal/signer"
	"github.com/kuveris/ocsp/internal/source"
	"github.com/prometheus/client_golang/prometheus"
	xocsp "golang.org/x/crypto/ocsp"
)

// errReader is an io.Reader that immediately returns an error.
type errReader struct{ err error }

func (e *errReader) Read(p []byte) (int, error) { return 0, e.err }

// newTestMetrics builds a *Metrics with unregistered prometheus collectors.
// These are never registered to any registry, so they work in any test binary
// regardless of what other tests do with the global default registry.
func newTestMetrics() *Metrics {
	return &Metrics{
		RequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "test_handler_requests_total",
			Help: "test",
		}, []string{"method", "status"}),
		RequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "test_handler_request_duration_seconds",
			Help: "test",
		}, []string{"method"}),
	}
}

// testPKI holds in-memory and on-disk PKI material for handler tests.
type testPKI struct {
	issuerCert     *x509.Certificate
	issuerKey      *rsa.PrivateKey
	issuerCertPath string
	ocspCertPath   string
	ocspKeyPath    string
}

// setupTestPKI generates a CA + OCSP signer keypair, writes them to a temp dir,
// and returns the paths needed by signer.NewSigner.
func setupTestPKI(t *testing.T, ocspNotAfter time.Time) *testPKI {
	t.Helper()
	dir := t.TempDir()

	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("issuer key: %v", err)
	}
	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
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
	issuerCert, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("parse issuer: %v", err)
	}

	ocspKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("ocsp key: %v", err)
	}
	ocspTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "OCSP Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     ocspNotAfter,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	ocspDER, err := x509.CreateCertificate(rand.Reader, ocspTmpl, issuerCert, &ocspKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("ocsp cert: %v", err)
	}

	issuerCertPath := filepath.Join(dir, "issuer.crt")
	ocspCertPath := filepath.Join(dir, "ocsp.crt")
	ocspKeyPath := filepath.Join(dir, "ocsp.key")

	write := func(path string, block *pem.Block) {
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	write(issuerCertPath, &pem.Block{Type: "CERTIFICATE", Bytes: issuerDER})
	write(ocspCertPath, &pem.Block{Type: "CERTIFICATE", Bytes: ocspDER})
	write(ocspKeyPath, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(ocspKey)})

	return &testPKI{
		issuerCert:     issuerCert,
		issuerKey:      issuerKey,
		issuerCertPath: issuerCertPath,
		ocspCertPath:   ocspCertPath,
		ocspKeyPath:    ocspKeyPath,
	}
}

func TestServeOCSP_RejectsUnsupportedMethod(t *testing.T) {
	handler := ServeOCSP(nil, time.Minute, nil, nil)
	req := httptest.NewRequest(http.MethodPut, "/", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

func TestServeOCSP_RejectsOversizedPostBody(t *testing.T) {
	handler := ServeOCSP(nil, time.Minute, nil, nil)
	body := strings.Repeat("a", maxOCSPRequestSize+1)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected %d, got %d", http.StatusRequestEntityTooLarge, rec.Code)
	}
}

func TestServeOCSP_RejectsMalformedGetEncoding(t *testing.T) {
	handler := ServeOCSP(nil, time.Minute, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/bad", nil)
	req.SetPathValue("request", "%%%bad%%%")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

func TestServeOCSP_POST_ValidRequest(t *testing.T) {
	pki := setupTestPKI(t, time.Now().Add(24*time.Hour))
	sgn, err := signer.NewSigner(pki.ocspCertPath, pki.ocspKeyPath, pki.issuerCertPath, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	src, _ := source.NewStaticSource("good")
	r := responder.NewResponder(src, sgn, time.Minute, 100, true, nil, nil, nil)

	// Build a real DER OCSP request.
	certTmpl := &x509.Certificate{SerialNumber: big.NewInt(42)}
	reqDER, err := xocsp.CreateRequest(certTmpl, pki.issuerCert, nil)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	handler := ServeOCSP(r, time.Minute, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(reqDER))
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/ocsp-response" {
		t.Fatalf("expected ocsp-response content type, got %q", ct)
	}
	resp, err := xocsp.ParseResponseForCert(rec.Body.Bytes(), nil, pki.issuerCert)
	if err != nil {
		t.Fatalf("parse OCSP response: %v", err)
	}
	if resp.Status != xocsp.Good {
		t.Fatalf("expected good, got %d", resp.Status)
	}
}

// TestServeOCSP_GET_ValidRequest covers the unpadded base64url form, which is
// not what RFC 6960 specifies but is what this responder accepted exclusively
// before MXS-1778. Kept so the lenient fallback stays wired up and existing
// callers do not break. The RFC-conformant path is covered by
// TestServeOCSP_GET_RFC6960Encoding.
func TestServeOCSP_GET_ValidRequest(t *testing.T) {
	pki := setupTestPKI(t, time.Now().Add(24*time.Hour))
	sgn, err := signer.NewSigner(pki.ocspCertPath, pki.ocspKeyPath, pki.issuerCertPath, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	src, _ := source.NewStaticSource("revoked")
	r := responder.NewResponder(src, sgn, time.Minute, 100, true, nil, nil, nil)

	certTmpl := &x509.Certificate{SerialNumber: big.NewInt(7)}
	reqDER, err := xocsp.CreateRequest(certTmpl, pki.issuerCert, nil)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(reqDER)

	handler := ServeOCSP(r, time.Minute, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/"+encoded, nil)
	req.SetPathValue("request", encoded)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	resp, err := xocsp.ParseResponseForCert(rec.Body.Bytes(), nil, pki.issuerCert)
	if err != nil {
		t.Fatalf("parse OCSP response: %v", err)
	}
	if resp.Status != xocsp.Revoked {
		t.Fatalf("expected revoked, got %d", resp.Status)
	}
	if rec.Header().Get("Cache-Control") == "" {
		t.Fatal("expected Cache-Control header on GET response")
	}
}

func TestServeHealth_OK(t *testing.T) {
	pki := setupTestPKI(t, time.Now().Add(60*24*time.Hour))
	sgn, err := signer.NewSigner(pki.ocspCertPath, pki.ocspKeyPath, pki.issuerCertPath, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	src, _ := source.NewStaticSource("good")

	handler := ServeHealth(sgn, src)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var payload map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("expected status=ok, got %v", payload["status"])
	}
	if payload["signer_valid"] != true {
		t.Fatalf("expected signer_valid=true")
	}
	if payload["source"] != "static" {
		t.Fatalf("expected source=static, got %v", payload["source"])
	}
	if payload["source_healthy"] != true {
		t.Fatalf("expected source_healthy=true")
	}
	if _, ok := payload["signer_expires_in_days"]; !ok {
		t.Fatal("expected signer_expires_in_days field")
	}
	if _, ok := payload["signer_expiry_status"]; !ok {
		t.Fatal("expected signer_expiry_status field")
	}
}

func TestServeHealth_SignerExpired(t *testing.T) {
	// Expired cert: NotAfter in the past.
	pki := setupTestPKI(t, time.Now().Add(-time.Hour))
	sgn, err := signer.NewSigner(pki.ocspCertPath, pki.ocspKeyPath, pki.issuerCertPath, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	src, _ := source.NewStaticSource("good")

	handler := ServeHealth(sgn, src)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
	var payload map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload["status"] != "unhealthy" {
		t.Fatalf("expected status=unhealthy, got %v", payload["status"])
	}
}

func TestServeHealth_SourceUnhealthy(t *testing.T) {
	pki := setupTestPKI(t, time.Now().Add(24*time.Hour))
	sgn, err := signer.NewSigner(pki.ocspCertPath, pki.ocspKeyPath, pki.issuerCertPath, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	// Use an unhealthySource stub.
	src := &unhealthySource{}

	handler := ServeHealth(sgn, src)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
	var payload map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload["status"] != "unhealthy" {
		t.Fatalf("expected status=unhealthy, got %v", payload["status"])
	}
}

func TestParseOCSPStatus_Good(t *testing.T) {
	pki := setupTestPKI(t, time.Now().Add(24*time.Hour))
	sgn, err := signer.NewSigner(pki.ocspCertPath, pki.ocspKeyPath, pki.issuerCertPath, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	der, err := sgn.CreateResponse(big.NewInt(1), source.StatusGood, nil, time.Now())
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}
	if got := parseOCSPStatus(der); got != "good" {
		t.Fatalf("expected good, got %q", got)
	}
}

func TestParseOCSPStatus_Revoked(t *testing.T) {
	pki := setupTestPKI(t, time.Now().Add(24*time.Hour))
	sgn, err := signer.NewSigner(pki.ocspCertPath, pki.ocspKeyPath, pki.issuerCertPath, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	der, err := sgn.CreateResponse(big.NewInt(2), source.StatusRevoked, &source.RevocationInfo{RevokedAt: time.Now()}, time.Now())
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}
	if got := parseOCSPStatus(der); got != "revoked" {
		t.Fatalf("expected revoked, got %q", got)
	}
}

func TestParseOCSPStatus_Unknown(t *testing.T) {
	pki := setupTestPKI(t, time.Now().Add(24*time.Hour))
	sgn, err := signer.NewSigner(pki.ocspCertPath, pki.ocspKeyPath, pki.issuerCertPath, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	der, err := sgn.CreateResponse(big.NewInt(3), source.StatusUnknown, nil, time.Now())
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}
	if got := parseOCSPStatus(der); got != "unknown" {
		t.Fatalf("expected unknown, got %q", got)
	}
}

func TestParseOCSPStatus_InvalidDER(t *testing.T) {
	if got := parseOCSPStatus([]byte("not a valid ocsp response")); got != "error" {
		t.Fatalf("expected error, got %q", got)
	}
}

func TestServeOCSP_POST_ReadBodyError(t *testing.T) {
	handler := ServeOCSP(nil, time.Minute, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/", &errReader{err: fmt.Errorf("injected read error")})
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

func TestServeOCSP_POST_WithMetrics_Error(t *testing.T) {
	m := newTestMetrics()
	handler := ServeOCSP(nil, time.Minute, m, nil)
	// Malformed body → Handle returns error → metrics.RecordRequest("post", "error", ...) path
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("nope")))
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestServeOCSP_POST_WithMetrics_Success(t *testing.T) {
	pki := setupTestPKI(t, time.Now().Add(24*time.Hour))
	sgn, err := signer.NewSigner(pki.ocspCertPath, pki.ocspKeyPath, pki.issuerCertPath, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	src, _ := source.NewStaticSource("good")
	r := responder.NewResponder(src, sgn, time.Minute, 100, true, nil, nil, nil)

	certTmpl := &x509.Certificate{SerialNumber: big.NewInt(88)}
	reqDER, err := xocsp.CreateRequest(certTmpl, pki.issuerCert, nil)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	m := newTestMetrics()
	handler := ServeOCSP(r, time.Minute, m, nil)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(reqDER))
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

// unhealthySource is a stub source that reports itself as unhealthy.
type unhealthySource struct{}

func (u *unhealthySource) GetStatus(_ context.Context, _ *big.Int, _ *x509.Certificate) (*source.CertStatus, error) {
	return &source.CertStatus{Status: source.StatusUnknown}, nil
}
func (u *unhealthySource) Name() string  { return "unhealthy-stub" }
func (u *unhealthySource) Healthy() bool { return false }

// Encoding vectors below were produced with python3's base64 module and
// cross-checked with `openssl base64`, deliberately not with Go's encoder.
// A symmetric test — encoding with the same function the handler decodes with —
// passes no matter which alphabet is chosen, which is how the base64url defect
// survived until MXS-1778.
func TestDecodeOCSPGetRequest(t *testing.T) {
	cases := []struct {
		name    string
		encoded string
		wantHex string
		wantErr bool
	}{
		{"RFC 6960 standard base64, padded", "+/+/AA==", "fbffbf00", false},
		{"standard base64, padding omitted", "+/+/AA", "fbffbf00", false},
		{"standard base64, single byte", "+w==", "fb", false},
		{"standard base64, two bytes", "+/8=", "fbff", false},
		{"legacy base64url, unpadded", "-_-_AA", "fbffbf00", false},
		{"legacy base64url, padded", "-_-_AA==", "fbffbf00", false},
		{"alphabet-neutral input", "MIIBAA==", "30820100", false},
		{"not base64", "!!!!", "", true},
		{"empty", "", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeOCSPGetRequest(tc.encoded)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got % x", tc.encoded, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("decode %q: %v", tc.encoded, err)
			}
			if hex.EncodeToString(got) != tc.wantHex {
				t.Fatalf("decode %q = %x, want %s", tc.encoded, got, tc.wantHex)
			}
		})
	}
}

// TestServeOCSP_GET_RFC6960Encoding drives a real ServeMux over a real HTTP
// connection so that percent-decoding of the path segment is exercised too,
// rather than being simulated with SetPathValue.
func TestServeOCSP_GET_RFC6960Encoding(t *testing.T) {
	pki := setupTestPKI(t, time.Now().Add(24*time.Hour))
	sgn, err := signer.NewSigner(pki.ocspCertPath, pki.ocspKeyPath, pki.issuerCertPath, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	src, _ := source.NewStaticSource("good")
	r := responder.NewResponder(src, sgn, time.Minute, 100, true, nil, nil, nil)

	certTmpl := &x509.Certificate{SerialNumber: big.NewInt(9)}
	reqDER, err := xocsp.CreateRequest(certTmpl, pki.issuerCert, nil)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{request}", ServeOCSP(r, time.Minute, nil, nil))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// RFC 6960 A.1.1: url-encoding of the base64 encoding of the DER request.
	encoded := url.PathEscape(base64.StdEncoding.EncodeToString(reqDER))

	httpResp, err := http.Get(srv.URL + "/" + encoded)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for RFC 6960 GET encoding, got %d", httpResp.StatusCode)
	}
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	resp, err := xocsp.ParseResponseForCert(body, nil, pki.issuerCert)
	if err != nil {
		t.Fatalf("parse OCSP response: %v", err)
	}
	if resp.Status != xocsp.Good {
		t.Fatalf("expected good, got %d", resp.Status)
	}
}

// TestDecodeOCSPGetRequest_SizeCap pins the GET-side equivalent of the POST
// body limit. Without it a single unauthenticated GET buys an arbitrary
// base64 decode plus ASN.1 parse, bounded only by net/http's header limit.
func TestDecodeOCSPGetRequest_SizeCap(t *testing.T) {
	atLimit := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, maxOCSPRequestSize))
	if len(atLimit) != maxOCSPGetRequestSize {
		t.Fatalf("fixture is %d encoded bytes, cap is %d", len(atLimit), maxOCSPGetRequestSize)
	}
	// At the limit the input is decodable; it is not a valid OCSP request, but
	// it must get past the size check rather than being rejected for length.
	if _, err := decodeOCSPGetRequest(atLimit); err != nil {
		t.Fatalf("input exactly at the cap was rejected: %v", err)
	}

	overLimit := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, maxOCSPRequestSize+64))
	_, err := decodeOCSPGetRequest(overLimit)
	if err == nil {
		t.Fatal("expected an oversized GET request to be rejected")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected a size error, got %v", err)
	}
}

// TestServeOCSP_GET_OversizedRejected checks the cap is wired into the handler
// and answers 400 rather than doing the work.
func TestServeOCSP_GET_OversizedRejected(t *testing.T) {
	oversized := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, 512*1024))
	handler := ServeOCSP(nil, time.Minute, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/oversized", nil)
	req.SetPathValue("request", oversized)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an oversized GET request, got %d", rec.Code)
	}
}

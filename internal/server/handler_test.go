package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hartmann-it/ocsp-responder/internal/responder"
	"github.com/hartmann-it/ocsp-responder/internal/signer"
	"github.com/hartmann-it/ocsp-responder/internal/source"
	xocsp "golang.org/x/crypto/ocsp"
)

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

// unhealthySource is a stub source that reports itself as unhealthy.
type unhealthySource struct{}

func (u *unhealthySource) GetStatus(_ context.Context, _ *big.Int, _ *x509.Certificate) (*source.CertStatus, error) {
	return &source.CertStatus{Status: source.StatusUnknown}, nil
}
func (u *unhealthySource) Name() string  { return "unhealthy-stub" }
func (u *unhealthySource) Healthy() bool { return false }

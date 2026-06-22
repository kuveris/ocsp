package signer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hartmann-it/ocsp-responder/internal/source"
	"github.com/prometheus/client_golang/prometheus"
	xocsp "golang.org/x/crypto/ocsp"
)

var (
	testDir          string
	issuerCertPath   string
	ocspCertPath     string
	ocspKeyPath      string
	expiredCertPath  string
	expiredKeyPath   string
	issuerKey        *rsa.PrivateKey
	issuerCert       *x509.Certificate
	ocspCert         *x509.Certificate
)

func TestMain(m *testing.M) {
	d, err := os.MkdirTemp("", "ocsp-responder-signer-*")
	if err != nil {
		os.Exit(1)
	}
	defer os.RemoveAll(d)
	testDir = d

	issuerKeyTmp, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		os.Exit(1)
	}
	issuerKey = issuerKeyTmp
	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Issuer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		os.Exit(1)
	}
	issuerCert, err = x509.ParseCertificate(issuerDER)
	if err != nil {
		os.Exit(1)
	}

	ocspKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		os.Exit(1)
	}
	ocspTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "OCSP Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	ocspDER, err := x509.CreateCertificate(rand.Reader, ocspTmpl, issuerCert, &ocspKey.PublicKey, issuerKey)
	if err != nil {
		os.Exit(1)
	}
	ocspCert, err = x509.ParseCertificate(ocspDER)
	if err != nil {
		os.Exit(1)
	}

	issuerCertPath = filepath.Join(d, "issuer.crt")
	ocspCertPath = filepath.Join(d, "ocsp.crt")
	ocspKeyPath = filepath.Join(d, "ocsp.key")

	if err := os.WriteFile(issuerCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER}), 0o600); err != nil {
		os.Exit(1)
	}
	if err := os.WriteFile(ocspCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ocspDER}), 0o600); err != nil {
		os.Exit(1)
	}
	if err := os.WriteFile(ocspKeyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(ocspKey)}), 0o600); err != nil {
		os.Exit(1)
	}

	// Generate expired OCSP signing cert.
	expiredKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		os.Exit(1)
	}
	expiredTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "Expired OCSP Signer"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-1 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	expiredDER, err := x509.CreateCertificate(rand.Reader, expiredTmpl, issuerCert, &expiredKey.PublicKey, issuerKey)
	if err != nil {
		os.Exit(1)
	}
	expiredCertPath = filepath.Join(d, "expired.crt")
	expiredKeyPath = filepath.Join(d, "expired.key")
	if err := os.WriteFile(expiredCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: expiredDER}), 0o600); err != nil {
		os.Exit(1)
	}
	if err := os.WriteFile(expiredKeyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(expiredKey)}), 0o600); err != nil {
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func TestSigner_LoadsValidCert(t *testing.T) {
	if _, err := NewSigner(ocspCertPath, ocspKeyPath, issuerCertPath, time.Hour); err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
}

func TestSigner_RejectsWrongEKU(t *testing.T) {
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	wrongTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(10),
		Subject:      pkix.Name{CommonName: "Wrong EKU"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, wrongTmpl, issuerCert, &wrongKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	wrongDir := t.TempDir()
	wrongCertPath := filepath.Join(wrongDir, "wrong.crt")
	wrongKeyPath := filepath.Join(wrongDir, "wrong.key")
	if err := os.WriteFile(wrongCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(wrongKeyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(wrongKey)}), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := NewSigner(wrongCertPath, wrongKeyPath, issuerCertPath, time.Hour); err == nil {
		t.Fatalf("expected error")
	}
}

func TestSigner_RejectsSignerNotSignedByIssuer(t *testing.T) {
	otherIssuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	otherIssuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(77),
		Subject:               pkix.Name{CommonName: "Other Issuer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	otherIssuerDER, err := x509.CreateCertificate(rand.Reader, otherIssuerTmpl, otherIssuerTmpl, &otherIssuerKey.PublicKey, otherIssuerKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	dir := t.TempDir()
	otherIssuerPath := filepath.Join(dir, "other-issuer.crt")
	if err := os.WriteFile(otherIssuerPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherIssuerDER}), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := NewSigner(ocspCertPath, ocspKeyPath, otherIssuerPath, time.Hour); err == nil {
		t.Fatalf("expected signer trust validation error")
	}
}

func TestSigner_CreateResponse_Good(t *testing.T) {
	s, err := NewSigner(ocspCertPath, ocspKeyPath, issuerCertPath, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	der, err := s.CreateResponse(big.NewInt(99), source.StatusGood, nil, time.Now())
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}
	resp, err := xocsp.ParseResponseForCert(der, nil, issuerCert)
	if err != nil {
		t.Fatalf("ParseResponseForCert: %v", err)
	}
	if resp.Status != xocsp.Good {
		t.Fatalf("expected good, got %d", resp.Status)
	}
}

func TestSigner_CreateResponse_Revoked(t *testing.T) {
	s, err := NewSigner(ocspCertPath, ocspKeyPath, issuerCertPath, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	now := time.Now()
	der, err := s.CreateResponse(big.NewInt(42), source.StatusRevoked, &source.RevocationInfo{RevokedAt: now, Reason: 1}, now)
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}
	resp, err := xocsp.ParseResponseForCert(der, nil, issuerCert)
	if err != nil {
		t.Fatalf("ParseResponseForCert: %v", err)
	}
	if resp.Status != xocsp.Revoked {
		t.Fatalf("expected revoked, got %d", resp.Status)
	}
	if resp.RevokedAt.IsZero() {
		t.Fatalf("expected revokedAt")
	}
}

func TestSigner_SignatureVerifiable(t *testing.T) {
	s, err := NewSigner(ocspCertPath, ocspKeyPath, issuerCertPath, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	der, err := s.CreateResponse(big.NewInt(123), source.StatusGood, nil, time.Now())
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}
	if _, err := xocsp.ParseResponseForCert(der, nil, issuerCert); err != nil {
		t.Fatalf("signature verify failed: %v", err)
	}
}

func TestSigner_ExpiredCert(t *testing.T) {
	s, err := NewSigner(expiredCertPath, expiredKeyPath, issuerCertPath, time.Hour)
	if err != nil {
		t.Fatalf("expected no error loading expired cert, got %v", err)
	}
	if s.Valid() {
		t.Fatal("expected Valid() = false for expired cert")
	}
}

// createSignerWithExpiry generates a fresh OCSP signing cert with the given NotAfter
// offset from now, signed by the global issuerCert/issuerKey from TestMain.
func createSignerWithExpiry(t *testing.T, notAfterOffset time.Duration) *Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(500),
		Subject:      pkix.Name{CommonName: "Expiry Test Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(notAfterOffset),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuerCert, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "signer.crt")
	keyPath := filepath.Join(dir, "signer.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("WriteFile cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatalf("WriteFile key: %v", err)
	}
	s, err := NewSigner(certPath, keyPath, issuerCertPath, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

func TestSigner_DaysUntilExpiry_Valid(t *testing.T) {
	s, err := NewSigner(ocspCertPath, ocspKeyPath, issuerCertPath, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if days := s.DaysUntilExpiry(); days < 0 {
		t.Fatalf("expected non-negative days for valid cert, got %d", days)
	}
}

func TestSigner_DaysUntilExpiry_Expired(t *testing.T) {
	s, err := NewSigner(expiredCertPath, expiredKeyPath, issuerCertPath, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if days := s.DaysUntilExpiry(); days >= 0 {
		t.Fatalf("expected negative days for expired cert, got %d", days)
	}
}

func TestSigner_GetExpiryStatus_OK(t *testing.T) {
	s := createSignerWithExpiry(t, 60*24*time.Hour)
	if got := s.GetExpiryStatus(); got != ExpiryOK {
		t.Fatalf("expected ExpiryOK, got %v", got)
	}
}

func TestSigner_GetExpiryStatus_Warning(t *testing.T) {
	s := createSignerWithExpiry(t, 20*24*time.Hour)
	if got := s.GetExpiryStatus(); got != ExpiryWarning {
		t.Fatalf("expected ExpiryWarning, got %v", got)
	}
}

func TestSigner_GetExpiryStatus_Critical(t *testing.T) {
	s := createSignerWithExpiry(t, 5*24*time.Hour)
	if got := s.GetExpiryStatus(); got != ExpiryCritical {
		t.Fatalf("expected ExpiryCritical, got %v", got)
	}
}

func TestSigner_GetExpiryStatus_Expired(t *testing.T) {
	s, err := NewSigner(expiredCertPath, expiredKeyPath, issuerCertPath, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if got := s.GetExpiryStatus(); got != ExpiryExpired {
		t.Fatalf("expected ExpiryExpired, got %v", got)
	}
}

func TestSigner_ExpiryStatusString(t *testing.T) {
	cases := []struct {
		status ExpiryStatus
		want   string
	}{
		{ExpiryOK, "ok"},
		{ExpiryWarning, "warning"},
		{ExpiryCritical, "critical"},
		{ExpiryExpired, "expired"},
		{ExpiryStatus(99), "unknown"},
	}
	for _, tc := range cases {
		if got := ExpiryStatusString(tc.status); got != tc.want {
			t.Errorf("ExpiryStatusString(%d) = %q, want %q", tc.status, got, tc.want)
		}
	}
}

func TestSigner_StartExpiryMonitor_SetsGauge(t *testing.T) {
	s := createSignerWithExpiry(t, 60*24*time.Hour)

	g := &recordingGauge{Gauge: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "test_signer_days_until_expiry",
		Help: "test gauge",
	})}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately so the monitor goroutine exits quickly

	s.StartExpiryMonitor(ctx, slog.Default(), g)
	time.Sleep(20 * time.Millisecond) // give the goroutine time to set the gauge

	g.mu.Lock()
	recorded := g.recorded
	g.mu.Unlock()

	if recorded != float64(s.DaysUntilExpiry()) {
		t.Fatalf("gauge = %v, want %d", recorded, s.DaysUntilExpiry())
	}
}

// recordingGauge wraps a prometheus.Gauge and records the most recent Set value.
type recordingGauge struct {
	prometheus.Gauge
	mu       sync.Mutex
	recorded float64
}

func (r *recordingGauge) Set(v float64) {
	r.mu.Lock()
	r.recorded = v
	r.mu.Unlock()
	r.Gauge.Set(v)
}

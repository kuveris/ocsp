package source

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var (
	testIssuerCert *x509.Certificate
	testIssuerKey  *rsa.PrivateKey
	testCRLPath    string
)

func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp("", "ocsp-responder-file-source-*")
	if err != nil {
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		os.Exit(1)
	}
	testIssuerKey = key

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
		os.Exit(1)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		os.Exit(1)
	}
	testIssuerCert = cert

	testCRLPath = filepath.Join(tmpDir, "ca.crl")
	if err := writeCRL(testCRLPath, cert, key, []pkix.RevokedCertificate{{
		SerialNumber:   big.NewInt(42),
		RevocationTime: time.Now(),
	}}); err != nil {
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func writeCRL(path string, issuer *x509.Certificate, issuerKey *rsa.PrivateKey, revoked []pkix.RevokedCertificate) error {
	rl := &x509.RevocationList{
		Number:              big.NewInt(1),
		ThisUpdate:          time.Now().Add(-time.Minute),
		NextUpdate:          time.Now().Add(time.Hour),
		RevokedCertificates: revoked,
	}
	der, err := x509.CreateRevocationList(rand.Reader, rl, issuer, issuerKey)
	if err != nil {
		return err
	}
	return os.WriteFile(path, der, 0o600)
}

func TestFileSource_Good(t *testing.T) {
	s, err := NewFileSource(testCRLPath, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	cs, err := s.GetStatus(big.NewInt(99), testIssuerCert)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if cs.Status != StatusGood {
		t.Fatalf("expected good, got %v", cs.Status)
	}
}

func TestFileSource_Revoked(t *testing.T) {
	s, err := NewFileSource(testCRLPath, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	cs, err := s.GetStatus(big.NewInt(42), testIssuerCert)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if cs.Status != StatusRevoked {
		t.Fatalf("expected revoked, got %v", cs.Status)
	}
	if cs.RevocationInfo == nil {
		t.Fatalf("expected revocation info")
	}
	if time.Since(cs.RevocationInfo.RevokedAt) > 10*time.Second {
		t.Fatalf("revokedAt too old: %v", cs.RevocationInfo.RevokedAt)
	}
}

// TestFileSource_NotInCRL verifies that a serial not in the CRL returns StatusGood
// (CRL is authoritative — absence from the list means the certificate is valid).
func TestFileSource_NotInCRL(t *testing.T) {
	s, err := NewFileSource(testCRLPath, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	cs, err := s.GetStatus(big.NewInt(999), testIssuerCert)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if cs.Status != StatusGood {
		t.Fatalf("expected good, got %v", cs.Status)
	}
}

func TestFileSource_InvalidCRL(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad.crl")
	if err := os.WriteFile(path, []byte("not a crl"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := NewFileSource(path, 50*time.Millisecond); err == nil {
		t.Fatalf("expected error")
	}
}

func TestFileSource_Reload(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "ca.crl")
	if err := writeCRL(path, testIssuerCert, testIssuerKey, []pkix.RevokedCertificate{{
		SerialNumber:   big.NewInt(42),
		RevocationTime: time.Now(),
	}}); err != nil {
		t.Fatalf("writeCRL: %v", err)
	}

	s, err := NewFileSource(path, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	if cs, err := s.GetStatus(big.NewInt(99), testIssuerCert); err != nil || cs.Status != StatusGood {
		t.Fatalf("expected initial good for 99, got %v err=%v", cs.Status, err)
	}

	if err := writeCRL(path, testIssuerCert, testIssuerKey, []pkix.RevokedCertificate{{
		SerialNumber:   big.NewInt(42),
		RevocationTime: time.Now(),
	}, {
		SerialNumber:   big.NewInt(99),
		RevocationTime: time.Now(),
	}}); err != nil {
		t.Fatalf("writeCRL: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		cs, err := s.GetStatus(big.NewInt(99), testIssuerCert)
		if err == nil && cs.Status == StatusRevoked {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected 99 revoked after reload, got status=%v err=%v", cs.Status, err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func TestFileSource_HTTPDownload(t *testing.T) {
	crlBytes, err := os.ReadFile(testCRLPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(crlBytes)
	}))
	defer srv.Close()

	s, err := NewFileSource(srv.URL+"/ca.crl", 50*time.Millisecond)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	if !s.Healthy() {
		t.Fatal("expected healthy")
	}
	cs, err := s.GetStatus(big.NewInt(42), testIssuerCert)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if cs.Status != StatusRevoked {
		t.Fatalf("expected revoked, got %v", cs.Status)
	}
}

func TestFileSource_HTTPDownloadFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := NewFileSource(srv.URL+"/ca.crl", 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected error when server returns 500")
	}
}

func TestFileSource_HTTPTimeout(t *testing.T) {
	// Server that hangs — close it immediately so the initial download fails
	// with a connection refused error, simulating an unreachable server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The server is closed before any request completes.
	}))
	srv.Close() // close before NewFileSource tries to connect

	_, err := NewFileSource(srv.URL+"/ca.crl", 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected error when server is unreachable")
	}
}

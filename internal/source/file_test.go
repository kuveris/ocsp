package source

import (
	"context"
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
	// testRevokedAt is the RevocationTime baked into the shared CRL fixture.
	// Assertions compare against this rather than time.Now(), so they stay
	// correct however long the package has been running under -count.
	testRevokedAt time.Time
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
	testRevokedAt = time.Now().UTC().Truncate(time.Second)
	if err := writeCRL(testCRLPath, cert, key, []pkix.RevokedCertificate{{
		SerialNumber:   big.NewInt(42),
		RevocationTime: testRevokedAt,
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
	s, err := NewFileSource(testCRLPath, 50*time.Millisecond, testIssuerCert)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer s.Stop()
	cs, err := s.GetStatus(context.Background(), big.NewInt(99), testIssuerCert)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if cs.Status != StatusGood {
		t.Fatalf("expected good, got %v", cs.Status)
	}
}

func TestFileSource_Revoked(t *testing.T) {
	s, err := NewFileSource(testCRLPath, 50*time.Millisecond, testIssuerCert)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer s.Stop()
	cs, err := s.GetStatus(context.Background(), big.NewInt(42), testIssuerCert)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if cs.Status != StatusRevoked {
		t.Fatalf("expected revoked, got %v", cs.Status)
	}
	if cs.RevocationInfo == nil {
		t.Fatalf("expected revocation info")
	}
	// Compare against the fixture's own timestamp, not elapsed wall-clock time:
	// TestMain builds the CRL once, so a time.Since() bound breaks under -count
	// as soon as the package has been running longer than the bound.
	if delta := cs.RevocationInfo.RevokedAt.Sub(testRevokedAt); delta < -time.Second || delta > time.Second {
		t.Fatalf("revokedAt %v does not match fixture %v (delta %v)",
			cs.RevocationInfo.RevokedAt, testRevokedAt, delta)
	}
}

// TestFileSource_NotInCRL verifies that a serial not in the CRL returns StatusGood
// (CRL is authoritative — absence from the list means the certificate is valid).
func TestFileSource_NotInCRL(t *testing.T) {
	s, err := NewFileSource(testCRLPath, 50*time.Millisecond, testIssuerCert)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer s.Stop()
	cs, err := s.GetStatus(context.Background(), big.NewInt(999), testIssuerCert)
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
	if _, err := NewFileSource(path, 50*time.Millisecond, testIssuerCert); err == nil {
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

	s, err := NewFileSource(path, 20*time.Millisecond, testIssuerCert)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer s.Stop()
	if cs, err := s.GetStatus(context.Background(), big.NewInt(99), testIssuerCert); err != nil || cs.Status != StatusGood {
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
		cs, err := s.GetStatus(context.Background(), big.NewInt(99), testIssuerCert)
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

	s, err := NewFileSource(srv.URL+"/ca.crl", 50*time.Millisecond, testIssuerCert)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer s.Stop()
	if !s.Healthy() {
		t.Fatal("expected healthy")
	}
	cs, err := s.GetStatus(context.Background(), big.NewInt(42), testIssuerCert)
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

	_, err := NewFileSource(srv.URL+"/ca.crl", 50*time.Millisecond, testIssuerCert)
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

	_, err := NewFileSource(srv.URL+"/ca.crl", 50*time.Millisecond, testIssuerCert)
	if err == nil {
		t.Fatal("expected error when server is unreachable")
	}
}

func TestFileSource_RejectsMismatchedIssuerCertificate(t *testing.T) {
	s, err := NewFileSource(testCRLPath, 50*time.Millisecond, testIssuerCert)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer s.Stop()

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	otherIssuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(500),
		Subject:               pkix.Name{CommonName: "Other CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	otherIssuerDER, err := x509.CreateCertificate(rand.Reader, otherIssuerTmpl, otherIssuerTmpl, &otherKey.PublicKey, otherKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	otherIssuer, err := x509.ParseCertificate(otherIssuerDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	if _, err := s.GetStatus(context.Background(), big.NewInt(42), otherIssuer); err == nil {
		t.Fatal("expected CRL issuer verification error")
	}
}

func TestFileSource_Name(t *testing.T) {
	s, err := NewFileSource(testCRLPath, time.Minute, testIssuerCert)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer s.Stop()
	if got := s.Name(); got != "file" {
		t.Fatalf("expected 'file', got %q", got)
	}
}

func TestFileSource_GetStatus_Unloaded(t *testing.T) {
	s, err := NewFileSource(testCRLPath, time.Minute, testIssuerCert)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer s.Stop()

	s.loaded.Store(false) // simulate a failed CRL reload
	_, err = s.GetStatus(context.Background(), big.NewInt(1), testIssuerCert)
	if err != ErrSourceUnhealthy {
		t.Fatalf("expected ErrSourceUnhealthy, got %v", err)
	}
}

func TestFileSource_GetStatus_NilIssuer(t *testing.T) {
	s, err := NewFileSource(testCRLPath, time.Minute, testIssuerCert)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer s.Stop()

	_, err = s.GetStatus(context.Background(), big.NewInt(1), nil)
	if err == nil {
		t.Fatal("expected error for nil issuer")
	}
}

func TestFileSource_GetStatus_CanceledContext(t *testing.T) {
	s, err := NewFileSource(testCRLPath, time.Minute, testIssuerCert)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer s.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.GetStatus(ctx, big.NewInt(1), testIssuerCert)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestFileSource_RevokedWithReasonCode(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "reason.crl")

	rl := &x509.RevocationList{
		Number:     big.NewInt(2),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   big.NewInt(55),
				RevocationTime: time.Now(),
				ReasonCode:     1, // keyCompromise
			},
		},
	}
	der, err := x509.CreateRevocationList(rand.Reader, rl, testIssuerCert, testIssuerKey)
	if err != nil {
		t.Fatalf("CreateRevocationList: %v", err)
	}
	if err := os.WriteFile(path, der, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s, err := NewFileSource(path, time.Minute, testIssuerCert)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer s.Stop()

	cs, err := s.GetStatus(context.Background(), big.NewInt(55), testIssuerCert)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if cs.Status != StatusRevoked {
		t.Fatalf("expected revoked, got %v", cs.Status)
	}
	if cs.RevocationInfo == nil || cs.RevocationInfo.Reason != 1 {
		t.Fatalf("expected reason=1, got %+v", cs.RevocationInfo)
	}
}

func TestFileSource_ReloadLoop_StatError(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "loop.crl")
	if err := writeCRL(path, testIssuerCert, testIssuerKey, nil); err != nil {
		t.Fatalf("writeCRL: %v", err)
	}

	s, err := NewFileSource(path, 20*time.Millisecond, testIssuerCert)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer s.Stop()

	if !s.Healthy() {
		t.Fatal("expected healthy before file deletion")
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	// Wait for reload tick + slack; a read error in the reload loop sets loaded=false.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if !s.Healthy() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("expected source to become unhealthy after file deletion")
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func TestFileSource_ReloadLoop_FileNotModified(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "nomod.crl")
	if err := writeCRL(path, testIssuerCert, testIssuerKey, nil); err != nil {
		t.Fatalf("writeCRL: %v", err)
	}

	s, err := NewFileSource(path, 20*time.Millisecond, testIssuerCert)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer s.Stop()

	// Wait for multiple reload ticks; each recomputes the digest, finds it
	// unchanged, and skips the parse/swap.
	time.Sleep(80 * time.Millisecond)

	// Source should still be healthy — skipping reload on unchanged file is benign.
	if !s.Healthy() {
		t.Fatal("expected source to remain healthy when file not modified")
	}
}

func TestFileSource_LoadFromDisk_StatError(t *testing.T) {
	s, err := NewFileSource(testCRLPath, time.Minute, testIssuerCert)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer s.Stop()

	s.crlPath = "/nonexistent/does/not/exist.crl"
	s.isURL = false
	if err := s.loadFromDisk(); err == nil {
		t.Fatal("expected error for nonexistent file path")
	}
}

func TestFileSource_CRLWrongIssuer(t *testing.T) {
	// Generate a different CA and sign a CRL with it.
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	otherCATmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(999),
		Subject:               pkix.Name{CommonName: "Other CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	otherCADER, err := x509.CreateCertificate(rand.Reader, otherCATmpl, otherCATmpl, &otherKey.PublicKey, otherKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	otherCA, err := x509.ParseCertificate(otherCADER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	// CRL signed by otherCA, but we'll try to load it against testIssuerCert.
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "other.crl")
	if err := writeCRL(path, otherCA, otherKey, nil); err != nil {
		t.Fatalf("writeCRL: %v", err)
	}

	if _, err := NewFileSource(path, time.Minute, testIssuerCert); err == nil {
		t.Fatal("expected error when CRL is signed by a different issuer")
	}
}

// TestFileSource_ReloadDetectsBackdatedCRL covers the operational case that
// mtime-based change detection gets wrong: a CRL swapped in with a timestamp
// older than the one already loaded, as produced by cp -p, rsync -a,
// install -p, or a restore from backup. The contents changed, so the responder
// must pick it up regardless of what the timestamp claims.
func TestFileSource_ReloadDetectsBackdatedCRL(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "backdated.crl")
	if err := writeCRL(path, testIssuerCert, testIssuerKey, []pkix.RevokedCertificate{{
		SerialNumber:   big.NewInt(42),
		RevocationTime: time.Now(),
	}}); err != nil {
		t.Fatalf("writeCRL: %v", err)
	}

	s, err := NewFileSource(path, 20*time.Millisecond, testIssuerCert)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer s.Stop()

	if cs, err := s.GetStatus(context.Background(), big.NewInt(99), testIssuerCert); err != nil || cs.Status != StatusGood {
		t.Fatalf("expected initial good for 99, got %v err=%v", cs.Status, err)
	}

	// Replace the CRL, then backdate it an hour into the past.
	if err := writeCRL(path, testIssuerCert, testIssuerKey, []pkix.RevokedCertificate{{
		SerialNumber:   big.NewInt(42),
		RevocationTime: time.Now(),
	}, {
		SerialNumber:   big.NewInt(99),
		RevocationTime: time.Now(),
	}}); err != nil {
		t.Fatalf("writeCRL: %v", err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		cs, err := s.GetStatus(context.Background(), big.NewInt(99), testIssuerCert)
		if err == nil && cs.Status == StatusRevoked {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("backdated CRL was never reloaded: status=%v err=%v", cs.Status, err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// TestFileSource_ReloadIsDeterministic guards the flake in MXS-1780 directly:
// an immediate rewrite frequently lands in the same coarse filesystem
// timestamp tick as the previous write, so change detection must not depend on
// mtime advancing.
func TestFileSource_ReloadIsDeterministic(t *testing.T) {
	for i := 0; i < 20; i++ {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "rapid.crl")
		if err := writeCRL(path, testIssuerCert, testIssuerKey, nil); err != nil {
			t.Fatalf("writeCRL: %v", err)
		}
		s, err := NewFileSource(path, 10*time.Millisecond, testIssuerCert)
		if err != nil {
			t.Fatalf("NewFileSource: %v", err)
		}

		// Rewrite immediately, with no intervening work to push the write into
		// a later tick.
		if err := writeCRL(path, testIssuerCert, testIssuerKey, []pkix.RevokedCertificate{{
			SerialNumber:   big.NewInt(7),
			RevocationTime: time.Now(),
		}}); err != nil {
			s.Stop()
			t.Fatalf("writeCRL: %v", err)
		}

		deadline := time.Now().Add(2 * time.Second)
		reloaded := false
		for !reloaded {
			cs, err := s.GetStatus(context.Background(), big.NewInt(7), testIssuerCert)
			if err == nil && cs.Status == StatusRevoked {
				reloaded = true
				break
			}
			if time.Now().After(deadline) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		s.Stop()
		if !reloaded {
			t.Fatalf("iteration %d: rewrite was never reloaded", i)
		}
	}
}

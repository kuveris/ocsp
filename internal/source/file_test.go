package source

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// TestFileSource_ReloadSurvivesIdenticalMtime pins the coarse-timestamp half
// of the change-detection contract. The replacement CRL is forced to carry the
// *same* mtime as the one already loaded, which is what a rapid rewrite looks
// like on a filesystem whose timestamp granularity is coarser than the gap
// between the two writes.
//
// Forcing the timestamp rather than racing the clock matters: on a filesystem
// with nanosecond mtime granularity an immediate rewrite gets a strictly newer
// mtime, so a timing-based version of this test passes even against a
// mtime-comparing implementation and guards nothing.
func TestFileSource_ReloadSurvivesIdenticalMtime(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "sametime.crl")
	if err := writeCRL(path, testIssuerCert, testIssuerKey, nil); err != nil {
		t.Fatalf("writeCRL: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	original := info.ModTime()

	s, err := NewFileSource(path, 20*time.Millisecond, testIssuerCert)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer s.Stop()

	if err := writeCRL(path, testIssuerCert, testIssuerKey, []pkix.RevokedCertificate{{
		SerialNumber:   big.NewInt(7),
		RevocationTime: time.Now(),
	}}); err != nil {
		t.Fatalf("writeCRL: %v", err)
	}
	// Pin the replacement to the original timestamp. An implementation that
	// compares modification times cannot see this change at all.
	if err := os.Chtimes(path, original, original); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		cs, err := s.GetStatus(context.Background(), big.NewInt(7), testIssuerCert)
		if err == nil && cs.Status == StatusRevoked {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("CRL with an identical mtime was never reloaded")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestFileSource_RecoversAfterTransientReadError covers a regression: change
// detection short-circuits on an unchanged digest, but the parse it skips is
// the only thing that sets loaded=true. A momentary read failure followed by
// the *identical* CRL returning must still re-arm the source, or a blip
// becomes a permanent outage that only a restart clears.
func TestFileSource_RecoversAfterTransientReadError(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "transient.crl")
	if err := writeCRL(path, testIssuerCert, testIssuerKey, []pkix.RevokedCertificate{{
		SerialNumber:   big.NewInt(42),
		RevocationTime: time.Now(),
	}}); err != nil {
		t.Fatalf("writeCRL: %v", err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	s, err := NewFileSource(path, 20*time.Millisecond, testIssuerCert)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer s.Stop()
	if !s.Healthy() {
		t.Fatal("expected healthy after load")
	}

	// Remove the file so a reload tick fails, then restore byte-identical
	// content — exactly what a non-atomic publish or an NFS blip looks like.
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for s.Healthy() {
		if time.Now().After(deadline) {
			t.Fatal("source never went unhealthy after the file was removed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatalf("restore: %v", err)
	}

	deadline = time.Now().Add(3 * time.Second)
	for !s.Healthy() {
		if time.Now().After(deadline) {
			t.Fatal("source stuck unhealthy after the identical CRL was restored")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if cs, err := s.GetStatus(context.Background(), big.NewInt(42), testIssuerCert); err != nil || cs.Status != StatusRevoked {
		t.Fatalf("expected revoked after recovery, got %v err=%v", cs.Status, err)
	}
}

// TestFileSource_RecoversAfterCorruptThenRollback is the operator-facing shape
// of the same defect: a bad CRL is published, then rolled back to the version
// that was already loaded.
func TestFileSource_RecoversAfterCorruptThenRollback(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "rollback.crl")
	if err := writeCRL(path, testIssuerCert, testIssuerKey, nil); err != nil {
		t.Fatalf("writeCRL: %v", err)
	}
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	s, err := NewFileSource(path, 20*time.Millisecond, testIssuerCert)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer s.Stop()

	if err := os.WriteFile(path, []byte("not a CRL"), 0o600); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for s.Healthy() {
		if time.Now().After(deadline) {
			t.Fatal("source never went unhealthy on a corrupt CRL")
		}
		time.Sleep(20 * time.Millisecond)
	}

	if err := os.WriteFile(path, good, 0o600); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for {
		if s.Healthy() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("source stuck unhealthy after rollback to the previously-loaded CRL")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// writeCRLWithNextUpdate writes a CRL with an explicit NextUpdate, so expiry
// behaviour can be tested without waiting.
func writeCRLWithNextUpdate(path string, issuer *x509.Certificate, issuerKey *rsa.PrivateKey, nextUpdate time.Time, revoked []pkix.RevokedCertificate) error {
	rl := &x509.RevocationList{
		Number:              big.NewInt(1),
		ThisUpdate:          nextUpdate.Add(-time.Hour),
		NextUpdate:          nextUpdate,
		RevokedCertificates: revoked,
	}
	der, err := x509.CreateRevocationList(rand.Reader, rl, issuer, issuerKey)
	if err != nil {
		return err
	}
	return os.WriteFile(path, der, 0o600)
}

// TestFileSource_ExpiredCRLAtStartupFailsClosed covers the core invariant at
// load time: a CRL already past its NextUpdate must not answer `good`. It is a
// transient condition rather than a startup failure — the source constructs but
// reports unhealthy and answers `unknown`, so a routine publication delay does
// not become a crash loop.
func TestFileSource_ExpiredCRLAtStartupFailsClosed(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "expired.crl")
	if err := writeCRLWithNextUpdate(path, testIssuerCert, testIssuerKey,
		time.Now().Add(-24*time.Hour), []pkix.RevokedCertificate{{
			SerialNumber:   big.NewInt(42),
			RevocationTime: time.Now(),
		}}); err != nil {
		t.Fatalf("writeCRL: %v", err)
	}

	s, err := NewFileSource(path, time.Minute, testIssuerCert)
	if err != nil {
		t.Fatalf("an expired CRL should construct, not fail startup: %v", err)
	}
	defer s.Stop()
	if s.Healthy() {
		t.Fatal("expected unhealthy for an expired CRL at startup")
	}
	if _, err := s.GetStatus(context.Background(), big.NewInt(99), testIssuerCert); !errors.Is(err, ErrSourceUnhealthy) {
		t.Fatalf("expected ErrSourceUnhealthy, got %v", err)
	}
}

// TestFileSource_ExpiredInPlaceFailsClosed is the regression for the defect
// review found: a CRL valid at load that expires while the file on disk never
// changes. Content-hash change detection skips the re-parse, so a load-time
// only expiry check would keep serving `good` forever. The file is deliberately
// never rewritten.
func TestFileSource_ExpiredInPlaceFailsClosed(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "inplace.crl")
	// A generous validity window so construction — which under -race with other
	// packages competing for CPU can be slow — cannot eat it before the
	// "healthy while valid" check below. The reload interval is an hour, so the
	// file is never re-read: this exercises the live expiry check, not reload.
	const validFor = 2 * time.Second
	if err := writeCRLWithNextUpdate(path, testIssuerCert, testIssuerKey, time.Now().Add(validFor), nil); err != nil {
		t.Fatalf("writeCRL: %v", err)
	}

	s, err := NewFileSource(path, time.Hour, testIssuerCert)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer s.Stop()
	if !s.Healthy() {
		t.Fatal("expected healthy while the CRL is still valid")
	}

	time.Sleep(validFor + 300*time.Millisecond)

	if s.Healthy() {
		t.Fatal("source still healthy after its CRL expired in place; the file was never re-read")
	}
	if _, err := s.GetStatus(context.Background(), big.NewInt(99), testIssuerCert); !errors.Is(err, ErrSourceUnhealthy) {
		t.Fatalf("expected ErrSourceUnhealthy after in-place expiry, got %v", err)
	}
}

// TestFileSource_ExpiredCRLOnReloadFailsClosed covers the runtime path: a CRL
// that expires (or is replaced by an expired one) while the responder is
// running must take the source unhealthy so answers become `unknown`, never a
// stale `good`.
func TestFileSource_ExpiredCRLOnReloadFailsClosed(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "reload-expiry.crl")
	if err := writeCRLWithNextUpdate(path, testIssuerCert, testIssuerKey,
		time.Now().Add(time.Hour), []pkix.RevokedCertificate{{
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
	if !s.Healthy() {
		t.Fatal("expected healthy with a valid CRL")
	}

	if err := writeCRLWithNextUpdate(path, testIssuerCert, testIssuerKey,
		time.Now().Add(-time.Minute), nil); err != nil {
		t.Fatalf("writeCRL: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for s.Healthy() {
		if time.Now().After(deadline) {
			t.Fatal("source stayed healthy after the CRL expired")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// A previously-good serial must now be unknown, not good.
	if _, err := s.GetStatus(context.Background(), big.NewInt(99), testIssuerCert); !errors.Is(err, ErrSourceUnhealthy) {
		t.Fatalf("expected ErrSourceUnhealthy once the CRL expired, got %v", err)
	}
}

// TestFileSource_ExpiryGrace covers the operator escape hatch: a CA that
// publishes late should not take the responder down the instant NextUpdate
// passes. Health is what reflects the grace, not construction — an expired CRL
// always constructs now.
func TestFileSource_ExpiryGrace(t *testing.T) {
	tmpDir := t.TempDir()

	newExpired := func(name string, opts ...FileSourceOption) *FileSource {
		t.Helper()
		path := filepath.Join(tmpDir, name)
		if err := writeCRLWithNextUpdate(path, testIssuerCert, testIssuerKey,
			time.Now().Add(-30*time.Second), nil); err != nil {
			t.Fatalf("writeCRL: %v", err)
		}
		s, err := NewFileSource(path, time.Minute, testIssuerCert, opts...)
		if err != nil {
			t.Fatalf("NewFileSource: %v", err)
		}
		return s
	}

	// Without grace: unhealthy.
	s0 := newExpired("nograce.crl")
	defer s0.Stop()
	if s0.Healthy() {
		t.Fatal("expected unhealthy without a grace period")
	}

	// Grace wider than the overrun: healthy.
	s1 := newExpired("wide.crl", WithCRLExpiryGrace(10*time.Minute))
	defer s1.Stop()
	if !s1.Healthy() {
		t.Fatal("expected healthy within the grace period")
	}

	// Grace narrower than the overrun: unhealthy.
	s2 := newExpired("narrow.crl", WithCRLExpiryGrace(5*time.Second))
	defer s2.Stop()
	if s2.Healthy() {
		t.Fatal("expected unhealthy when the grace period is shorter than the overrun")
	}
}

// TestCRLExpired covers the expiry predicate directly, including the
// zero-NextUpdate case — Go's x509.CreateRevocationList refuses to emit a CRL
// without a NextUpdate, so that branch is only reachable from a non-Go CA.
func TestCRLExpired(t *testing.T) {
	cases := []struct {
		name       string
		nextUpdate time.Time
		grace      time.Duration
		want       bool
	}{
		{"no NextUpdate is never expired", time.Time{}, 0, false},
		{"future NextUpdate", time.Now().Add(time.Hour), 0, false},
		{"expired, no grace", time.Now().Add(-time.Minute), 0, true},
		{"expired within grace", time.Now().Add(-time.Minute), time.Hour, false},
		{"expired beyond grace", time.Now().Add(-time.Hour), time.Minute, true},
		{"grace does not resurrect a long-dead CRL", time.Now().Add(-365 * 24 * time.Hour), 24 * time.Hour, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &FileSource{expiryGrace: tc.grace, nextUpdate: tc.nextUpdate}
			if got := s.crlExpired(); got != tc.want {
				t.Fatalf("crlExpired() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestFileSource_LogsExpiryOnce pins the operator-facing half of failing
// closed: the reason must be logged, at a level a default deployment sees, and
// exactly once rather than every reload tick.
//
// The handler is at Info level deliberately — the earlier version of this test
// ran at Debug and so could not tell the Error transition line from a Debug
// repeat, letting a "log nothing but Debug" regression pass.
func TestFileSource_LogsExpiryOnce(t *testing.T) {
	buf := &lockedBuffer{}
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "logging.crl")
	// Valid briefly, then expires in place with the file untouched.
	if err := writeCRLWithNextUpdate(path, testIssuerCert, testIssuerKey,
		time.Now().Add(300*time.Millisecond), nil); err != nil {
		t.Fatalf("writeCRL: %v", err)
	}

	s, err := NewFileSource(path, 20*time.Millisecond, testIssuerCert, WithLogger(logger))
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer s.Stop()

	deadline := time.Now().Add(3 * time.Second)
	for s.Healthy() {
		if time.Now().After(deadline) {
			t.Fatal("source never went unhealthy")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Give several more reload ticks a chance to re-log.
	time.Sleep(200 * time.Millisecond)

	out := buf.String()
	if n := strings.Count(out, "CRL expired"); n != 1 {
		t.Fatalf("expected the expiry to be logged exactly once at Info+, got %d occurrences in:\n%s", n, out)
	}
}

// lockedBuffer is a concurrency-safe io.Writer for capturing log output that a
// background goroutine produces.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

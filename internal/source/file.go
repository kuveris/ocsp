package source

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// FileSource reads a CRL file (PEM or DER format) and uses it to determine certificate status.
// crl_path may be a local file path or an HTTP(S) URL.
// It automatically reloads the CRL when the file is modified (file) or on each reload interval (URL).
// It is safe for concurrent use. Call Stop() to release the background reload goroutine.
type FileSource struct {
	crlPath        string
	reloadInterval time.Duration
	issuerCert     *x509.Certificate
	isURL          bool

	mu      sync.RWMutex
	revoked map[string]pkix.RevokedCertificate
	loaded  atomic.Bool

	// lastHash is the SHA-256 digest of the CRL bytes currently loaded.
	//
	// Change detection deliberately hashes contents rather than comparing
	// modification times. Filesystem timestamps come from a coarse clock, so
	// two writes in quick succession routinely share an mtime; and timestamp
	// preserving copies (cp -p, rsync -a, install -p, backup restores) can
	// install a new CRL whose mtime is *older* than the loaded one. Either way
	// an mtime comparison silently keeps serving stale revocation data, which
	// for an OCSP responder means reporting a revoked certificate as good.
	lastHashMu sync.RWMutex
	lastHash   [sha256.Size]byte

	done chan struct{}
}

// NewFileSource creates a FileSource.
// crlPath: path to the CRL file (PEM or DER auto-detected) or an HTTP(S) URL
// reloadInterval: how often to check for file changes / re-download the URL
func NewFileSource(crlPath string, reloadInterval time.Duration, issuerCert *x509.Certificate) (*FileSource, error) {
	if issuerCert == nil {
		return nil, fmt.Errorf("ocsp-responder/source: issuer certificate is required")
	}
	isURL := strings.HasPrefix(crlPath, "http://") || strings.HasPrefix(crlPath, "https://")
	s := &FileSource{crlPath: crlPath, reloadInterval: reloadInterval, issuerCert: issuerCert, isURL: isURL, done: make(chan struct{})}
	if err := s.loadCRL(); err != nil {
		return nil, err
	}
	go s.reloadLoop()
	return s, nil
}

// Stop stops the background CRL reload goroutine. It is safe to call once.
func (s *FileSource) Stop() {
	close(s.done)
}

func (s *FileSource) Name() string { return "file" }

func (s *FileSource) Healthy() bool { return s.loaded.Load() }

func (s *FileSource) GetStatus(ctx context.Context, serial *big.Int, issuer *x509.Certificate) (*CertStatus, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !s.loaded.Load() {
		return nil, ErrSourceUnhealthy
	}
	if issuer == nil {
		return nil, fmt.Errorf("ocsp-responder/source: issuer certificate required")
	}
	if !bytes.Equal(issuer.RawSubject, s.issuerCert.RawSubject) {
		return nil, fmt.Errorf("ocsp-responder/source: issuer certificate mismatch")
	}

	s.mu.RLock()
	rev, ok := s.revoked[serial.String()]
	s.mu.RUnlock()

	if ok {
		reason := 0
		if len(rev.Extensions) > 0 {
			for _, ext := range rev.Extensions {
				if ext.Id.Equal([]int{2, 5, 29, 21}) {
					if len(ext.Value) > 0 {
						reason = int(ext.Value[len(ext.Value)-1])
					}
					break
				}
			}
		}
		return &CertStatus{
			Status: StatusRevoked,
			RevocationInfo: &RevocationInfo{
				RevokedAt: rev.RevocationTime,
				Reason:    reason,
			},
		}, nil
	}

	return &CertStatus{Status: StatusGood}, nil
}

func (s *FileSource) reloadLoop() {
	t := time.NewTicker(s.reloadInterval)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			if s.isURL {
				if err := s.loadFromURL(); err != nil {
					s.loaded.Store(false)
				}
				continue
			}
			if err := s.reloadFromDiskIfChanged(); err != nil {
				s.loaded.Store(false)
			}
		}
	}
}

// loadCRL dispatches to loadFromURL or loadFromDisk based on the path type.
func (s *FileSource) loadCRL() error {
	if s.isURL {
		return s.loadFromURL()
	}
	return s.loadFromDisk()
}

// loadFromURL downloads the CRL from an HTTP(S) URL and parses it.
func (s *FileSource) loadFromURL() error {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(s.crlPath)
	if err != nil {
		return fmt.Errorf("ocsp-responder/source: downloading CRL: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ocsp-responder/source: downloading CRL: HTTP %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("ocsp-responder/source: reading CRL body: %w", err)
	}

	return s.parseCRLBytes(b)
}

func (s *FileSource) loadFromDisk() error {
	b, sum, err := s.readCRLFile()
	if err != nil {
		return err
	}
	if err := s.parseCRLBytes(b); err != nil {
		return err
	}
	s.storeHash(sum)
	return nil
}

// reloadFromDiskIfChanged parses and swaps in the CRL only when its contents
// differ from what is currently loaded. Reading the file on every tick is
// deliberate: it is the only way to detect a change that the filesystem
// timestamp does not report. CRLs are small and the interval is measured in
// minutes, so the read is not worth optimising away with a stat pre-check that
// would reintroduce the bug it replaced.
func (s *FileSource) reloadFromDiskIfChanged() error {
	b, sum, err := s.readCRLFile()
	if err != nil {
		return err
	}

	s.lastHashMu.RLock()
	unchanged := sum == s.lastHash
	s.lastHashMu.RUnlock()
	if unchanged {
		return nil
	}

	if err := s.parseCRLBytes(b); err != nil {
		return err
	}
	s.storeHash(sum)
	return nil
}

// readCRLFile reads the CRL file and returns its contents with their digest.
func (s *FileSource) readCRLFile() ([]byte, [sha256.Size]byte, error) {
	b, err := os.ReadFile(s.crlPath)
	if err != nil {
		return nil, [sha256.Size]byte{}, fmt.Errorf("ocsp-responder/source: %w", err)
	}
	return b, sha256.Sum256(b), nil
}

func (s *FileSource) storeHash(sum [sha256.Size]byte) {
	s.lastHashMu.Lock()
	s.lastHash = sum
	s.lastHashMu.Unlock()
}

func (s *FileSource) parseCRLBytes(b []byte) error {
	der := b
	if blk, _ := pem.Decode(b); blk != nil {
		der = blk.Bytes
	}

	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		return fmt.Errorf("ocsp-responder/source: %w", ErrInvalidCRL)
	}
	if err := verifyCRLForIssuer(rl, s.issuerCert); err != nil {
		return err
	}

	revoked := make(map[string]pkix.RevokedCertificate, len(rl.RevokedCertificateEntries))
	for _, rc := range rl.RevokedCertificateEntries {
		revoked[rc.SerialNumber.String()] = pkix.RevokedCertificate{
			SerialNumber:   rc.SerialNumber,
			RevocationTime: rc.RevocationTime,
			Extensions:     rc.Extensions,
		}
	}

	s.mu.Lock()
	s.revoked = revoked
	s.mu.Unlock()

	s.loaded.Store(true)
	return nil
}

func verifyCRLForIssuer(rl *x509.RevocationList, issuer *x509.Certificate) error {
	if !bytes.Equal(rl.RawIssuer, issuer.RawSubject) {
		return fmt.Errorf("ocsp-responder/source: CRL issuer mismatch")
	}
	if err := rl.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("ocsp-responder/source: CRL signature verification failed: %w", err)
	}
	return nil
}

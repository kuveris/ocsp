package source

import (
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
// It is safe for concurrent use.
type FileSource struct {
	crlPath        string
	reloadInterval time.Duration
	isURL          bool

	mu      sync.RWMutex
	revoked map[string]pkix.RevokedCertificate
	loaded  atomic.Bool

	lastModMu sync.RWMutex
	lastMod   time.Time
}

// NewFileSource creates a FileSource.
// crlPath: path to the CRL file (PEM or DER auto-detected) or an HTTP(S) URL
// reloadInterval: how often to check for file changes / re-download the URL
func NewFileSource(crlPath string, reloadInterval time.Duration) (*FileSource, error) {
	isURL := strings.HasPrefix(crlPath, "http://") || strings.HasPrefix(crlPath, "https://")
	s := &FileSource{crlPath: crlPath, reloadInterval: reloadInterval, isURL: isURL}
	if err := s.loadCRL(); err != nil {
		return nil, err
	}
	go s.reloadLoop()
	return s, nil
}

func (s *FileSource) Name() string { return "file" }

func (s *FileSource) Healthy() bool { return s.loaded.Load() }

func (s *FileSource) GetStatus(serial *big.Int, issuer *x509.Certificate) (*CertStatus, error) {
	_ = issuer
	if !s.loaded.Load() {
		return nil, ErrSourceUnhealthy
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
	for range t.C {
		if s.isURL {
			if err := s.loadFromURL(); err != nil {
				s.loaded.Store(false)
			}
			continue
		}
		info, err := os.Stat(s.crlPath)
		if err != nil {
			s.loaded.Store(false)
			continue
		}
		mod := info.ModTime()
		s.lastModMu.RLock()
		last := s.lastMod
		s.lastModMu.RUnlock()
		if !mod.After(last) {
			continue
		}
		if err := s.loadFromDisk(); err != nil {
			s.loaded.Store(false)
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
	defer resp.Body.Close()

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
	info, err := os.Stat(s.crlPath)
	if err != nil {
		return fmt.Errorf("ocsp-responder/source: %w", err)
	}
	b, err := os.ReadFile(s.crlPath)
	if err != nil {
		return fmt.Errorf("ocsp-responder/source: %w", err)
	}

	if err := s.parseCRLBytes(b); err != nil {
		return err
	}

	s.lastModMu.Lock()
	s.lastMod = info.ModTime()
	s.lastModMu.Unlock()

	return nil
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

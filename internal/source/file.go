package source

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// FileSource reads a CRL file (PEM or DER format) and uses it to determine certificate status.
// It automatically reloads the CRL when the file is modified.
// It is safe for concurrent use.
type FileSource struct {
	crlPath        string
	reloadInterval time.Duration

	mu      sync.RWMutex
	revoked map[string]pkix.RevokedCertificate
	loaded  atomic.Bool

	lastModMu sync.RWMutex
	lastMod   time.Time
}

// NewFileSource creates a FileSource.
// crlPath: path to the CRL file (PEM or DER auto-detected)
// reloadInterval: how often to check for file changes
func NewFileSource(crlPath string, reloadInterval time.Duration) (*FileSource, error) {
	s := &FileSource{crlPath: crlPath, reloadInterval: reloadInterval}
	if err := s.loadFromDisk(); err != nil {
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

func (s *FileSource) loadFromDisk() error {
	info, err := os.Stat(s.crlPath)
	if err != nil {
		return fmt.Errorf("ocsp-responder/source: %w", err)
	}
	b, err := os.ReadFile(s.crlPath)
	if err != nil {
		return fmt.Errorf("ocsp-responder/source: %w", err)
	}

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

	s.lastModMu.Lock()
	s.lastMod = info.ModTime()
	s.lastModMu.Unlock()

	s.loaded.Store(true)
	return nil
}


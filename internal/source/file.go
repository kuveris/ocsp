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
	"log/slog"
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

	mu         sync.RWMutex
	revoked    map[string]pkix.RevokedCertificate
	thisUpdate time.Time // under mu; when the CRL becomes valid (zero = unset)
	nextUpdate time.Time // under mu; zero means the CRL carries no expiry
	loaded     atomic.Bool

	// expiredLogged tracks whether the current expiry has already been logged,
	// so the reload loop reports the transition once rather than every tick.
	expiredLogged atomic.Bool

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

	// expiryGrace extends how long a CRL stays usable past its NextUpdate.
	// Zero means strict: the CRL is rejected the moment it expires.
	expiryGrace time.Duration

	logger *slog.Logger

	done chan struct{}
}

// FileSourceOption configures optional FileSource behaviour.
type FileSourceOption func(*FileSource)

// WithCRLExpiryGrace keeps a CRL usable for the given duration past its
// NextUpdate.
//
// The default is strict — an expired CRL is refused, so the responder answers
// `unknown` rather than serving revocation data the CA has already superseded.
// That is the correct default for a revocation service, but it means a CA that
// publishes late takes the responder down at the moment NextUpdate passes.
// Trading a short window of slightly-stale data against an outage is the
// operator's call, so it is opt-in rather than a built-in tolerance.
func WithCRLExpiryGrace(d time.Duration) FileSourceOption {
	return func(s *FileSource) { s.expiryGrace = d }
}

// WithLogger sets the logger used to report reload failures.
func WithLogger(l *slog.Logger) FileSourceOption {
	return func(s *FileSource) {
		if l != nil {
			s.logger = l
		}
	}
}

// NewFileSource creates a FileSource.
// crlPath: path to the CRL file (PEM or DER auto-detected) or an HTTP(S) URL
// reloadInterval: how often to check for file changes / re-download the URL
func NewFileSource(crlPath string, reloadInterval time.Duration, issuerCert *x509.Certificate, opts ...FileSourceOption) (*FileSource, error) {
	if issuerCert == nil {
		return nil, fmt.Errorf("ocsp-responder/source: issuer certificate is required")
	}
	isURL := strings.HasPrefix(crlPath, "http://") || strings.HasPrefix(crlPath, "https://")
	s := &FileSource{
		crlPath:        crlPath,
		reloadInterval: reloadInterval,
		issuerCert:     issuerCert,
		isURL:          isURL,
		logger:         slog.Default(),
		done:           make(chan struct{}),
	}
	for _, opt := range opts {
		opt(s)
	}
	if err := s.loadCRL(); err != nil {
		return nil, err
	}
	// An already-expired CRL is not a startup failure: it is a transient runtime
	// condition the source fails closed on (answering `unknown`) and recovers
	// from when the CA publishes. Making it fatal would turn a routine
	// publication delay into a crash loop, since restarting is the operator's
	// first instinct when /health goes 503. Log it now so the cause is visible.
	s.checkExpiry()
	go s.reloadLoop()
	return s, nil
}

// Stop stops the background CRL reload goroutine. It is safe to call once.
func (s *FileSource) Stop() {
	close(s.done)
}

func (s *FileSource) Name() string { return "file" }

func (s *FileSource) Healthy() bool { return s.loaded.Load() && s.crlUsable() }

// crlClockSkewAllowance tolerates a CRL whose ThisUpdate is slightly ahead of
// this host's clock — ordinary jitter between the CA and the responder — so a
// freshly published CRL is not rejected as not-yet-valid.
const crlClockSkewAllowance = 5 * time.Minute

// crlUsable reports whether the loaded CRL is within its validity window: not
// expired and not still in the future.
func (s *FileSource) crlUsable() bool {
	return !s.crlExpired() && !s.crlNotYetValid()
}

// crlNotYetValid reports whether the loaded CRL's ThisUpdate is meaningfully in
// the future — a post-dated CRL, or a host clock that is behind. Symmetric with
// crlExpired: the two together bound both ends of the validity window, and a
// CRL outside it is treated as unhealthy rather than served.
func (s *FileSource) crlNotYetValid() bool {
	s.mu.RLock()
	tu := s.thisUpdate
	s.mu.RUnlock()
	if tu.IsZero() {
		return false
	}
	return time.Now().Before(tu.Add(-crlClockSkewAllowance))
}

// crlExpired reports whether the loaded CRL is past its NextUpdate (plus any
// configured grace). It is evaluated live on every status lookup and health
// check rather than once at load: a CRL that is valid when read expires in
// place while the file on disk never changes, so a load-time-only check keeps
// serving superseded revocation data indefinitely — reporting `good` for a
// certificate revoked since the last publication.
func (s *FileSource) crlExpired() bool {
	s.mu.RLock()
	nu := s.nextUpdate
	s.mu.RUnlock()
	if nu.IsZero() {
		return false
	}
	return time.Now().After(nu.Add(s.expiryGrace))
}

func (s *FileSource) GetStatus(ctx context.Context, serial *big.Int, issuer *x509.Certificate) (*CertStatus, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !s.loaded.Load() {
		return nil, ErrSourceUnhealthy
	}
	// Fail closed on a CRL outside its validity window (expired or not yet
	// valid). Checked here, not only in the reload loop, so there is no window
	// between a CRL going out of validity and the next reload tick.
	if !s.crlUsable() {
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
	nextUpdate := s.nextUpdate
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
			SourceNextUpdate: nextUpdate,
		}, nil
	}

	return &CertStatus{Status: StatusGood, SourceNextUpdate: nextUpdate}, nil
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
					s.markUnhealthy(err)
				} else {
					s.checkExpiry()
				}
				continue
			}
			if err := s.reloadFromDiskIfChanged(); err != nil {
				s.markUnhealthy(err)
				continue
			}
			// The file may be unchanged but the loaded CRL expired in place.
			s.checkExpiry()
		}
	}
}

// log returns the configured logger, defaulting when a FileSource was built as
// a bare struct literal (as some tests do) without going through NewFileSource.
func (s *FileSource) log() *slog.Logger {
	if s.logger == nil {
		return slog.Default()
	}
	return s.logger
}

// checkExpiry logs the transition into and out of CRL expiry exactly once each
// way. Going unhealthy silently is the same class of problem this guards
// against: the responder degrades to `unknown` and an operator seeing /health
// flip to 503 has nothing to explain it.
func (s *FileSource) checkExpiry() {
	if !s.crlUsable() {
		if !s.expiredLogged.Swap(true) {
			s.mu.RLock()
			tu, nu := s.thisUpdate, s.nextUpdate
			s.mu.RUnlock()
			if s.crlNotYetValid() {
				s.log().Error("CRL is not yet valid; answering unknown until it takes effect",
					"path", s.crlPath, "this_update", tu.UTC().Format(time.RFC3339))
			} else {
				s.log().Error("CRL expired; answering unknown until a fresh CRL is published",
					"path", s.crlPath, "next_update", nu.UTC().Format(time.RFC3339), "grace", s.expiryGrace)
			}
		}
		return
	}
	if s.expiredLogged.Swap(false) {
		s.log().Info("CRL is within its validity window again", "path", s.crlPath)
	}
}

// markUnhealthy takes the source out of service and says why. The responder
// answers `unknown` from here on, which is correct but indistinguishable from
// a dozen other causes unless the reason is recorded — an operator seeing
// /health flip to 503 has nothing else to go on.
func (s *FileSource) markUnhealthy(err error) {
	wasHealthy := s.loaded.Swap(false)
	if wasHealthy {
		s.log().Error("CRL source is unhealthy; answering unknown", "path", s.crlPath, "err", err)
		return
	}
	// Already unhealthy — log at debug so a persistent failure does not flood.
	s.log().Debug("CRL source still unhealthy", "path", s.crlPath, "err", err)
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

	// Skip the re-parse only when the contents are unchanged *and* the source
	// is currently serving. parseCRLBytes is the only thing that sets loaded
	// back to true, so short-circuiting on the digest alone would make a
	// transient read failure permanent: the identical CRL returning to disk
	// would match lastHash, skip the parse, and leave the source unhealthy
	// until the process restarted.
	if unchanged && s.loaded.Load() {
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

	// NextUpdate is stored, not enforced here: expiry is a live property checked
	// on every lookup (see crlExpired), because a CRL valid at load can expire
	// in place while its bytes never change. NextUpdate is optional per RFC 5280;
	// a zero value means no expiry to enforce.
	s.mu.Lock()
	s.revoked = revoked
	s.thisUpdate = rl.ThisUpdate
	s.nextUpdate = rl.NextUpdate
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

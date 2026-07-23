package responder

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/kuveris/ocsp/internal/source"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"
)

type subjectPublicKeyInfo struct {
	Algorithm        asn1.RawValue
	SubjectPublicKey asn1.BitString
}

// MetricsRecorder is the optional interface for recording request metrics.
// Implementations must be safe for concurrent use.
type MetricsRecorder interface {
	RecordRequest(method, status string, durationSeconds float64)
	RecordSourceRequest(sourceName, result string)
	RecordCacheHit()
	RecordCacheMiss()
}

// Responder processes OCSP requests and returns signed responses.
// It wraps the Source with an in-memory cache.
type Responder struct {
	source  source.Source
	signer  signer
	cache   *cache
	metrics MetricsRecorder
	logger  *slog.Logger
}

type signer interface {
	IssuerCert() *x509.Certificate
	CreateResponse(serial *big.Int, status source.Status, revInfo *source.RevocationInfo, thisUpdate time.Time) ([]byte, error)
}

func NewResponder(src source.Source, sgn signer, cacheTTL time.Duration, maxEntries int, cacheEnabled bool, metrics MetricsRecorder, cacheEntriesGauge prometheus.Gauge, logger *slog.Logger) *Responder {
	if logger == nil {
		logger = slog.Default()
	}
	return &Responder{
		source: src,
		signer: sgn,
		cache: &cache{
			entries:      make(map[string]*cacheEntry),
			ttl:          cacheTTL,
			maxEntries:   maxEntries,
			enabled:      cacheEnabled,
			entriesGauge: cacheEntriesGauge,
		},
		metrics: metrics,
		logger:  logger,
	}
}

// Handle processes a raw DER-encoded OCSP request.
func (r *Responder) Handle(ctx context.Context, requestDER []byte) ([]byte, error) {
	start := time.Now()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("ocsp-responder/responder: %w", err)
	}

	req, err := ocsp.ParseRequest(requestDER)
	if err != nil {
		return nil, fmt.Errorf("ocsp-responder/responder: %w", err)
	}
	if err := validateIssuerBinding(req, r.signer.IssuerCert()); err != nil {
		return nil, fmt.Errorf("ocsp-responder/responder: %w", err)
	}
	serial := req.SerialNumber
	key := serial.String()

	if data, ok := r.cache.get(key); ok {
		r.logger.Info("ocsp", "serial", serialHex(serial), "status", "cached", "source", r.source.Name(), "cache_hit", true, "duration_ms", time.Since(start).Milliseconds())
		if r.metrics != nil {
			r.metrics.RecordCacheHit()
		}
		return data, nil
	}

	if r.metrics != nil {
		r.metrics.RecordCacheMiss()
	}

	status := source.StatusUnknown
	var revInfo *source.RevocationInfo
	cs, srcErr := r.source.GetStatus(ctx, serial, r.signer.IssuerCert())
	if srcErr == nil && cs != nil {
		status = cs.Status
		revInfo = cs.RevocationInfo
	}
	if srcErr != nil {
		status = source.StatusUnknown
		revInfo = nil
	}

	if r.metrics != nil {
		result := "ok"
		if srcErr != nil {
			result = "error"
		}
		r.metrics.RecordSourceRequest(r.source.Name(), result)
	}

	der, err := r.signer.CreateResponse(serial, status, revInfo, time.Now())
	if err != nil {
		return nil, fmt.Errorf("ocsp-responder/responder: %w", err)
	}

	r.cache.set(key, der)
	r.logger.Info("ocsp", "serial", serialHex(serial), "status", statusString(status), "source", r.source.Name(), "cache_hit", false, "duration_ms", time.Since(start).Milliseconds())
	return der, nil
}

func validateIssuerBinding(req *ocsp.Request, issuer *x509.Certificate) error {
	if req == nil || issuer == nil {
		return fmt.Errorf("invalid issuer binding context")
	}
	h := req.HashAlgorithm
	if !h.Available() {
		return fmt.Errorf("unsupported issuer hash algorithm")
	}

	nameHasher := h.New()
	nameHasher.Write(issuer.RawSubject)
	expectedNameHash := nameHasher.Sum(nil)
	if !equalBytes(req.IssuerNameHash, expectedNameHash) {
		return fmt.Errorf("issuer name hash mismatch")
	}

	var spki subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return fmt.Errorf("unable to parse issuer subject public key info")
	}
	spkiHasher := h.New()
	spkiHasher.Write(spki.SubjectPublicKey.Bytes)
	expectedSPKIHash := spkiHasher.Sum(nil)
	if !equalBytes(req.IssuerKeyHash, expectedSPKIHash) {
		return fmt.Errorf("issuer key hash mismatch")
	}

	return nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

func serialHex(n *big.Int) string {
	if n == nil {
		return ""
	}
	return hex.EncodeToString(n.Bytes())
}

func statusString(s source.Status) string {
	switch s {
	case source.StatusGood:
		return "good"
	case source.StatusRevoked:
		return "revoked"
	case source.StatusUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

type cache struct {
	mu           sync.RWMutex
	entries      map[string]*cacheEntry
	ttl          time.Duration
	maxEntries   int
	enabled      bool
	entriesGauge prometheus.Gauge // optional, nil = no gauge update
}

type cacheEntry struct {
	data      []byte
	expiresAt time.Time
}

func (c *cache) get(key string) ([]byte, bool) {
	if !c.enabled {
		return nil, false
	}
	c.mu.RLock()
	e := c.entries[key]
	c.mu.RUnlock()
	if e == nil {
		return nil, false
	}
	if time.Now().After(e.expiresAt) {
		c.mu.Lock()
		delete(c.entries, key)
		n := len(c.entries)
		c.mu.Unlock()
		if c.entriesGauge != nil {
			c.entriesGauge.Set(float64(n))
		}
		return nil, false
	}
	return e.data, true
}

func (c *cache) set(key string, data []byte) {
	if !c.enabled || c.maxEntries <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxEntries {
		for k := range c.entries {
			delete(c.entries, k)
			break
		}
	}
	c.entries[key] = &cacheEntry{data: data, expiresAt: time.Now().Add(c.ttl)}
	n := len(c.entries)
	if c.entriesGauge != nil {
		c.entriesGauge.Set(float64(n))
	}
}

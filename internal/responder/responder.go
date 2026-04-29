package responder

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/hartmann-it/ocsp-responder/internal/source"
	"golang.org/x/crypto/ocsp"
)

// Responder processes OCSP requests and returns signed responses.
// It wraps the Source with an in-memory cache.
type Responder struct {
	source source.Source
	signer signer
	cache  *cache
	logger *slog.Logger
}

type signer interface {
	IssuerCert() *x509.Certificate
	CreateResponse(serial *big.Int, status source.Status, revInfo *source.RevocationInfo, thisUpdate time.Time) ([]byte, error)
}

func NewResponder(src source.Source, sgn signer, cacheTTL time.Duration, maxEntries int, logger *slog.Logger) *Responder {
	if logger == nil {
		logger = slog.Default()
	}
	return &Responder{
		source: src,
		signer: sgn,
		cache: &cache{
			entries:    make(map[string]*cacheEntry),
			ttl:        cacheTTL,
			maxEntries: maxEntries,
		},
		logger: logger,
	}
}

// Handle processes a raw DER-encoded OCSP request.
func (r *Responder) Handle(ctx context.Context, requestDER []byte) ([]byte, error) {
	_ = ctx
	start := time.Now()
	req, err := ocsp.ParseRequest(requestDER)
	if err != nil {
		return nil, fmt.Errorf("ocsp-responder/responder: %w", err)
	}
	serial := req.SerialNumber
	key := serial.String()

	if data, ok := r.cache.get(key); ok {
		r.logger.Info("ocsp", "serial", serialHex(serial), "status", "cached", "source", r.source.Name(), "cache_hit", true, "duration_ms", time.Since(start).Milliseconds())
		return data, nil
	}

	status := source.StatusUnknown
	var revInfo *source.RevocationInfo
	cs, err := r.source.GetStatus(serial, r.signer.IssuerCert())
	if err == nil && cs != nil {
		status = cs.Status
		revInfo = cs.RevocationInfo
	}
	if err != nil {
		status = source.StatusUnknown
		revInfo = nil
	}

	der, err := r.signer.CreateResponse(serial, status, revInfo, time.Now())
	if err != nil {
		return nil, fmt.Errorf("ocsp-responder/responder: %w", err)
	}

	r.cache.set(key, der)
	r.logger.Info("ocsp", "serial", serialHex(serial), "status", statusString(status), "source", r.source.Name(), "cache_hit", false, "duration_ms", time.Since(start).Milliseconds())
	return der, nil
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
	mu         sync.RWMutex
	entries    map[string]*cacheEntry
	ttl        time.Duration
	maxEntries int
}

type cacheEntry struct {
	data      []byte
	expiresAt time.Time
}

func (c *cache) get(key string) ([]byte, bool) {
	c.mu.RLock()
	e := c.entries[key]
	c.mu.RUnlock()
	if e == nil {
		return nil, false
	}
	if time.Now().After(e.expiresAt) {
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return nil, false
	}
	return e.data, true
}

func (c *cache) set(key string, data []byte) {
	if c.maxEntries <= 0 {
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
}

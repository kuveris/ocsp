package responder

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/kuveris/ocsp/internal/source"
	"github.com/prometheus/client_golang/prometheus"
	xocsp "golang.org/x/crypto/ocsp"
)

type fakeMetrics struct {
	cacheHits   int
	cacheMisses int
	sourceReqs  int
	requests    int
}

func (f *fakeMetrics) RecordRequest(method, status string, durationSeconds float64) { f.requests++ }
func (f *fakeMetrics) RecordSourceRequest(sourceName, result string)                 { f.sourceReqs++ }
func (f *fakeMetrics) RecordCacheHit()                                               { f.cacheHits++ }
func (f *fakeMetrics) RecordCacheMiss()                                              { f.cacheMisses++ }

type testSigner struct {
	issuer *x509.Certificate

	key        *rsa.PrivateKey
	signerCert *x509.Certificate
	validity   time.Duration
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Issuer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	ocspKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ocspTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "OCSP"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	ocspDER, err := x509.CreateCertificate(rand.Reader, ocspTmpl, issuer, &ocspKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	ocspCert, err := x509.ParseCertificate(ocspDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	return &testSigner{issuer: issuer, key: ocspKey, signerCert: ocspCert, validity: time.Hour}
}

func (s *testSigner) IssuerCert() *x509.Certificate { return s.issuer }

func (s *testSigner) CreateResponse(serial *big.Int, st source.Status, revInfo *source.RevocationInfo, thisUpdate time.Time) ([]byte, error) {
	r := xocsp.Response{
		Status:       xocsp.Unknown,
		SerialNumber: serial,
		ThisUpdate:   thisUpdate,
		NextUpdate:   thisUpdate.Add(s.validity),
		IssuerHash:   crypto.SHA1,
		Certificate:  s.signerCert,
	}
	if st == source.StatusGood {
		r.Status = xocsp.Good
	}
	if st == source.StatusRevoked {
		r.Status = xocsp.Revoked
		if revInfo != nil {
			r.RevokedAt = revInfo.RevokedAt
			r.RevocationReason = revInfo.Reason
		}
	}
	der, err := xocsp.CreateResponse(s.issuer, s.signerCert, r, s.key)
	if err != nil {
		return nil, err
	}
	return der, nil
}

type countingSource struct {
	inner source.Source
	count int
}

func (c *countingSource) GetStatus(ctx context.Context, serial *big.Int, issuer *x509.Certificate) (*source.CertStatus, error) {
	c.count++
	return c.inner.GetStatus(ctx, serial, issuer)
}
func (c *countingSource) Name() string  { return c.inner.Name() }
func (c *countingSource) Healthy() bool { return c.inner.Healthy() }

func makeRequest(t *testing.T, issuer *x509.Certificate, serial *big.Int) []byte {
	t.Helper()
	certTmpl := &x509.Certificate{SerialNumber: serial}
	req, err := xocsp.CreateRequest(certTmpl, issuer, nil)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	return req
}

func parseResp(t *testing.T, issuer *x509.Certificate, der []byte) *xocsp.Response {
	t.Helper()
	resp, err := xocsp.ParseResponseForCert(der, nil, issuer)
	if err != nil {
		t.Fatalf("ParseResponseForCert: %v", err)
	}
	return resp
}

func TestHandle_Good(t *testing.T) {
	sgn := newTestSigner(t)
	src, _ := source.NewStaticSource("good")
	r := NewResponder(src, sgn, time.Minute, 100, true, nil, nil, nil)
	der, err := r.Handle(context.Background(), makeRequest(t, sgn.IssuerCert(), big.NewInt(99)))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	resp := parseResp(t, sgn.IssuerCert(), der)
	if resp.Status != xocsp.Good {
		t.Fatalf("expected good, got %d", resp.Status)
	}
}

func TestHandle_Revoked(t *testing.T) {
	sgn := newTestSigner(t)
	src, _ := source.NewStaticSource("revoked")
	r := NewResponder(src, sgn, time.Minute, 100, true, nil, nil, nil)
	der, err := r.Handle(context.Background(), makeRequest(t, sgn.IssuerCert(), big.NewInt(42)))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	resp := parseResp(t, sgn.IssuerCert(), der)
	if resp.Status != xocsp.Revoked {
		t.Fatalf("expected revoked, got %d", resp.Status)
	}
}

func TestHandle_Unknown(t *testing.T) {
	sgn := newTestSigner(t)
	src, _ := source.NewStaticSource("unknown")
	r := NewResponder(src, sgn, time.Minute, 100, true, nil, nil, nil)
	der, err := r.Handle(context.Background(), makeRequest(t, sgn.IssuerCert(), big.NewInt(7)))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	resp := parseResp(t, sgn.IssuerCert(), der)
	if resp.Status != xocsp.Unknown {
		t.Fatalf("expected unknown, got %d", resp.Status)
	}
}

func TestHandle_MalformedInput(t *testing.T) {
	sgn := newTestSigner(t)
	src, _ := source.NewStaticSource("good")
	r := NewResponder(src, sgn, time.Minute, 100, true, nil, nil, nil)
	if _, err := r.Handle(context.Background(), []byte("nope")); err == nil {
		t.Fatalf("expected error")
	}
}

func TestHandle_CacheHit(t *testing.T) {
	sgn := newTestSigner(t)
	inner, _ := source.NewStaticSource("good")
	src := &countingSource{inner: inner}
	r := NewResponder(src, sgn, time.Minute, 100, true, nil, nil, nil)
	req := makeRequest(t, sgn.IssuerCert(), big.NewInt(99))
	if _, err := r.Handle(context.Background(), req); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if _, err := r.Handle(context.Background(), req); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if src.count != 1 {
		t.Fatalf("expected 1 source call, got %d", src.count)
	}
}

type errSource struct{}

func (e *errSource) GetStatus(ctx context.Context, serial *big.Int, issuer *x509.Certificate) (*source.CertStatus, error) {
	_ = ctx
	return nil, fmt.Errorf("boom")
}
func (e *errSource) Name() string  { return "err" }
func (e *errSource) Healthy() bool { return false }

func TestHandle_SourceError(t *testing.T) {
	sgn := newTestSigner(t)
	r := NewResponder(&errSource{}, sgn, time.Minute, 100, true, nil, nil, nil)
	der, err := r.Handle(context.Background(), makeRequest(t, sgn.IssuerCert(), big.NewInt(5)))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	resp := parseResp(t, sgn.IssuerCert(), der)
	if resp.Status != xocsp.Unknown {
		t.Fatalf("expected unknown, got %d", resp.Status)
	}
}

func TestHandle_SignatureValid(t *testing.T) {
	sgn := newTestSigner(t)
	src, _ := source.NewStaticSource("good")
	r := NewResponder(src, sgn, time.Minute, 100, true, nil, nil, nil)
	der, err := r.Handle(context.Background(), makeRequest(t, sgn.IssuerCert(), big.NewInt(123)))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if _, err := xocsp.ParseResponseForCert(der, nil, sgn.IssuerCert()); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestHandle_RejectsMismatchedIssuerBinding(t *testing.T) {
	sgn := newTestSigner(t)
	src, _ := source.NewStaticSource("good")
	r := NewResponder(src, sgn, time.Minute, 100, true, nil, nil, nil)

	otherSigner := newTestSigner(t)
	request := makeRequest(t, otherSigner.IssuerCert(), big.NewInt(123))

	if _, err := r.Handle(context.Background(), request); err == nil {
		t.Fatalf("expected issuer-binding validation error")
	}
}

func TestHandle_ContextCanceled(t *testing.T) {
	sgn := newTestSigner(t)
	src, _ := source.NewStaticSource("good")
	r := NewResponder(src, sgn, time.Minute, 100, true, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := r.Handle(ctx, makeRequest(t, sgn.IssuerCert(), big.NewInt(1))); err == nil {
		t.Fatalf("expected context cancellation error")
	}
}

func TestCache_Get_Disabled(t *testing.T) {
	c := &cache{
		entries:    make(map[string]*cacheEntry),
		ttl:        time.Minute,
		maxEntries: 10,
		enabled:    false,
	}
	// Manually insert an entry to verify get ignores it when disabled.
	c.entries["key"] = &cacheEntry{data: []byte("data"), expiresAt: time.Now().Add(time.Minute)}
	if _, ok := c.get("key"); ok {
		t.Fatal("expected cache miss when cache is disabled")
	}
}

func TestCache_Get_ExpiredEntry(t *testing.T) {
	c := &cache{
		entries:    make(map[string]*cacheEntry),
		ttl:        time.Millisecond,
		maxEntries: 10,
		enabled:    true,
	}
	c.set("key", []byte("data"))
	time.Sleep(5 * time.Millisecond)
	if _, ok := c.get("key"); ok {
		t.Fatal("expected cache miss for expired entry")
	}
	// Entry must have been deleted.
	if len(c.entries) != 0 {
		t.Fatalf("expected empty cache after expiry, got %d entries", len(c.entries))
	}
}

func TestCache_Set_MaxEntriesZero(t *testing.T) {
	c := &cache{
		entries:    make(map[string]*cacheEntry),
		ttl:        time.Minute,
		maxEntries: 0,
		enabled:    true,
	}
	c.set("key", []byte("data"))
	if len(c.entries) != 0 {
		t.Fatal("expected no entry when maxEntries=0")
	}
}

func TestCache_Set_Eviction(t *testing.T) {
	c := &cache{
		entries:    make(map[string]*cacheEntry),
		ttl:        time.Minute,
		maxEntries: 2,
		enabled:    true,
	}
	c.set("a", []byte("1"))
	c.set("b", []byte("2"))
	c.set("c", []byte("3")) // should evict one entry
	if len(c.entries) > 2 {
		t.Fatalf("expected at most 2 entries after eviction, got %d", len(c.entries))
	}
}

func TestEqualBytes_UnequalLength(t *testing.T) {
	if equalBytes([]byte{1, 2, 3}, []byte{1, 2}) {
		t.Fatal("expected false for slices of different length")
	}
}

func TestSerialHex_Nil(t *testing.T) {
	if got := serialHex(nil); got != "" {
		t.Fatalf("expected empty string for nil, got %q", got)
	}
}

func TestStatusString_Default(t *testing.T) {
	if got := statusString(source.Status(99)); got != "unknown" {
		t.Fatalf("expected 'unknown' for invalid status, got %q", got)
	}
}

func TestValidateIssuerBinding_NilRequest(t *testing.T) {
	sgn := newTestSigner(t)
	if err := validateIssuerBinding(nil, sgn.IssuerCert()); err == nil {
		t.Fatal("expected error for nil request")
	}
}

// failingSigner is a Signer stub whose CreateResponse always returns an error.
type failingSigner struct{ issuer *x509.Certificate }

func (f *failingSigner) IssuerCert() *x509.Certificate { return f.issuer }
func (f *failingSigner) CreateResponse(_ *big.Int, _ source.Status, _ *source.RevocationInfo, _ time.Time) ([]byte, error) {
	return nil, fmt.Errorf("signer error")
}

func TestValidateIssuerBinding_HashUnavailable(t *testing.T) {
	sgn := newTestSigner(t)
	issuer := sgn.IssuerCert()

	req := &xocsp.Request{
		HashAlgorithm:  crypto.Hash(255), // unregistered hash → !h.Available()
		IssuerNameHash: []byte("any"),
		IssuerKeyHash:  []byte("any"),
		SerialNumber:   big.NewInt(1),
	}
	if err := validateIssuerBinding(req, issuer); err == nil {
		t.Fatal("expected error for unavailable hash algorithm")
	}
}

func TestValidateIssuerBinding_NameHashMismatch(t *testing.T) {
	sgn := newTestSigner(t)
	issuer := sgn.IssuerCert()

	req := &xocsp.Request{
		HashAlgorithm:  crypto.SHA1,
		IssuerNameHash: make([]byte, 20), // 20 zeros — won't match SHA1(issuer.RawSubject)
		IssuerKeyHash:  make([]byte, 20),
		SerialNumber:   big.NewInt(1),
	}
	if err := validateIssuerBinding(req, issuer); err == nil {
		t.Fatal("expected name hash mismatch error")
	}
}

func TestValidateIssuerBinding_ASN1Error(t *testing.T) {
	sgn := newTestSigner(t)
	issuer := sgn.IssuerCert()

	// Compute correct name hash so we get past the name-hash check.
	nameHasher := crypto.SHA1.New()
	nameHasher.Write(issuer.RawSubject)
	correctNameHash := nameHasher.Sum(nil)

	// Certificate with garbage SPKI so asn1.Unmarshal fails.
	badCert := &x509.Certificate{
		RawSubject:              issuer.RawSubject,
		RawSubjectPublicKeyInfo: []byte("not valid asn1 garbage"),
	}

	req := &xocsp.Request{
		HashAlgorithm:  crypto.SHA1,
		IssuerNameHash: correctNameHash,
		IssuerKeyHash:  make([]byte, 20),
		SerialNumber:   big.NewInt(1),
	}
	if err := validateIssuerBinding(req, badCert); err == nil {
		t.Fatal("expected ASN1 parse error")
	}
}

func TestHandle_MetricsSourceError(t *testing.T) {
	sgn := newTestSigner(t)
	m := &fakeMetrics{}
	r := NewResponder(&errSource{}, sgn, time.Minute, 100, true, m, nil, nil)
	req := makeRequest(t, sgn.IssuerCert(), big.NewInt(11))

	// Source returns error → srcErr != nil branch in metrics block fires
	if _, err := r.Handle(context.Background(), req); err != nil {
		t.Fatalf("Handle should not return error when source fails (returns unknown): %v", err)
	}
	if m.sourceReqs != 1 {
		t.Fatalf("expected 1 source request recorded, got %d", m.sourceReqs)
	}
}

func TestHandle_SignerError(t *testing.T) {
	sgn := newTestSigner(t)
	src, _ := source.NewStaticSource("good")
	fs := &failingSigner{issuer: sgn.IssuerCert()}
	r := NewResponder(src, fs, time.Minute, 100, true, nil, nil, nil)
	req := makeRequest(t, sgn.IssuerCert(), big.NewInt(22))

	if _, err := r.Handle(context.Background(), req); err == nil {
		t.Fatal("expected error when signer.CreateResponse fails")
	}
}

func TestCache_Get_GaugeUpdate(t *testing.T) {
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "test_cache_get_gauge",
		Help: "test",
	})
	c := &cache{
		entries:      make(map[string]*cacheEntry),
		ttl:          time.Millisecond,
		maxEntries:   10,
		enabled:      true,
		entriesGauge: gauge,
	}
	c.set("k", []byte("v"))
	time.Sleep(5 * time.Millisecond) // let entry expire
	// get should delete the expired entry and update the gauge
	if _, ok := c.get("k"); ok {
		t.Fatal("expected cache miss for expired entry")
	}
}

func TestHandle_MetricsRecorded(t *testing.T) {
	sgn := newTestSigner(t)
	src, _ := source.NewStaticSource("good")
	m := &fakeMetrics{}
	r := NewResponder(src, sgn, time.Minute, 100, true, m, nil, nil)
	req := makeRequest(t, sgn.IssuerCert(), big.NewInt(77))

	// First call: cache miss + source request recorded
	if _, err := r.Handle(context.Background(), req); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if m.cacheMisses != 1 {
		t.Fatalf("expected 1 cache miss, got %d", m.cacheMisses)
	}
	if m.sourceReqs != 1 {
		t.Fatalf("expected 1 source request, got %d", m.sourceReqs)
	}

	// Second call: cache hit recorded
	if _, err := r.Handle(context.Background(), req); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if m.cacheHits != 1 {
		t.Fatalf("expected 1 cache hit, got %d", m.cacheHits)
	}
}

func TestValidateIssuerBinding_KeyHashMismatch(t *testing.T) {
	sgn := newTestSigner(t)
	issuer := sgn.IssuerCert()

	// Compute the correct name hash so the name-hash check passes.
	h := crypto.SHA1
	nameHasher := h.New()
	nameHasher.Write(issuer.RawSubject)
	correctNameHash := nameHasher.Sum(nil)

	// Use a zeroed key hash of the right length — it won't match the real SPKI hash.
	wrongKeyHash := make([]byte, 20)

	req := &xocsp.Request{
		HashAlgorithm:  crypto.SHA1,
		IssuerNameHash: correctNameHash,
		IssuerKeyHash:  wrongKeyHash,
		SerialNumber:   big.NewInt(1),
	}
	if err := validateIssuerBinding(req, issuer); err == nil {
		t.Fatal("expected key hash mismatch error")
	}
}

func TestCache_Set_GaugeUpdate(t *testing.T) {
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "test_cache_set_gauge",
		Help: "test",
	})
	c := &cache{
		entries:      make(map[string]*cacheEntry),
		ttl:          time.Minute,
		maxEntries:   10,
		enabled:      true,
		entriesGauge: gauge,
	}
	c.set("k", []byte("v"))
	// gauge should have been updated — no panic is the main check
}

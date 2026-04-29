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

	"github.com/hartmann-it/ocsp-responder/internal/source"
	xocsp "golang.org/x/crypto/ocsp"
)

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

func (c *countingSource) GetStatus(serial *big.Int, issuer *x509.Certificate) (*source.CertStatus, error) {
	c.count++
	return c.inner.GetStatus(serial, issuer)
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
	r := NewResponder(src, sgn, time.Minute, 100, nil)
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
	r := NewResponder(src, sgn, time.Minute, 100, nil)
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
	r := NewResponder(src, sgn, time.Minute, 100, nil)
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
	r := NewResponder(src, sgn, time.Minute, 100, nil)
	if _, err := r.Handle(context.Background(), []byte("nope")); err == nil {
		t.Fatalf("expected error")
	}
}

func TestHandle_CacheHit(t *testing.T) {
	sgn := newTestSigner(t)
	inner, _ := source.NewStaticSource("good")
	src := &countingSource{inner: inner}
	r := NewResponder(src, sgn, time.Minute, 100, nil)
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

func (e *errSource) GetStatus(serial *big.Int, issuer *x509.Certificate) (*source.CertStatus, error) {
	return nil, fmt.Errorf("boom")
}
func (e *errSource) Name() string  { return "err" }
func (e *errSource) Healthy() bool { return false }

func TestHandle_SourceError(t *testing.T) {
	sgn := newTestSigner(t)
	r := NewResponder(&errSource{}, sgn, time.Minute, 100, nil)
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
	r := NewResponder(src, sgn, time.Minute, 100, nil)
	der, err := r.Handle(context.Background(), makeRequest(t, sgn.IssuerCert(), big.NewInt(123)))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if _, err := xocsp.ParseResponseForCert(der, nil, sgn.IssuerCert()); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

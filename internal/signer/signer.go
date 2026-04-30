package signer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"time"

	"github.com/hartmann-it/ocsp-responder/internal/source"
	"github.com/prometheus/client_golang/prometheus"
	xocsp "golang.org/x/crypto/ocsp"
)

// ExpiryStatus describes how close the signer certificate is to expiry.
type ExpiryStatus int

const (
	ExpiryOK       ExpiryStatus = iota // > 30 days remaining
	ExpiryWarning                      // 8–30 days remaining
	ExpiryCritical                     // < 8 days remaining
	ExpiryExpired                      // already expired
)

// Signer holds the OCSP delegated signing certificate and private key.
type Signer struct {
	cert       *x509.Certificate
	key        crypto.Signer
	issuerCert *x509.Certificate
	validity   time.Duration
}

// NewSigner loads and validates the OCSP signing cert, key, and issuer cert.
func NewSigner(certFile, keyFile, issuerCertFile string, validity time.Duration) (*Signer, error) {
	cert, err := loadCert(certFile)
	if err != nil {
		return nil, err
	}
	key, err := loadKey(keyFile)
	if err != nil {
		return nil, err
	}
	issuer, err := loadCert(issuerCertFile)
	if err != nil {
		return nil, err
	}

	hasOCSPEKU := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageOCSPSigning {
			hasOCSPEKU = true
			break
		}
	}
	if !hasOCSPEKU {
		return nil, fmt.Errorf("ocsp-responder/signer: missing extKeyUsage OCSPSigning")
	}

	if err := verifyKeyMatches(cert, key); err != nil {
		return nil, err
	}
	if err := verifySignerTrust(cert, issuer); err != nil {
		return nil, err
	}

	if time.Until(cert.NotAfter) < 30*24*time.Hour {
		slog.Warn("OCSP signer certificate expires soon", "not_after", cert.NotAfter)
	}

	return &Signer{cert: cert, key: key, issuerCert: issuer, validity: validity}, nil
}

func verifySignerTrust(cert, issuer *x509.Certificate) error {
	if cert == nil || issuer == nil {
		return fmt.Errorf("ocsp-responder/signer: signer and issuer certificates are required")
	}
	if !issuer.IsCA {
		return fmt.Errorf("ocsp-responder/signer: issuer certificate is not a CA")
	}
	if issuer.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("ocsp-responder/signer: issuer certificate cannot sign certificates")
	}
	if cert.CheckSignatureFrom(issuer) != nil {
		return fmt.Errorf("ocsp-responder/signer: signer certificate is not signed by issuer")
	}
	return nil
}

func (s *Signer) CreateResponse(serial *big.Int, status source.Status, revInfo *source.RevocationInfo, thisUpdate time.Time) ([]byte, error) {
	var ocspStatus int
	var revokedAt time.Time
	reason := 0

	switch status {
	case source.StatusGood:
		ocspStatus = xocsp.Good
	case source.StatusRevoked:
		ocspStatus = xocsp.Revoked
		if revInfo != nil {
			revokedAt = revInfo.RevokedAt
			reason = revInfo.Reason
		}
	case source.StatusUnknown:
		ocspStatus = xocsp.Unknown
	default:
		return nil, fmt.Errorf("ocsp-responder/signer: unsupported status %v", status)
	}

	template := xocsp.Response{
		Status:           ocspStatus,
		SerialNumber:     serial,
		ThisUpdate:       thisUpdate,
		NextUpdate:       thisUpdate.Add(s.validity),
		IssuerHash:       crypto.SHA1,
		Certificate:      s.cert,
		RevokedAt:        revokedAt,
		RevocationReason: reason,
	}

	der, err := xocsp.CreateResponse(s.issuerCert, s.cert, template, s.key)
	if err != nil {
		return nil, fmt.Errorf("ocsp-responder/signer: %w", err)
	}
	return der, nil
}

func (s *Signer) IssuerCert() *x509.Certificate { return s.issuerCert }

func (s *Signer) Valid() bool {
	now := time.Now()
	return now.After(s.cert.NotBefore) && now.Before(s.cert.NotAfter)
}

// DaysUntilExpiry returns the number of complete days until the signing certificate expires.
// Returns a negative number if the certificate is already expired.
// The value is truncated (floor), so 7 days and 23 hours returns 7.
func (s *Signer) DaysUntilExpiry() int {
	return int(time.Until(s.cert.NotAfter).Hours() / 24)
}

// ExpiryStatus returns the current expiry status of the signing certificate.
func (s *Signer) GetExpiryStatus() ExpiryStatus {
	days := s.DaysUntilExpiry()
	switch {
	case days < 0:
		return ExpiryExpired
	case days < 8:
		return ExpiryCritical
	case days < 30:
		return ExpiryWarning
	default:
		return ExpiryOK
	}
}

// ExpiryStatusString returns a string representation of the expiry status.
func ExpiryStatusString(es ExpiryStatus) string {
	switch es {
	case ExpiryOK:
		return "ok"
	case ExpiryWarning:
		return "warning"
	case ExpiryCritical:
		return "critical"
	case ExpiryExpired:
		return "expired"
	default:
		return "unknown"
	}
}

// StartExpiryMonitor starts a goroutine that logs signer certificate expiry status every 24 hours.
// It stops when ctx is cancelled. daysGauge is optional — if non-nil it is updated on each tick
// and immediately on start.
func (s *Signer) StartExpiryMonitor(ctx context.Context, logger *slog.Logger, daysGauge prometheus.Gauge) {
	if logger == nil {
		logger = slog.Default()
	}
	go func() {
		// Set gauge immediately on start.
		if daysGauge != nil {
			daysGauge.Set(float64(s.DaysUntilExpiry()))
		}

		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				days := s.DaysUntilExpiry()
				if daysGauge != nil {
					daysGauge.Set(float64(days))
				}
				switch s.GetExpiryStatus() {
				case ExpiryWarning:
					logger.Warn("OCSP signer certificate expires soon", "days", days)
				case ExpiryCritical:
					logger.Error("OCSP signer certificate expires very soon", "days", days)
				case ExpiryExpired:
					logger.Error("OCSP signer certificate is EXPIRED")
				}
			}
		}
	}()
}

func loadCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ocsp-responder/signer: %w", err)
	}
	if blk, _ := pem.Decode(b); blk != nil {
		b = blk.Bytes
	}
	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, fmt.Errorf("ocsp-responder/signer: %w", err)
	}
	return cert, nil
}

func loadKey(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ocsp-responder/signer: %w", err)
	}
	if blk, _ := pem.Decode(b); blk != nil {
		b = blk.Bytes
	}
	key, err := x509.ParsePKCS8PrivateKey(b)
	if err != nil {
		key2, err2 := x509.ParsePKCS1PrivateKey(b)
		if err2 == nil {
			return key2, nil
		}
		return nil, fmt.Errorf("ocsp-responder/signer: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("ocsp-responder/signer: key does not implement crypto.Signer")
	}
	return signer, nil
}

func verifyKeyMatches(cert *x509.Certificate, key crypto.PrivateKey) error {
	pub := cert.PublicKey
	switch pk := pub.(type) {
	case *rsa.PublicKey:
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("ocsp-responder/signer: key type mismatch")
		}
		if pk.N.Cmp(rsaKey.N) != 0 || pk.E != rsaKey.E {
			return fmt.Errorf("ocsp-responder/signer: key does not match certificate")
		}
		return nil
	case *ecdsa.PublicKey:
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("ocsp-responder/signer: key type mismatch")
		}
		if pk.X.Cmp(ecdsaKey.X) != 0 || pk.Y.Cmp(ecdsaKey.Y) != 0 {
			return fmt.Errorf("ocsp-responder/signer: key does not match certificate")
		}
		return nil
	default:
		return fmt.Errorf("ocsp-responder/signer: unsupported public key type")
	}
}

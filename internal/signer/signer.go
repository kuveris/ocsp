package signer

import (
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

	cfocsp "github.com/cloudflare/cfssl/ocsp"
	"github.com/hartmann-it/ocsp-responder/internal/source"
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

	if time.Until(cert.NotAfter) < 30*24*time.Hour {
		slog.Warn("OCSP signer certificate expires soon", "not_after", cert.NotAfter)
	}

	return &Signer{cert: cert, key: key, issuerCert: issuer, validity: validity}, nil
}

func (s *Signer) CreateResponse(serial *big.Int, status source.Status, revInfo *source.RevocationInfo, thisUpdate time.Time) ([]byte, error) {
	ocspStatus := "unknown"
	var revokedAt time.Time
	reason := 0

	switch status {
	case source.StatusGood:
		ocspStatus = "good"
	case source.StatusRevoked:
		ocspStatus = "revoked"
		if revInfo != nil {
			revokedAt = revInfo.RevokedAt
			reason = revInfo.Reason
		}
	case source.StatusUnknown:
		ocspStatus = "unknown"
	default:
		return nil, fmt.Errorf("ocsp-responder/signer: unsupported status %v", status)
	}

	cfSigner, err := cfocsp.NewSigner(s.issuerCert, s.cert, s.key, s.validity)
	if err != nil {
		return nil, fmt.Errorf("ocsp-responder/signer: %w", err)
	}

	req := cfocsp.SignRequest{
		Certificate: s.issuerCert,
		Status:      ocspStatus,
		Reason:      reason,
		RevokedAt:   revokedAt,
		ThisUpdate:  &thisUpdate,
	}

	nextUpdate := thisUpdate.Add(s.validity)
	req.NextUpdate = &nextUpdate

	der, err := cfSigner.Sign(req)
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

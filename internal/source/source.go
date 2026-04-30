package source

import (
	"context"
	"crypto/x509"
	"errors"
	"math/big"
	"time"
)

// Status represents the revocation status of a certificate.
type Status int

const (
	StatusGood Status = iota
	StatusRevoked
	StatusUnknown
)

// RevocationInfo contains details about a revoked certificate.
type RevocationInfo struct {
	RevokedAt time.Time
	Reason    int
}

// CertStatus is the result of a status lookup.
type CertStatus struct {
	Status         Status
	RevocationInfo *RevocationInfo
}

// Source is the pluggable interface for certificate status backends.
// Implementations must be safe for concurrent use.
type Source interface {
	GetStatus(ctx context.Context, serial *big.Int, issuer *x509.Certificate) (*CertStatus, error)
	Name() string
	Healthy() bool
}

var (
	ErrSourceUnhealthy = errors.New("ocsp-responder/source: source is not healthy")
	ErrInvalidCRL      = errors.New("ocsp-responder/source: invalid or unparseable CRL")
)

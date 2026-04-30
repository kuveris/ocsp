package source

import (
	"context"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"
)

// StaticSource always returns a fixed status. Used for testing and development.
type StaticSource struct {
	status Status
}

// NewStaticSource creates a StaticSource.
// statusStr must be "good", "revoked", or "unknown".
func NewStaticSource(statusStr string) (*StaticSource, error) {
	var st Status
	switch statusStr {
	case "good":
		st = StatusGood
	case "revoked":
		st = StatusRevoked
	case "unknown":
		st = StatusUnknown
	default:
		return nil, fmt.Errorf("ocsp-responder/source: invalid static status %q", statusStr)
	}
	return &StaticSource{status: st}, nil
}

func (s *StaticSource) GetStatus(ctx context.Context, serial *big.Int, issuer *x509.Certificate) (*CertStatus, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	_ = serial
	_ = issuer

	cs := &CertStatus{Status: s.status}
	if s.status == StatusRevoked {
		cs.RevocationInfo = &RevocationInfo{RevokedAt: time.Now(), Reason: 0}
	}
	return cs, nil
}

func (s *StaticSource) Name() string {
	return "static"
}

func (s *StaticSource) Healthy() bool {
	return true
}

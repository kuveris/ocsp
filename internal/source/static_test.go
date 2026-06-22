package source

import (
	"context"
	"math/big"
	"testing"
)

func TestStaticSource_Good(t *testing.T) {
	s, err := NewStaticSource("good")
	if err != nil {
		t.Fatalf("NewStaticSource: %v", err)
	}
	cs, err := s.GetStatus(context.Background(), big.NewInt(1), nil)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if cs.Status != StatusGood {
		t.Fatalf("expected good, got %v", cs.Status)
	}
	if cs.RevocationInfo != nil {
		t.Fatal("expected no RevocationInfo for good status")
	}
}

func TestStaticSource_Revoked(t *testing.T) {
	s, err := NewStaticSource("revoked")
	if err != nil {
		t.Fatalf("NewStaticSource: %v", err)
	}
	cs, err := s.GetStatus(context.Background(), big.NewInt(2), nil)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if cs.Status != StatusRevoked {
		t.Fatalf("expected revoked, got %v", cs.Status)
	}
	if cs.RevocationInfo == nil {
		t.Fatal("expected RevocationInfo for revoked status")
	}
	if cs.RevocationInfo.RevokedAt.IsZero() {
		t.Fatal("expected non-zero RevokedAt")
	}
}

func TestStaticSource_Unknown(t *testing.T) {
	s, err := NewStaticSource("unknown")
	if err != nil {
		t.Fatalf("NewStaticSource: %v", err)
	}
	cs, err := s.GetStatus(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if cs.Status != StatusUnknown {
		t.Fatalf("expected unknown, got %v", cs.Status)
	}
}

func TestStaticSource_InvalidStatus(t *testing.T) {
	if _, err := NewStaticSource("invalid"); err == nil {
		t.Fatal("expected error for invalid status string")
	}
}

func TestStaticSource_Name(t *testing.T) {
	s, _ := NewStaticSource("good")
	if got := s.Name(); got != "static" {
		t.Fatalf("expected 'static', got %q", got)
	}
}

func TestStaticSource_Healthy(t *testing.T) {
	s, _ := NewStaticSource("good")
	if !s.Healthy() {
		t.Fatal("expected Healthy() = true")
	}
}

func TestStaticSource_ContextCanceled(t *testing.T) {
	s, _ := NewStaticSource("good")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.GetStatus(ctx, big.NewInt(1), nil); err == nil {
		t.Fatal("expected error on cancelled context")
	}
}

package server

import (
	"testing"
)

func TestNewMetrics_Smoke(t *testing.T) {
	m := NewMetrics()
	if m == nil {
		t.Fatal("expected non-nil Metrics")
	}

	// Exercise every Record* method to ensure no nil-pointer panics.
	m.RecordRequest("POST", "good", 0.005)
	m.RecordRequest("GET", "revoked", 0.002)
	m.RecordSourceRequest("file", "hit")
	m.RecordSourceLatency("file", 0.001)
	m.RecordSourceRetry("file")
	m.RecordSourceError("file", "timeout")
	m.RecordCacheHit()
	m.RecordCacheMiss()
}

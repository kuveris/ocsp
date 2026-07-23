package server

import (
	"runtime"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestNewMetrics_Smoke(t *testing.T) {
	m, _ := NewMetrics()
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

// TestNewMetrics_IsIndependentPerInstance covers two things the global default
// registry made impossible: constructing Metrics twice in one process, and
// running this package's tests with -count>1 (which is how you confirm a flaky
// test is actually fixed).
func TestNewMetrics_IsIndependentPerInstance(t *testing.T) {
	m1, reg1 := NewMetrics()
	m2, reg2 := NewMetrics()

	if m1 == nil || m2 == nil || reg1 == nil || reg2 == nil {
		t.Fatal("expected two usable Metrics/registry pairs")
	}
	if reg1 == reg2 {
		t.Fatal("each Metrics must own its registry; a shared one is what made a second call panic")
	}

	// Recording on one must not appear in the other.
	m1.RecordCacheHit()
	if got := countMetric(t, reg1, "ocsp_cache_hits_total"); got != 1 {
		t.Fatalf("reg1 cache hits = %v, want 1", got)
	}
	if got := countMetric(t, reg2, "ocsp_cache_hits_total"); got != 0 {
		t.Fatalf("reg2 cache hits = %v, want 0 — registries are not isolated", got)
	}
}

// TestNewMetrics_ExposesOCSPAndRuntimeMetrics guards the observability
// regression that moving off the default registry would otherwise cause: the
// go_* and process_* collectors come for free from the default registry and
// would have been silently lost.
func TestNewMetrics_ExposesOCSPAndRuntimeMetrics(t *testing.T) {
	m, reg := NewMetrics()

	// Vec metrics emit no family until a label combination is observed, so
	// exercise every recorder first. This also checks the labels actually work
	// rather than only that the collectors were constructed.
	m.RecordRequest("post", "good", 0.01)
	m.RecordSourceRequest("file", "ok")
	m.RecordSourceLatency("file", 0.02)
	m.RecordSourceRetry("file")
	m.RecordSourceError("file", "transport_or_upstream")
	m.RecordCacheHit()
	m.RecordCacheMiss()
	m.SignerDaysLeft.Set(42)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	names := map[string]bool{}
	for _, f := range families {
		names[f.GetName()] = true
	}

	for _, want := range []string{
		"ocsp_requests_total",
		"ocsp_request_duration_seconds",
		"ocsp_cache_entries",
		"ocsp_cache_hits_total",
		"ocsp_cache_misses_total",
		"ocsp_signer_days_until_expiry",
		"ocsp_source_requests_total",
		"ocsp_source_request_duration_seconds",
		"ocsp_source_retries_total",
		"ocsp_source_errors_total",
	} {
		if !names[want] {
			t.Errorf("missing OCSP metric %q", want)
		}
	}

	var hasGo, hasProcess bool
	for n := range names {
		if strings.HasPrefix(n, "go_") {
			hasGo = true
		}
		if strings.HasPrefix(n, "process_") {
			hasProcess = true
		}
	}
	if !hasGo {
		t.Error("expected go_* runtime collectors to be registered")
	}
	// The process collector emits nothing where procfs is unavailable (macOS,
	// Windows) — it degrades silently by design. The collector is always
	// registered; only its output is platform-dependent, so only assert the
	// series exist where they can.
	if runtime.GOOS == "linux" && !hasProcess {
		t.Error("expected process_* collectors to be registered on linux")
	}
}

func countMetric(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			if m.GetCounter() != nil {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

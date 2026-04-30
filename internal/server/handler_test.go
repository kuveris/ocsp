package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestServeOCSP_RejectsUnsupportedMethod(t *testing.T) {
	handler := ServeOCSP(nil, time.Minute, nil, nil)
	req := httptest.NewRequest(http.MethodPut, "/", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

func TestServeOCSP_RejectsOversizedPostBody(t *testing.T) {
	handler := ServeOCSP(nil, time.Minute, nil, nil)
	body := strings.Repeat("a", maxOCSPRequestSize+1)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected %d, got %d", http.StatusRequestEntityTooLarge, rec.Code)
	}
}

func TestServeOCSP_RejectsMalformedGetEncoding(t *testing.T) {
	handler := ServeOCSP(nil, time.Minute, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/bad", nil)
	req.SetPathValue("request", "%%%bad%%%")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

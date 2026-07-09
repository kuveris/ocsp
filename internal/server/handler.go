package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kuveris/ocsp/internal/responder"
	"github.com/kuveris/ocsp/internal/signer"
	"github.com/kuveris/ocsp/internal/source"
	xocsp "golang.org/x/crypto/ocsp"
)

const maxOCSPRequestSize = 10 * 1024 // 10 KB — OCSP requests are typically < 1 KB

func ServeOCSP(r *responder.Responder, cacheTTL time.Duration, metrics *Metrics, logger *slog.Logger) http.HandlerFunc {
	if logger == nil {
		logger = slog.Default()
	}
	return func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		method := strings.ToLower(req.Method)

		var requestDER []byte
		switch req.Method {
		case http.MethodPost:
			body, err := io.ReadAll(io.LimitReader(req.Body, maxOCSPRequestSize+1))
			if err != nil {
				http.Error(w, "failed to read body", http.StatusInternalServerError)
				return
			}
			if len(body) > maxOCSPRequestSize {
				http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
				return
			}
			requestDER = body
		case http.MethodGet:
			enc := req.PathValue("request")
			b, err := base64.RawURLEncoding.DecodeString(enc)
			if err != nil {
				http.Error(w, "malformed request", http.StatusBadRequest)
				return
			}
			requestDER = b
			w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", int(cacheTTL.Seconds())))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		respDER, err := r.Handle(req.Context(), requestDER)
		duration := time.Since(start).Seconds()

		if err != nil {
			if metrics != nil {
				metrics.RecordRequest(method, "error", duration)
			}
			http.Error(w, "malformed request", http.StatusBadRequest)
			return
		}

		if metrics != nil {
			metrics.RecordRequest(method, parseOCSPStatus(respDER), duration)
		}

		w.Header().Set("Content-Type", "application/ocsp-response")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respDER)
	}
}

// parseOCSPStatus parses the status from a signed DER OCSP response for metrics.
// Returns "good", "revoked", "unknown", or "error" on parse failure.
func parseOCSPStatus(der []byte) string {
	resp, err := xocsp.ParseResponse(der, nil)
	if err != nil {
		return "error"
	}
	switch resp.Status {
	case xocsp.Good:
		return "good"
	case xocsp.Revoked:
		return "revoked"
	default:
		return "unknown"
	}
}

func ServeHealth(sgn *signer.Signer, src source.Source) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		_ = req
		payload := map[string]any{
			"status":                 "ok",
			"signer_valid":           sgn.Valid(),
			"signer_expires_in_days": sgn.DaysUntilExpiry(),
			"signer_expiry_status":   signer.ExpiryStatusString(sgn.GetExpiryStatus()),
			"source":                 src.Name(),
			"source_healthy":         src.Healthy(),
		}

		status := http.StatusOK
		if !sgn.Valid() || !src.Healthy() {
			status = http.StatusServiceUnavailable
			payload["status"] = "unhealthy"
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(payload)
	}
}

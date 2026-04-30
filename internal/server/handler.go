package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/hartmann-it/ocsp-responder/internal/responder"
	"github.com/hartmann-it/ocsp-responder/internal/signer"
	"github.com/hartmann-it/ocsp-responder/internal/source"
)

func ServeOCSP(r *responder.Responder, cacheTTL time.Duration, logger *slog.Logger) http.HandlerFunc {
	if logger == nil {
		logger = slog.Default()
	}
	return func(w http.ResponseWriter, req *http.Request) {
		var requestDER []byte
		switch req.Method {
		case http.MethodPost:
			b, err := io.ReadAll(req.Body)
			if err != nil {
				http.Error(w, "failed to read body", http.StatusInternalServerError)
				return
			}
			requestDER = b
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
		if err != nil {
			http.Error(w, "malformed request", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/ocsp-response")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respDER)
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

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
				logger.Debug("reading OCSP request body failed", "err", err)
				http.Error(w, "failed to read body", http.StatusInternalServerError)
				return
			}
			if len(body) > maxOCSPRequestSize {
				logger.Debug("OCSP request exceeds size limit", "size", len(body), "limit", maxOCSPRequestSize)
				http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
				return
			}
			requestDER = body
		case http.MethodGet:
			b, err := decodeOCSPGetRequest(req.PathValue("request"))
			if err != nil {
				logger.Debug("decoding OCSP GET request failed", "err", err)
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
			// Debug rather than warn: request contents are attacker-controlled,
			// so a malformed-request log line is trivially floodable.
			logger.Debug("handling OCSP request failed", "method", method, "err", err)
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

// ocspGetEncodings lists the base64 alphabets accepted for GET requests, in
// order of preference.
//
// RFC 6960 Appendix A.1.1 defines a GET request as the url-encoding of the
// base64 encoding of the DER request, where "base64" means the standard
// alphabet with padding — so StdEncoding is the canonical form and is tried
// first. The rest are lenient fallbacks: clients that omit padding, and the
// base64url form this responder accepted exclusively before the RFC deviation
// was fixed.
//
// Trying them in turn is unambiguous. The standard and URL alphabets differ
// only in their two non-alphanumeric characters (+/ against -_), so any input
// valid under one is either invalid under the others or, if purely
// alphanumeric, decodes identically under both.
var ocspGetEncodings = []*base64.Encoding{
	base64.StdEncoding,
	base64.RawStdEncoding,
	base64.URLEncoding,
	base64.RawURLEncoding,
}

// decodeOCSPGetRequest decodes the path segment of an OCSP GET request. The
// segment arrives already percent-decoded from http.ServeMux, so the '+', '/'
// and '=' characters that standard base64 produces are present verbatim.
// maxOCSPGetRequestSize is the encoded-length equivalent of
// maxOCSPRequestSize. The POST branch caps the body with io.LimitReader, but a
// GET request arrives in the URL path, where nothing bounds it below net/http's
// 1 MB header limit — leaving room for roughly 68x the POST cap, and the
// base64 decode plus ASN.1 parse that goes with it, on an unauthenticated
// request.
var maxOCSPGetRequestSize = base64.StdEncoding.EncodedLen(maxOCSPRequestSize)

func decodeOCSPGetRequest(enc string) ([]byte, error) {
	if enc == "" {
		return nil, fmt.Errorf("ocsp-responder/server: empty OCSP GET request")
	}
	if len(enc) > maxOCSPGetRequestSize {
		return nil, fmt.Errorf("ocsp-responder/server: OCSP GET request exceeds %d encoded bytes", maxOCSPGetRequestSize)
	}
	for _, e := range ocspGetEncodings {
		if der, err := e.DecodeString(enc); err == nil {
			return der, nil
		}
	}
	return nil, fmt.Errorf("ocsp-responder/server: OCSP GET request is not valid base64")
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

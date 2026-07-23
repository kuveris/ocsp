# ocsp-responder — Design Document

**Status:** Implemented; maintained as an architecture reference
**Applies to:** v0.1.0
**Language:** Go 1.25+
**Repo:** `github.com/kuveris/ocsp`

This document explains *why* the responder is shaped the way it is. For
installation and configuration, see [README.md](README.md).

---

## 1. Scope

`ocsp-responder` is a standalone OCSP responder (RFC 6960), independent of any
particular CA software.

**Intended use:**

- Internal PKI of any flavour — step-ca, OpenSSL CA, EJBCA, XCA
- Homelab CAs
- As a sidecar next to an arbitrary CA server
- Anywhere mail clients, browsers, or other TLS clients need to check
  certificate status

**Explicit non-goals:**

- Not a CA server
- Not a certificate manager
- Not tied to any specific CA implementation
- Not a revocation tool — revocation happens in the CA; this service only
  reports what the CA already decided

---

## 2. Architecture

```
┌──────────────────────────────────────────────────┐
│              ocsp-responder                      │
│                                                  │
│  POST /          ← OCSP request (DER body)       │
│  GET  /{base64}  ← OCSP request (RFC 6960 A.1.1) │
│                                                  │
│  ┌──────────────┐    ┌────────────────────────┐  │
│  │ HTTP Handler │───▶│  Responder Core        │  │
│  └──────────────┘    │  (golang.org/x/crypto) │  │
│                      └──────────┬─────────────┘  │
│                                 │                │
│                      ┌──────────▼─────────────┐  │
│                      │  Status Source         │  │
│                      │  (pluggable interface) │  │
│                      └──────────┬─────────────┘  │
│                                 │                │
│            ┌────────────────────┼──────────────┐ │
│            ▼                    ▼              ▼ │
│      ┌──────────┐        ┌──────────┐  ┌────────┐│
│      │  File    │        │  HTTP    │  │ Static ││
│      │  Source  │        │  Source  │  │ Source ││
│      │  (CRL)   │        │  (API)   │  │ (Test) ││
│      └──────────┘        └──────────┘  └────────┘│
└──────────────────────────────────────────────────┘
```

### Why a Source interface

The responder has no independent knowledge of whether a certificate is valid or
revoked — only the CA does. The **Status Source** is the seam between the two,
and making it an interface is what keeps the responder CA-agnostic. Supporting a
new CA means configuring a mapping or, at worst, adding one implementation
behind an existing interface — never touching the OCSP logic.

| Source | Description | When to use |
|---|---|---|
| `file` | Reads a CRL (PEM or DER), hot-reloads, accepts an HTTP(S) URL | step-ca, OpenSSL, any CA that exports a CRL |
| `http` | Queries a CA REST API with a configurable response mapping, TLS pinning, retry | step-ca API, EJBCA, any CA with an HTTP API |
| `static` | Fixed answer | Tests and development only |

### Fail-closed

The `Source` contract forbids returning `StatusGood` as an error fallback.
A backend that cannot answer must return an error, which the responder turns
into `unknown`. This is the single most important invariant in the design: the
failure mode of a revocation service must never be "this certificate is fine".

---

## 3. Project structure

```
ocsp/
├── cmd/ocsp-responder/main.go     # Entrypoint: config load, wiring, signals
├── internal/
│   ├── config/                    # Config structs, YAML loader, validation
│   ├── source/
│   │   ├── source.go              # Source interface + shared types
│   │   ├── file.go                # CRL-backed source (file or URL)
│   │   ├── http.go                # CA REST API source
│   │   └── static.go              # Fixed-answer source
│   ├── signer/signer.go           # Signing cert/key, expiry monitoring
│   ├── responder/responder.go     # OCSP core + in-memory response cache
│   └── server/
│       ├── server.go              # HTTP server, TLS/ACME, graceful shutdown
│       ├── handler.go             # POST, GET, /health handlers
│       └── metrics.go             # Prometheus collectors
├── config/ocsp-responder.yaml     # Annotated example configuration
├── examples/systemd/              # Unit file for non-container deployment
├── integration_test.go            # End-to-end tests (build tag: integration)
├── .golangci.yml                  # Lint configuration
├── Dockerfile                     # Multi-stage, non-root runtime
└── docker-compose.yaml
```

Every package under `internal/` is unexported by construction — this is a
service, not a library, and nothing here is a stable public API.

---

## 4. Core interface

```go
// internal/source/source.go

// Status represents the revocation status of a certificate.
type Status int

const (
    StatusGood    Status = iota // Certificate is valid
    StatusRevoked               // Certificate has been revoked
    StatusUnknown               // Certificate is not known to this responder
)

// RevocationInfo contains details about a revoked certificate.
type RevocationInfo struct {
    RevokedAt time.Time
    Reason    int // RFC 5280 CRLReason codes (0=unspecified, 1=keyCompromise, ...)
}

// CertStatus is the result of a status lookup.
type CertStatus struct {
    Status         Status
    RevocationInfo *RevocationInfo // only set when Status == StatusRevoked
}

// Source is the pluggable interface for certificate status backends.
// Implementations must be safe for concurrent use.
type Source interface {
    // GetStatus returns the revocation status of the certificate with the given serial.
    // The issuer certificate is provided for backends that need to verify the chain.
    // Must never return StatusGood as a fallback on errors — return error instead.
    GetStatus(ctx context.Context, serial *big.Int, issuer *x509.Certificate) (*CertStatus, error)

    // Name returns a human-readable identifier for this source (used in logs and /health).
    Name() string

    // Healthy returns true if the source is operational and up-to-date.
    Healthy() bool
}
```

---

## 5. Design decisions

### CRL change detection uses a content hash, not mtime

The file source re-reads the CRL on each interval and compares a SHA-256 digest
against the loaded one. Comparing modification times was tried first and is
wrong in two ways:

- Filesystem timestamps come from a coarse clock, so two writes in quick
  succession often share an mtime.
- Timestamp-preserving copies — `cp -p`, `rsync -a`, `install -p`, backup
  restores — can install a *newer* CRL with an *older* mtime.

Either case leaves the responder serving a stale CRL indefinitely while
reporting healthy, which means answering `good` for a revoked certificate. The
extra read per interval is irrelevant next to that.

### Issuer binding is checked before lookup

Incoming requests are validated against the configured issuer's name and key
hashes before any status lookup happens. A responder that answers for issuers it
was not configured for is answering questions it has no authority over.

### CRLs are verified against the configured issuer

A CRL is checked for issuer match and signature validity before its entries are
trusted, so a swapped or corrupted CRL is rejected rather than served.

### Validation happens at startup

Missing `OCSPSigning` EKU, a signer not issued by the configured issuer, a
non-CA issuer, or a key that does not match the certificate are all startup
failures. Misconfiguration should prevent the service from starting, not produce
wrong answers at runtime.

### Caching is safe by construction

OCSP responses are signed and carry their own validity window, so caching cannot
forge an answer. Cache eviction at `max_entries` drops an arbitrary entry rather
than the oldest — acceptable because every entry is independently valid and a
miss costs one source lookup.

### GET accepts more than the RFC requires

RFC 6960 A.1.1 specifies the url-encoding of *standard* base64. That is the
canonical form, tried first. Unpadded standard base64 and both base64url
variants are also accepted, since the alphabets are distinguishable and
rejecting a client over padding serves nobody.

---

## 6. HTTP endpoints

```
POST /
  Content-Type: application/ocsp-request
  Body: DER-encoded OCSPRequest (max 10 KB)
  → 200 + Content-Type: application/ocsp-response
  → 400 on malformed request
  → 413 if the body exceeds the limit

GET /{base64-encoded-request}
  → Same logic, per RFC 6960 Appendix A.1.1
  → Sets Cache-Control for proxy caching

GET /health
  → 200 + {"status":"ok","signer_valid":true,"signer_expires_in_days":312,
           "signer_expiry_status":"ok","source":"file","source_healthy":true}
  → 503 if the signer is invalid/expired or the source is unhealthy

GET /metrics
  → Prometheus exposition format
```

---

## 7. Dependencies

| Library | Purpose |
|---|---|
| `golang.org/x/crypto/ocsp` | Parse OCSP requests, build and sign responses |
| `golang.org/x/crypto/acme/autocert` | Automatic TLS via ACME (optional) |
| `crypto/x509` (stdlib) | Certificate handling, CRL parsing |
| `net/http` (stdlib) | HTTP server and routing |
| `gopkg.in/yaml.v3` | Configuration |
| `github.com/prometheus/client_golang` | Prometheus metrics |

First-party code is limited to the source interface, config, HTTP handlers,
signer wiring, and the cache. `golang.org/x/crypto/ocsp` covers every OCSP
operation, so no external OCSP toolkit is required.

---

## 8. Implementation status

All three phases are complete.

### Phase 1 — Working responder with a CRL source

- [x] `source.Source` interface and shared types
- [x] `source.Static`: configurable answer, for tests
- [x] `source.File`: CRL loading (PEM + DER), serial indexing, hot reload
- [x] `signer.Signer`: key/cert loading, `OCSPSigning` EKU validation
- [x] `responder.Responder`: OCSP core plus in-memory cache with TTL
- [x] HTTP handlers: POST, GET, `/health`
- [x] Graceful shutdown (SIGTERM, 10s timeout)
- [x] Structured logging

### Phase 2 — HTTP source

- [x] `source.HTTP`: generic REST client
- [x] Configurable response mapping (path template, status field, good/revoked values)
- [x] TLS verification with root certificate pinning
- [x] Retry with backoff
- [x] In-memory cache with configurable TTL
- [x] Observer interface for Prometheus metrics

### Phase 3 — Hardening

- [x] Signer certificate expiry monitoring (warning under 30 days, critical under 8)
- [x] Prometheus metrics at `/metrics`
- [x] TLS for the HTTP server (manual cert+key or ACME/autocert)
- [x] Dockerfile (multi-stage, non-root)
- [x] systemd unit example

---

## 9. Security notes

- The OCSP signing key is never logged, at any level
- `certs/` is gitignored in full
- Signing key file permissions: `600`, owned by the service user
- On source error: return `StatusUnknown`, **never** `StatusGood`
- Requests are validated against configured issuer bindings before lookup
- CRLs are verified against the configured issuer before use
- OCSP responses are signed, so caching is safe and intended
- Request bodies are capped at 10 KB
- The container image runs as a non-root user

---

## 10. Using it with different CAs

### step-ca with a CRL

```bash
step ca crl --out certs/ca.crl
# → source.type: "file", file.crl_path: "certs/ca.crl"
```

### OpenSSL CA

```bash
openssl ca -gencrl -out ca.crl.pem -config openssl.cnf
# Or as DER:
openssl crl -in ca.crl.pem -outform DER -out certs/ca.crl
# → source.type: "file" — PEM and DER are auto-detected
```

### Any other CA

Any CA that can export a CRL works with the `file` source. Any CA with an HTTP
status API works with the `http` source and a suitable response mapping.

---

## 11. Testing

Roughly 146 tests across six packages, plus an end-to-end suite behind the
`integration` build tag.

| Package | Focus |
|---|---|
| `internal/config` | Loading, validation of every required field and duration |
| `internal/source` | CRL parsing (PEM/DER), reload, issuer verification, HTTP source mapping, retry, error classification |
| `internal/signer` | Cert/key loading (RSA and ECDSA, PKCS#1 and PKCS#8), EKU and trust validation, expiry thresholds |
| `internal/responder` | Status handling, issuer binding, cache behaviour, fail-closed on source errors |
| `internal/server` | Handlers for POST/GET/health, request limits, GET encodings, metrics recording |
| `integration_test.go` | Full server over real HTTP: POST, GET, health, cache, reload |

Two conventions worth preserving:

- **Do not encode test fixtures with the function under test.** The GET handler
  accepted a non-RFC base64 alphabet for months because both the unit and
  integration tests encoded with the same function the handler decoded with.
  Encoding vectors now come from an independent tool.
- **Do not assert against wall-clock elapsed time.** Compare against the value a
  fixture was built with, so the suite survives `-count=N`.

CI runs vet, golangci-lint (with and without the integration tag), the unit and
integration suites under `-race`, a coverage report, and a Docker image build.

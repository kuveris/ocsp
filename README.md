# ocsp-responder

A standalone, CA-agnostic OCSP Responder (RFC 6960) written in Go.

## Features

- File-backed CRL source with hot-reload (PEM and DER), including HTTP(S) CRL URLs
- HTTP source for CA REST APIs (configurable response mapping)
- Static source for testing
- In-memory response cache (configurable TTL and max entries)
- Prometheus metrics at `/metrics`
- TLS support (manual cert or automatic via ACME)
- Graceful shutdown on SIGTERM/SIGINT
- Structured JSON logging

## Quick Start

### Docker Compose

```yaml
# docker-compose.yaml
version: "3.9"
services:
  ocsp-responder:
    image: ocsp-responder:latest
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./certs:/certs:ro
      - ./config:/etc/ocsp-responder:ro
    command: ["--config", "/etc/ocsp-responder/ocsp-responder.yaml"]
```

### Binary

```bash
make build
./ocsp-responder --config config/ocsp-responder.yaml
```

### Test the responder

```bash
# Health check
curl http://localhost:8080/health

# Prometheus metrics
curl http://localhost:8080/metrics
```

## Configuration

See [`config/ocsp-responder.yaml`](config/ocsp-responder.yaml) for a fully annotated example.

### Key fields

| Field | Description |
|---|---|
| `server.listen_addr` | Address to listen on (default: `0.0.0.0:8080`) |
| `server.tls.enabled` | Enable TLS |
| `server.tls.cert_file` / `key_file` | Manual TLS certificate and key |
| `server.tls.acme_host` | Hostname for automatic ACME certificate |
| `server.tls.acme_ca_url` | ACME directory URL for internal CAs |
| `signer.cert_file` | OCSP delegated signing certificate (must have `extKeyUsage OCSPSigning`) |
| `signer.key_file` | OCSP signing private key |
| `signer.issuer_cert_file` | Issuer certificate of the end-entity certificates |
| `signer.response_validity` | OCSP response validity window (e.g. `24h`) |
| `source.type` | Status source: `file`, `http`, or `static` |
| `cache.enabled` | Enable in-memory response cache |
| `cache.ttl` | Cache TTL (e.g. `1h`) |
| `cache.max_entries` | Maximum number of cached responses |
| `logging.level` | Log level: `debug`, `info`, `warn`, `error` |
| `logging.format` | Log format: `json` or `text` |

## Status Sources

### File Source

Reads a CRL file (PEM or DER) and uses it to determine revocation status.
Supports hot-reload when the file changes.
`crl_path` may also be an HTTP(S) URL — the CRL will be downloaded and refreshed
at the configured `reload_interval`.

```yaml
source:
  type: "file"
  file:
    crl_path: "certs/ca.crl"        # local file or HTTP(S) URL
    reload_interval: "5m"
```

### HTTP Source

Queries a CA REST API for certificate status. The response mapping is fully
configurable so any CA API can be supported without code changes.

```yaml
source:
  type: "http"
  http:
    base_url: "https://ca.example.local:9000"
    root_cert_file: "certs/root-ca.crt"   # optional: TLS pinning
    timeout: "10s"
    retry_max: 3
    retry_backoff: "500ms"
    cache_ttl: "5m"
    response_mapping:
      path_template: "/1.0/certificates/{serial}"
      status_field: "status"
      good_values: ["active", "valid"]
      revoked_values: ["revoked", "suspended"]
```

### Static Source

Returns a hardcoded status for all certificates. Useful for testing.

```yaml
source:
  type: "static"
  static:
    status: "good"   # "good" | "revoked" | "unknown"
```

## Supported CAs

### step-ca

```bash
# Export CRL from step-ca
step ca crl --out certs/ca.crl
```

Use `source.type: "file"` with `file.crl_path: "certs/ca.crl"`.

Alternatively, use `source.type: "http"` with the step-ca certificate API:

```yaml
source:
  type: "http"
  http:
    base_url: "https://ca.example.local:9000"
    response_mapping:
      path_template: "/1.0/certificates/{serial}"
      status_field: "status"
      good_values: ["active", "valid"]
      revoked_values: ["revoked"]
```

### OpenSSL CA

```bash
# Generate CRL (PEM)
openssl ca -gencrl -out certs/ca.crl.pem -config openssl.cnf

# Or as DER
openssl crl -in certs/ca.crl.pem -outform DER -out certs/ca.crl
```

Use `source.type: "file"` — both PEM and DER are auto-detected.

### Generic HTTP API

Any CA with an HTTP API that returns certificate status can be used with the
`http` source and a custom `response_mapping`.

## Security Notes

- **Private key** — the OCSP signing key is never logged, even at `DEBUG` level
- **`certs/`** is listed in `.gitignore` — never commit certificate files
- **Key permissions** — set signing key to `chmod 600`, owned by the service user
- **StatusUnknown on errors** — the responder never returns `StatusGood` as a
  fallback; it always returns `StatusUnknown` when the status source fails
- **Signed responses** — OCSP responses are cryptographically signed; in-memory
  caching is safe and recommended
- **Request size limit** — request bodies are limited to 10 KB (OCSP requests are
  typically under 1 KB)
- **Issuer binding checks** — incoming OCSP requests are validated against the configured
  issuer certificate hash bindings before status lookup
- **CRL trust checks** — file/URL CRLs are validated against the configured issuer before
  revocation entries are used

## HTTP Endpoints

| Endpoint | Description |
|---|---|
| `POST /` | DER-encoded OCSP request body → signed OCSP response |
| `GET /{base64url}` | Base64url-encoded OCSP request (RFC 6960 Section 5) |
| `GET /health` | Health check — returns 200 OK or 503 if unhealthy |
| `GET /metrics` | Prometheus metrics |

## Prometheus Metrics

| Metric | Type | Description |
|---|---|---|
| `ocsp_requests_total{method,status}` | Counter | Total OCSP requests processed |
| `ocsp_request_duration_seconds{method}` | Histogram | Request processing time |
| `ocsp_cache_entries` | Gauge | Current number of cached responses |
| `ocsp_cache_hits_total` | Counter | Cache hits |
| `ocsp_cache_misses_total` | Counter | Cache misses |
| `ocsp_signer_days_until_expiry` | Gauge | Days until the signing certificate expires |
| `ocsp_source_requests_total{source,result}` | Counter | Requests to the status source |
| `ocsp_source_request_duration_seconds{source}` | Histogram | Source request latency |
| `ocsp_source_retries_total{source}` | Counter | Source retries |
| `ocsp_source_errors_total{source,class}` | Counter | Source error classes |

## Building

```bash
make build    # build binary
make test     # run unit tests
make lint     # run go vet
```

### Integration tests

```bash
go test -tags integration ./...
```

## License

MIT — see [`LICENSE`](LICENSE).

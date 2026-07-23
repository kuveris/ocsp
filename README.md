# ocsp-responder

[![CI](https://github.com/kuveris/ocsp/actions/workflows/ci.yml/badge.svg)](https://github.com/kuveris/ocsp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)](go.mod)

A small, CA-agnostic OCSP responder ([RFC 6960](https://www.rfc-editor.org/rfc/rfc6960)) written in Go.

Point it at a CRL file, a URL, or a CA's REST API, give it a delegated signing
certificate, and it answers OCSP queries about your certificates. It ships as a
single static binary or a 19 MB container image, with no database and no runtime
dependencies.

## What it is

- A **standalone OCSP responder** you run next to an existing CA
- **CA-agnostic** — it reads revocation state from a CRL or an HTTP API, so it
  doesn't care which software issued your certificates
- **Read-only** — it answers status queries and nothing else

## What it is not

- Not a CA — it does not issue certificates
- Not a certificate manager
- Not a revocation tool — revoking happens in your CA; this service only reports
  what the CA already decided

## Should you use this?

Probably worth being upfront: if you need a battle-tested OCSP responder for a
public PKI, use [Boulder](https://github.com/letsencrypt/boulder) (what Let's
Encrypt runs) or [OpenXPKI](https://www.openxpki.org/). They have years of
production exposure that this does not.

This project is aimed at a narrower case: an internal or homelab PKI where you
already have a CA that emits a CRL, you want OCSP without deploying a full PKI
suite, and you'd like the whole thing to be a config file and one binary. If
that's you, it should be a comfortable fit. If you're securing something that
matters to the public internet, reach for the established options.

## Quick start

### Docker Compose

The repository ships a [`docker-compose.yaml`](docker-compose.yaml):

```bash
git clone https://github.com/kuveris/ocsp.git
cd ocsp
# place your certificates in ./certs and edit ./config/ocsp-responder.yaml
docker compose up        # or: make up
```

This pulls the published image from GHCR. To build from local source instead,
use `make dev` (equivalently `docker compose -f docker-compose.dev.yaml up
--build`).

Set `OCSP_PORT` to bind a host port other than 8080, and `OCSP_IMAGE` to pin a
release tag rather than `latest`.

### Binary

```bash
go install github.com/kuveris/ocsp/cmd/ocsp-responder@latest
ocsp-responder --config /etc/ocsp-responder/ocsp-responder.yaml
```

Or build from source:

```bash
make build
./ocsp-responder --config config/ocsp-responder.yaml
```

For a long-running install, see the unit file in
[`examples/systemd/`](examples/systemd/).

### Check it works

```bash
curl http://localhost:8080/health
```

```json
{
  "signer_expires_in_days": 312,
  "signer_expiry_status": "ok",
  "signer_valid": true,
  "source": "file",
  "source_healthy": true,
  "status": "ok"
}
```

Then query a real certificate with OpenSSL:

```bash
openssl ocsp -issuer intermediate-ca.crt -cert client.crt \
  -url http://localhost:8080 -resp_text
```

## Certificates you need

Three files, and the responder validates all of them at startup — it refuses to
boot on a misconfiguration rather than serving bad answers.

| File | Requirement |
|---|---|
| `signer.cert_file` | Must carry `extendedKeyUsage = OCSPSigning`, and must be signed by the issuer below |
| `signer.key_file` | The matching private key: PKCS#8 (RSA or ECDSA) or PKCS#1 (RSA). SEC1 EC keys (`BEGIN EC PRIVATE KEY`, from `openssl ecparam -genkey`) are **not** accepted — convert with `openssl pkcs8 -topk8 -nocrypt` |
| `signer.issuer_cert_file` | The CA that issued the certificates you're answering for. Must be a CA certificate with the `keyCertSign` key usage |

The signing certificate is a **delegated responder**: the issuing CA signs it,
so clients trust its answers without the CA's own key ever touching this
service.

Generating one with OpenSSL — first an extensions file:

```ini
# ocsp-signer.cnf
[ ocsp_signer ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
```

Then issue it from your intermediate CA:

```bash
openssl req -newkey rsa:3072 -nodes \
  -keyout certs/ocsp-signer.key \
  -out certs/ocsp-signer.csr \
  -subj "/CN=OCSP Responder"

openssl x509 -req -in certs/ocsp-signer.csr \
  -CA certs/intermediate-ca.crt -CAkey certs/intermediate-ca.key \
  -CAcreateserial -days 365 \
  -extfile ocsp-signer.cnf -extensions ocsp_signer \
  -out certs/ocsp-signer.crt
```

With `step-ca`, the equivalent is a certificate issued from a provisioner
configured for OCSP signing.

## Configuration

A fully annotated example lives at
[`config/ocsp-responder.yaml`](config/ocsp-responder.yaml).

| Field | If omitted | Description |
|---|---|---|
| `server.listen_addr` | `0.0.0.0:8080` | Address to listen on |
| `server.tls.enabled` | `false` | Serve OCSP over HTTPS |
| `server.tls.cert_file` / `key_file` | — | Manual TLS certificate and key |
| `server.tls.min_version` | `1.2` | Minimum TLS version — `1.3` selects TLS 1.3, anything else is 1.2 |
| `server.tls.acme_host` | — | Hostname for an automatic ACME certificate |
| `server.tls.acme_ca_url` | — | ACME directory URL, for internal CAs |
| `signer.cert_file` | **required** | OCSP delegated signing certificate |
| `signer.key_file` | **required** | Signing private key |
| `signer.issuer_cert_file` | **required** | Issuer of the certificates being checked |
| `signer.response_validity` | **required** | Response validity window, sets `nextUpdate` (e.g. `24h`) |
| `source.type` | **required** | `file`, `http`, or `static` |
| `source.file.expiry_grace` | strict | How long a CRL stays usable past its `NextUpdate`. Empty or `0s` refuses an expired CRL |
| `cache.enabled` | `false` | In-memory response cache. The example config enables it |
| `cache.ttl` | **required** | Cache entry lifetime (e.g. `1h`) — validated even when the cache is disabled |
| `cache.max_entries` | `0` (cache inert) | Cache size cap. `0` silently disables caching |
| `logging.level` | `info` | `debug`, `info`, `warn`, `error` |
| `logging.format` | `text` | `json` selects JSON; any other value is text |

Config is validated on load and the process exits on anything invalid, so a
bad *value* surfaces at startup rather than in production. Note that a
misspelled *field name* is silently ignored rather than rejected — the loader
does not reject unknown keys, so `lissten_addr` reads as "unset" and takes the
default.

One of these is easy to trip over: the cache is off unless you set both
`cache.enabled: true` and a non-zero `cache.max_entries`. Starting from the
shipped example config avoids it.

OCSP is served over plain HTTP by design — responses are signed, so the
transport doesn't need to be confidential. TLS is available if you want it, but
it is not what makes the answers trustworthy.

## Status sources

### `file` — CRL on disk or over HTTP

Reads a CRL in PEM or DER (auto-detected) and answers from its revocation
entries. Reloads automatically when the file changes.

```yaml
source:
  type: "file"
  file:
    crl_path: "certs/ca.crl"    # local path or an http(s):// URL
    reload_interval: "5m"
```

`crl_path` also accepts an HTTP(S) URL, in which case the CRL is downloaded and
refreshed on every `reload_interval`.

The CRL's signature is verified against `signer.issuer_cert_file` before any of
its entries are trusted, so a swapped or corrupted CRL is rejected instead of
being served.

**Expired CRLs are refused.** A CRL past its `NextUpdate` is not loaded, and one
that expires while the responder is running takes the source unhealthy, so
answers become `unknown` rather than a stale `good`. This matters because the
failure is otherwise invisible: if publication stops, the file on disk never
changes, so nothing detects that the data is obsolete while certificates
revoked since then are still reported valid.

If your CA publishes late, `expiry_grace` widens the window rather than taking
the responder down at the moment `NextUpdate` passes:

```yaml
source:
  type: "file"
  file:
    crl_path: "certs/ca.crl"
    reload_interval: "5m"
    expiry_grace: "30m"   # default is strict
```

### `http` — a CA's REST API

Queries your CA directly. The response mapping is configuration, not code, so
most CA APIs can be supported without patching anything.

```yaml
source:
  type: "http"
  http:
    base_url: "https://ca.example.local:9000"
    root_cert_file: "certs/root-ca.crt"   # optional: pin the CA's TLS root
    timeout: "10s"
    retry_max: 3                          # default 3
    retry_backoff: "500ms"                # default 500ms
    cache_ttl: "5m"
    response_mapping:
      path_template: "/1.0/certificates/{serial}"
      status_field: "status"
      good_values: ["active", "valid"]
      revoked_values: ["revoked", "suspended"]
```

`{serial}` is replaced with the certificate serial from the OCSP request,
formatted as **uppercase hexadecimal with no leading zeros**. A CA API that
expects decimal or lowercase will 404, which the source maps to `unknown` for
every certificate.
Anything not matching `good_values` or `revoked_values` becomes `unknown`.

### `static` — fixed answer

Returns the same status for every certificate. For testing only.

```yaml
source:
  type: "static"
  static:
    status: "good"   # good | revoked | unknown
```

## CA integration

### step-ca

Export the CRL and use the `file` source:

```bash
step ca crl --out certs/ca.crl
```

Or query the certificate API directly with the `http` source:

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
openssl ca -gencrl -out certs/ca.crl.pem -config openssl.cnf
```

Use the `file` source — PEM and DER are both accepted.

### Anything else

Any CA that exposes certificate status over HTTP works with the `http` source
and a suitable `response_mapping`. Any CA that publishes a CRL works with the
`file` source. Between the two, most setups are covered.

## HTTP endpoints

| Endpoint | Description |
|---|---|
| `POST /` | DER-encoded OCSP request in the body → signed OCSP response |
| `GET /{encoded}` | Base64-encoded OCSP request in the path, per RFC 6960 A.1.1 |
| `GET /health` | Health check — `200` when healthy, `503` when not |
| `GET /metrics` | Prometheus metrics |

Requests are capped at 10 KB of DER on both methods — the POST body directly,
the GET path at its base64-encoded equivalent. Real OCSP requests are well
under 1 KB.

`GET` follows RFC 6960 Appendix A.1.1 — the URL-encoding of the standard base64
encoding of the DER request. Unpadded standard base64 and both base64url forms
are also accepted, so a client that picks a different variant still works.

## Observability

### Health

`GET /health` returns `503` and `"status": "unhealthy"` when the signing
certificate is invalid or expired, or when the status source is unhealthy —
a CRL that failed to load or has expired, or a CA API that stopped answering.
Suitable as a container health check or load-balancer probe.

Both sources are healthy until proven otherwise, so a freshly started responder
reports healthy without needing to serve a request first. For the `file` source
that is settled at startup, since the CRL is loaded before the server binds; for
the `http` source the first failed lookup demotes it, and a later success
restores it.

### Metrics

| Metric | Type | Description |
|---|---|---|
| `ocsp_requests_total{method,status}` | Counter | OCSP requests processed |
| `ocsp_request_duration_seconds{method}` | Histogram | Request processing time |
| `ocsp_cache_entries` | Gauge | Responses currently cached |
| `ocsp_cache_hits_total` | Counter | Cache hits |
| `ocsp_cache_misses_total` | Counter | Cache misses |
| `ocsp_signer_days_until_expiry` | Gauge | Days until the signing certificate expires |
| `ocsp_source_requests_total{source,result}` | Counter | Requests to the status source |
| `ocsp_source_request_duration_seconds{source}` | Histogram | Status source latency |
| `ocsp_source_retries_total{source}` | Counter | Status source retries |
| `ocsp_source_errors_total{source,class}` | Counter | Status source errors by class |

`ocsp_signer_days_until_expiry` is the one worth alerting on. The responder
classifies it internally as OK at 30 days or more, warning at 8–29, and
critical below 8 — an expired signing certificate does not stop the process — it keeps
serving responses that clients reject, which is an outage that looks like
uptime. Easy to forget about for a year.

## Security notes

- **Fails closed.** When the status source errors, the responder returns
  `unknown` — never `good`. A broken CRL feed cannot silently vouch for a
  revoked certificate.
- **Issuer binding is enforced.** Incoming requests are checked against the
  configured issuer's name and key hashes before any lookup happens, so the
  responder won't answer for a CA it isn't configured to speak for.
- **CRLs are verified.** A CRL is checked against the configured issuer before
  its entries are used, and refused once past its `NextUpdate` (see
  `expiry_grace`) so stale revocation data cannot be served as current.
- **The signing key is never logged**, at any log level.
- **Startup validation.** Missing EKU, a signer not issued by the configured
  issuer, a non-CA issuer, or a key that doesn't match the certificate are all
  startup failures rather than runtime surprises.
- **Runs as non-root** in the container image, as uid 100.
- **Caching is safe.** OCSP responses are signed and carry their own validity
  window, so caching them cannot forge an answer. Note that eviction at
  `max_entries` drops an arbitrary entry, not the oldest or least-used.
- **Key permissions** are your responsibility: `chmod 600`, owned by the service
  user. Key and certificate *extensions* under `certs/` are gitignored
  (`*.key`, `*.crt`, `*.pem`, `*.der`, `*.crl`, `*.p12`) — other filenames
  there are not, so avoid `privkey` or `signer.key.bak`.

## Development

```bash
make check              # full gate: lint + unit + integration, all under -race
make build              # build the binary
make test               # unit tests
make integration-test   # integration tests
make coverage           # coverage summary
make coverage-check     # fail if coverage drops below the threshold
make lint               # go vet + golangci-lint
make dev                # build locally and run via compose
make help               # list the available targets
```

Requires Go 1.25 or newer. `make lint` additionally needs
[golangci-lint](https://golangci-lint.run) v2.

## Contributing

Bug reports and patches are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
For security issues, please follow [SECURITY.md](SECURITY.md) rather than
opening a public issue.

## License

MIT — see [LICENSE](LICENSE).

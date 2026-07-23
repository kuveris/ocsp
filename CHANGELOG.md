# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-07-23

First public release. Pre-1.0: the configuration format may still change, and
the responder has not yet been run against a production PKI.

### Added

- OCSP responder per RFC 6960, over `POST /` and `GET /{base64}`
- **File status source** — reads a CRL in PEM or DER, hot-reloads on change,
  and accepts an HTTP(S) URL as well as a local path
- **HTTP status source** — queries a CA REST API with a configurable response
  mapping, TLS root pinning, and retry with backoff, so a new CA needs
  configuration rather than code
- **Static status source** for testing
- In-memory response cache with configurable TTL and entry cap
- Prometheus metrics at `/metrics`, covering requests, cache, status source,
  and signing certificate expiry
- Health endpoint at `/health`, reporting signer validity, days to expiry, and
  source health, and returning 503 when either is unhealthy
- TLS support with a manual certificate or automatic issuance via ACME
- Signing certificate expiry monitoring — warning under 30 days, critical
  under 8
- Startup validation of the signing certificate, its key, and the issuer:
  `OCSPSigning` EKU, key/certificate match, issuer is a CA with `keyCertSign`,
  and the signer is issued by that issuer
- Issuer binding validation on incoming requests, before any status lookup
- CRL issuer and signature verification before revocation entries are trusted
- Graceful shutdown on SIGTERM and SIGINT
- Structured logging in JSON or text
- Multi-stage Dockerfile running as a non-root user, plus production and
  development Compose stacks
- systemd unit example

### Security

- The responder never returns `good` as an error fallback. A status source that
  cannot answer produces `unknown`, so a broken CRL feed cannot vouch for a
  revoked certificate.
- CRL change detection compares a content hash rather than modification time.
  Timestamp comparison could silently serve a stale CRL indefinitely — mtimes
  are coarse enough to collide on rapid rewrites, and timestamp-preserving
  copies (`cp -p`, `rsync -a`, backup restores) can install a newer CRL with an
  older timestamp. For a revocation service that meant reporting a revoked
  certificate as good.
- The OCSP signing key is never logged, at any level.
- Request bodies are capped at 10 KB.

[Unreleased]: https://github.com/kuveris/ocsp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kuveris/ocsp/releases/tag/v0.1.0

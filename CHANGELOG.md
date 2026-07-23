# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Expired CRLs are no longer used. Expiry is checked live on every lookup, so a
  CRL past its `NextUpdate` takes the file source unhealthy and the responder
  answers `unknown` — whether it was already expired at load or expires later
  while the file on disk never changes. Previously a stalled CRL publisher meant
  every certificate revoked since the last publication was reported `good`,
  indefinitely, with `/health` still green. An already-expired CRL at startup is
  now a transient condition the responder recovers from, not a fatal error.

### Added

- `source.file.expiry_grace` keeps a CRL usable for a configured duration past
  its `NextUpdate`, for CAs that publish late. Defaults to strict.

### Documentation

- Recorded that RFC 6960 nonces are deliberately not echoed, with the caching
  tradeoff and the resulting replay window, in README, SECURITY.md and
  DESIGN.md. The behaviour is unchanged; it was previously undocumented, so
  every `openssl ocsp` user saw an unexplained warning.

### Changed

- Unknown keys in the configuration file are now rejected by name instead of
  being silently discarded. A misspelled field previously took its default with
  no indication — `cache.enabeld: true` left the cache off, and a typo in a
  path meant the configured file was not the one in use. **Breaking** for any
  config carrying extra keys.

### Security

- Release workflow actions on the publishing jobs are pinned to commit SHAs
  rather than mutable major tags, and the publish job now builds the exact
  commit the test job validated rather than re-resolving the tag.
- Published images now carry an SBOM and full build provenance.

### Fixed

- The release step is idempotent, so a re-run after a partial failure completes
  instead of aborting with "release already exists".
- The ACME certificate cache is now configurable via
  `server.tls.acme_cache_dir` and defaults to the absolute
  `/var/lib/ocsp-responder/acme`. It was a path relative to the working
  directory, which in the container resolved inside the read-only `/certs`
  mount — autocert then fell back to in-memory and re-ordered a certificate on
  every restart. Startup now fails if the directory is not writable instead of
  degrading silently, and the Compose stacks mount a named volume for it. The
  writability probe uses a unique temp name so concurrent instances sharing the
  cache directory do not race.
- Added `.dockerignore`. The build context previously carried `.git`, which
  differs on every checkout and so invalidated the source-copy layer and the
  compile behind it on every CI run — making the layer cache not merely useless
  but counterproductive, since each run wrote a full layer set into a shared,
  size-capped cache. Local builds also no longer copy `certs/` into an
  intermediate layer.
- Prometheus collectors are registered on a per-instance registry instead of
  the global default, so the responder can be constructed more than once in a
  process. `/metrics` output is unchanged, including the `go_*` and `process_*`
  collectors, which are now registered explicitly.
- CI now runs on pull requests, including from forks. Previously the workflow
  triggered only on `push`, so an external contribution produced no CI run at
  all — no tests, no race detector, no lint, no coverage gate.
- The `http` status source no longer reports unhealthy until its first
  successful lookup. It previously deadlocked any deployment gating traffic on
  `/health`: the probe withheld the request that would have proven the source
  works, so it never became healthy. Both sources are now healthy until a
  failure demotes them.
- The file source now logs why it went unhealthy. Reload failures were
  discarded, so a responder that dropped to `unknown` gave an operator a 503
  and nothing else to work from.

### Added

- Dependabot configuration for Go modules, GitHub Actions, and Docker base
  images, so pinned versions cannot silently age.

## [0.1.2] — 2026-07-23

No functional change. The binary and container image are equivalent to 0.1.1;
this release exists to tag the CI change below.

### Changed

- Coverage threshold lowered from 88% to 85%. Still above the 80% project
  minimum, with more headroom for legitimately hard-to-test code.

## [0.1.1] — 2026-07-23

### Fixed

- `server.listen_addr` now defaults to `0.0.0.0:8080` when omitted. Previously
  an omitted value reached Go's HTTP server as an empty address, which binds
  the privileged port 80 — neither documented nor intended.

### Changed

- Test coverage raised from 79.7% to 89.2%. `internal/config`,
  `internal/responder` and `internal/server` are now at 100%; `server.Start`
  went from 8.8% to full coverage, including the TLS, ACME, misconfiguration
  and listen-failure paths.
- CI and the release workflow now fail when total coverage drops below a
  threshold, rather than printing the number and continuing. `make check`
  enforces the same threshold locally.

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

[Unreleased]: https://github.com/kuveris/ocsp/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/kuveris/ocsp/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/kuveris/ocsp/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/kuveris/ocsp/releases/tag/v0.1.0

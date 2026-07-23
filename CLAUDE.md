# ocsp-responder — agent briefing

Standalone OCSP responder (RFC 6960), Go, no database. Public, MIT.

Read [DESIGN.md](DESIGN.md) for architecture and the reasoning behind the
non-obvious decisions. [README.md](README.md) is the user-facing documentation
and must stay accurate — it is the first thing an external reader sees.

## Ground rules

- **Gate before committing:** `make check` (lint + unit + integration, `-race`).
- **Tests first.** For a bug, a failing reproduction before the fix.
- **Never return `good` on error.** A status source that cannot answer produces
  `unknown`. This is the core invariant; a change that weakens it is wrong even
  if tests pass.
- Commit format: `ISSUE-ID (type): description`.
- User-visible changes get a `[Unreleased]` entry in CHANGELOG.md, same commit.

## Testing conventions

Both of these come from real defects that shipped:

- **Never encode a test fixture with the function under test.** The GET handler
  used the wrong base64 alphabet for months because tests encoded with the same
  function the handler decoded with. For spec-defined formats, generate fixtures
  with an independent tool and hardcode them.
- **Never assert on wall-clock elapsed time.** Compare against the value a
  fixture was built with, or the package cannot be stressed with `-count=N`.

## Things that bite

- `internal/source/file.go` detects CRL changes by **content hash**, not mtime.
  Do not "optimise" this back to a stat comparison — coarse timestamps and
  timestamp-preserving copies (`cp -p`, `rsync -a`) both cause a silently stale
  CRL, which means answering `good` for a revoked certificate.
- The Dockerfile pin must track `go.mod`. The official Go images set
  `GOTOOLCHAIN=local`, so they will not auto-upgrade to satisfy it, and neither
  local builds nor `setup-go` can catch the mismatch — only the CI Docker build.
- `server.listen_addr` defaults to `0.0.0.0:8080` via `config.DefaultListenAddr`.
  It must stay non-privileged — an empty value would let Go bind `:80`.
- Config is YAML only. There is no env-var configuration path; `OCSP_PORT` and
  `OCSP_IMAGE` are Compose-level only.

## Known gaps

- Coverage is 79.7%, just under the 80% target. The shortfall is
  `server.Start` — listener/TLS/ACME wiring. Tracked in MXS-576.
- Never run against a production PKI. Treat behaviour claims accordingly.

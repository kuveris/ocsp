# Test Evidence

## Commands

```powershell
& "C:\Program Files\Go\bin\go.exe" mod tidy
& "C:\Program Files\Go\bin\go.exe" test ./...
& "C:\Program Files\Go\bin\go.exe" test -tags integration ./...
```

## Latest Outcome

- `go test ./...`: pass
- `go test -tags integration ./...`: pass

## Coverage Highlights

- Protocol hardening checks:
  - OCSP issuer-binding validation
  - CRL authenticity verification against configured issuer
  - signer trust chain verification
- Reliability:
  - context-aware upstream calls and retries
  - defensive duration parsing
- Degraded-mode e2e:
  - `POST /` returns `Unknown` on upstream failure
  - `GET /{base64url}` returns `Unknown` on upstream failure
  - `/health` returns `503` when source becomes unhealthy

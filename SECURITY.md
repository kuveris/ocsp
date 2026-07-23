# Security Policy

## Reporting a vulnerability

Please do not open a public issue for a security vulnerability.

Report it privately through GitHub's
[private vulnerability reporting](https://github.com/kuveris/ocsp/security/advisories/new)
— the "Report a vulnerability" button under the Security tab.

Useful things to include: what an attacker can achieve, the configuration and
status source in use, and a reproduction if you have one.

This is a small project maintained on a best-effort basis. It is not a funded
security programme and there is no bounty — but reports will be read and acted
on, and you will be credited in the advisory unless you would rather not be.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| < 0.1 | No — no such release exists |

Pre-1.0, fixes go to the latest minor only. There are no backports.

## What counts

Things worth reporting:

- Any path that produces a `good` response for a revoked certificate
- Any way to make the responder sign a response for an issuer it is not
  configured for, or that bypasses issuer binding validation
- Anything that discloses the signing key or its material
- Forging or tampering with a response that clients would still accept
- Accepting a CRL that fails issuer or signature verification
- Remote crash or resource exhaustion from a crafted OCSP request

Things that are working as intended:

- **OCSP served over plain HTTP.** Responses are signed; the transport is not
  what makes them trustworthy. TLS is available but optional by design.
- **Responses are cached in memory.** They are signed and carry their own
  validity window, so a cached response cannot be forged into something else.
- **`unknown` returned when the status source fails.** This is the intended
  fail-closed behaviour, not an availability bug.
- **Request contents appearing in debug-level logs.** Debug logging is opt-in
  and OCSP requests are not secret.

## Operational notes

Two things that are your responsibility rather than the software's, and that
cause real incidents:

- **Signing key permissions.** `600`, owned by the service user. The key is
  never logged, but file permissions are not something this project can enforce.
- **Signing certificate expiry.** An expired signer takes the whole responder
  down. `ocsp_signer_days_until_expiry` is exported for exactly this reason —
  alert on it.

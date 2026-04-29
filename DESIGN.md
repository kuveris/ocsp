# ocsp-responder — Design Document

**Version:** 0.1.0-draft  
**Status:** Pre-implementation  
**Language:** Go 1.22+  
**Repo:** `github.com/hartmann-it/ocsp-responder`  

---

## 1. Projektbeschreibung

`ocsp-responder` ist ein eigenständiger, domain- und projektunabhängiger
OCSP-Responder (RFC 6960). Er ist nicht an Encromail, step-ca oder eine
spezifische CA-Software gebunden.

**Einsatzszenarien:**
- Interne PKI jeder Art (step-ca, OpenSSL CA, EJBCA, XCA, ...)
- Homelab mit eigener CA
- Als Sidecar neben einem beliebigen CA-Server
- Überall wo Mail-Clients, Browser oder andere TLS-Clients
  Zertifikatsstatus prüfen müssen

**Was der Responder nicht ist:**
- Kein CA-Server
- Kein Zertifikat-Manager
- Keine Anbindung an eine spezifische CA-Software
- Kein Revocation-Tool (Widerruf passiert in der CA — dieser Service antwortet nur)

---

## 2. Architektur

```
┌──────────────────────────────────────────────────┐
│              ocsp-responder                      │
│                                                  │
│  POST /   ← OCSP Request (DER)                   │
│  GET  /{base64} ← OCSP Request (RFC 6960 GET)    │
│                                                  │
│  ┌──────────────┐    ┌────────────────────────┐  │
│  │ HTTP Handler │───▶│  Responder Core        │  │
│  └──────────────┘    │  (cfssl/ocsp)          │  │
│                      └──────────┬─────────────┘  │
│                                 │                 │
│                      ┌──────────▼─────────────┐  │
│                      │  Status Source         │  │
│                      │  (pluggable interface) │  │
│                      └──────────┬─────────────┘  │
│                                 │                 │
│            ┌────────────────────┼──────────────┐ │
│            ▼                    ▼              ▼  │
│      ┌──────────┐        ┌──────────┐  ┌────────┐│
│      │  File    │        │  HTTP    │  │ Static ││
│      │  Source  │        │  Source  │  │ Source ││
│      │  (CRL)   │        │  (API)   │  │ (Test) ││
│      └──────────┘        └──────────┘  └────────┘│
└──────────────────────────────────────────────────┘
```

### Status Sources

Der Responder weiß von sich aus nicht ob ein Zertifikat gültig oder
widerrufen ist — das weiß die CA. Die **Status Source** ist das
Bindeglied. Sie ist ein Interface, hinter dem verschiedene Backends
stecken können:

| Source | Beschreibung | Wann sinnvoll |
|---|---|---|
| `file` | Liest eine CRL-Datei (PEM oder DER), Hot-Reload | step-ca, OpenSSL, jede CA mit CRL-Export |
| `http` | Fragt eine CA-REST-API ab | step-ca API, EJBCA, jede CA mit HTTP-API |
| `static` | Hardcodierte Antwort | Tests, Entwicklung |

Phase 1: `file` + `static`. Phase 2: `http`.

---

## 3. Projektstruktur

```
ocsp-responder/
├── cmd/
│   └── ocsp-responder/
│       └── main.go                  # Entrypoint
├── internal/
│   ├── config/
│   │   └── config.go                # Config structs + YAML loader
│   ├── source/
│   │   ├── source.go                # Source interface + shared types
│   │   ├── file.go                  # CRL-file backed Source
│   │   ├── file_test.go
│   │   ├── http.go                  # HTTP/REST API backed Source (Phase 2)
│   │   ├── http_test.go
│   │   └── static.go                # Static Source (immer good/revoked/unknown)
│   ├── signer/
│   │   ├── signer.go                # OCSP Signing Key + Cert laden
│   │   └── signer_test.go
│   ├── responder/
│   │   ├── responder.go             # cfssl/ocsp wrapper + in-memory cache
│   │   └── responder_test.go
│   └── server/
│       ├── server.go                # HTTP Server + graceful shutdown
│       └── handler.go               # POST + GET + /health Handler
├── config/
│   └── ocsp-responder.yaml          # Beispiel-Konfiguration
├── certs/
│   ├── .gitkeep
│   └── README.md                    # Erklärt welche Certs hier erwartet werden
├── DESIGN.md
├── go.mod
├── Makefile
└── .gitignore
```

---

## 4. Core Interface

```go
// internal/source/source.go
package source

import (
    "crypto/x509"
    "math/big"
    "time"
)

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
    GetStatus(serial *big.Int, issuer *x509.Certificate) (*CertStatus, error)

    // Name returns a human-readable identifier for this source (used in logs and /health).
    Name() string

    // Healthy returns true if the source is operational and up-to-date.
    Healthy() bool
}
```

---

## 5. Konfiguration

```yaml
# config/ocsp-responder.yaml

server:
  listen_addr: "0.0.0.0:8080"
  tls:
    enabled: false
    cert_file: ""
    key_file: ""

signer:
  # OCSP Delegated Signing Certificate + Key
  # Muss extKeyUsage OCSPSigning haben
  # Muss von derselben CA signiert sein wie die geprüften Zertifikate
  cert_file: "certs/ocsp-signer.crt"
  key_file:  "certs/ocsp-signer.key"

  # Intermediate CA Zertifikat (Issuer der zu prüfenden Zertifikate)
  issuer_cert_file: "certs/intermediate-ca.crt"

  # Gültigkeitsdauer einer ausgestellten OCSP Response (NextUpdate)
  response_validity: "24h"

source:
  type: "file"   # "file" | "http" | "static"

  file:
    crl_path: "certs/ca.crl"        # PEM oder DER
    reload_interval: "5m"           # Prüft auf Dateiänderung

  http:
    base_url: "https://ca.example.local:9000"
    root_cert_file: "certs/root-ca.crt"
    timeout: "10s"

  static:
    status: "good"   # "good" | "revoked" | "unknown"

cache:
  enabled: true
  ttl: "1h"
  max_entries: 10000

logging:
  level: "info"    # debug | info | warn | error
  format: "json"   # json | text
```

---

## 6. HTTP Endpunkte

```
POST /
  Content-Type: application/ocsp-request
  Body: DER-encoded OCSPRequest
  → 200 + Content-Type: application/ocsp-response
  → 400 bei malformed Request

GET /{base64url-encoded-request}
  → Selbe Logik, GET-Variante per RFC 6960 Section 5
  → Setzt Cache-Control Header für Proxy-Caching

GET /health
  → 200 + {"status":"ok","signer_valid":true,"source":"file","source_healthy":true}
  → 503 wenn Signer abgelaufen oder Source unhealthy
```

---

## 7. Abhängigkeiten

| Library | Zweck |
|---|---|
| `github.com/cloudflare/cfssl/ocsp` | OCSP Request/Response parsen, Response bauen, signieren |
| `crypto/x509` (stdlib) | Zertifikat-Handling, CRL-Parsing |
| `net/http` (stdlib) | HTTP Server |
| `gopkg.in/yaml.v3` | Config |
| `golang.org/x/crypto` | Crypto-Primitiven |

`cfssl/ocsp` übernimmt: DER-Parsing, Response-Building, Signing-Logik.
Eigencode beschränkt sich auf Source-Interface, Config, HTTP-Handler, Cache.

---

## 8. Implementierungsphasen

### Phase 1 — Funktionierender Responder mit CRL-Source

- [ ] `source.Source` Interface + shared types
- [ ] `source.Static`: konfigurierbare Antwort, für Tests
- [ ] `source.File`: CRL laden (PEM + DER), Serials indizieren, Hot-Reload
- [ ] `signer.Signer`: Key + Cert laden, OCSPSigning EKU validieren
- [ ] `responder.Responder`: cfssl-Wrapper + in-memory Cache mit TTL
- [ ] HTTP Handler: POST + GET (base64) + `/health`
- [ ] Graceful Shutdown (SIGTERM, 10s Timeout)
- [ ] Structured Logging: serial, status, source, cache_hit, duration_ms
- [ ] Tests (siehe Abschnitt 11)
- [ ] `certs/README.md`: erklärt welche Dateien erwartet werden und wie man sie erstellt

### Phase 2 — HTTP Source

- [ ] `source.HTTP`: generischer REST-Client
- [ ] Konfigurierbare Response-Interpretation
- [ ] TLS-Verifikation mit Root-Cert-Pinning
- [ ] Retry mit exponential Backoff

### Phase 3 — Hardening

- [ ] Signer-Cert Expiry-Monitoring (Log-Warnung X Tage vor Ablauf)
- [ ] Prometheus Metrics (`/metrics`)
- [ ] TLS für den HTTP-Server selbst
- [ ] Dockerfile
- [ ] systemd Unit-Datei Beispiel

---

## 9. Sicherheitshinweise

- OCSP Signing Key **niemals** loggen — auch nicht bei DEBUG
- `certs/` Verzeichnis komplett in `.gitignore`
- Signer-Key Dateiberechtigung: `600`, Owner: Service-User
- Bei Source-Fehler: **`StatusUnknown` zurückgeben, niemals `StatusGood` als Fallback**
- OCSP Responses sind signiert — Caching ist sicher und ausdrücklich erwünscht

---

## 10. Nutzung mit verschiedenen CAs

### step-ca + CRL

```bash
# CRL aus step-ca exportieren
step ca crl --out certs/ca.crl
# → source.type: "file", file.crl_path: "certs/ca.crl"
```

### OpenSSL CA

```bash
openssl ca -gencrl -out ca.crl.pem -config openssl.cnf
# Oder als DER:
openssl crl -in ca.crl.pem -outform DER -out certs/ca.crl
# → source.type: "file" — funktioniert mit PEM und DER
```

### Jede andere CA

Jede CA die eine CRL exportieren kann → `file` Source.
Jede CA mit HTTP API → `http` Source (Phase 2).

---

## 11. Tests

```
internal/source/file_test.go
  TestFileSource_Good          → Serial nicht in CRL → StatusGood
  TestFileSource_Revoked       → Serial in CRL → StatusRevoked + RevokedAt korrekt
  TestFileSource_Unknown       → CRL vorhanden aber Serial fehlt → StatusUnknown
  TestFileSource_Reload        → CRL-Datei ändert sich → neuer Status erkannt
  TestFileSource_InvalidCRL    → korrupte Datei → Fehler, kein Panic, Healthy()=false

internal/responder/responder_test.go
  TestHandle_Good              → gültiger Request → signierte Good-Response
  TestHandle_Revoked           → widerrufene Serial → signierte Revoked-Response
  TestHandle_Unknown           → unbekannte Serial → Unknown-Response
  TestHandle_MalformedRequest  → zufälliges DER → Fehler zurück
  TestHandle_SignatureValid    → Response mit Signer-Cert verifizierbar
  TestHandle_CacheHit          → zweiter Request → Source nur einmal befragt
  TestHandle_SourceError       → Source gibt error → Unknown, niemals Good

internal/signer/signer_test.go
  TestSigner_ValidCert         → korrektes OCSPSigning EKU → geladen
  TestSigner_MissingOCSPEKU   → falsches EKU → Fehler beim Laden
  TestSigner_ExpiredCert       → abgelaufenes Cert → geladlen aber Warnung geloggt
```

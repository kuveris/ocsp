# ocsp-responder — Phase 2 Plan

**Stand:** April 2026  
**Basiert auf:** Code-Review Phase 1 Output

---

## Phase 1 — Ehrliches Assessment

### ✅ Vollständig und funktional
- Source Interface + `FileSource` + `StaticSource`
- `Signer` mit EKU-Validierung und Key-Cert-Match
- `Responder` mit Cache, korrekte StatusUnknown-Fallback-Logik
- HTTP Server mit POST + GET + `/health`
- Graceful Shutdown
- Vollständige Tests ohne `t.Skip()`

### ⚠️ Bugs die vor Phase 2 gefixt werden müssen

| # | Problem | Datei | Schwere |
|---|---|---|---|
| B1 | `SignRequest.Certificate` ist `issuerCert` statt End-Entity-Cert | `internal/signer/signer.go` | Mittel — funktioniert zufällig, falsche Semantik |
| B2 | `cache.enabled: false` hat keinen Effekt — immer gecached | `internal/responder/responder.go` | Niedrig — Config-Feld ist wirkungslos |
| B3 | `go.mod` deklariert Go 1.25 (nicht existent) | `go.mod` | Niedrig |
| B4 | `TestSigner_ExpiredCert` fehlt (im DESIGN.md spezifiziert) | `internal/signer/signer_test.go` | Niedrig |
| B5 | `TestFileSource_Unknown` testet auf `StatusGood`, Name falsch | `internal/source/file_test.go` | Niedrig — nur Nomenklatur |

---

## Phase 2 Scope

### P2.1 — Bugfixes (zuerst)

Alle fünf Bugs aus der Tabelle oben beheben bevor neue Features.

**B1 Detail:** `cfocsp.SignRequest.Certificate` muss ein synthetisches
Zertifikat mit der richtigen SerialNumber sein, nicht der Issuer:

```go
// Statt:
req := cfocsp.SignRequest{Certificate: s.issuerCert, ...}

// Korrekt: synthetisches Cert mit korrekter Serial
template := &x509.Certificate{SerialNumber: serial}
req := cfocsp.SignRequest{Certificate: template, ...}
```

**B2 Detail:** `cache` struct bekommt ein `enabled bool` Feld.
`NewResponder` setzt es aus Config. `cache.set()` und `cache.get()` prüfen es.

---

### P2.2 — HTTP Source (`internal/source/http.go`)

Generischer REST-Client der eine CA-API nach Zertifikatsstatus befragt.
Keine Annahmen über das CA-Produkt — konfigurierbare Response-Interpretation.

```go
// HTTPSource fragt eine CA REST API ab.
// Konfigurierbar über response_mapping, damit verschiedene CA-APIs
// ohne Code-Änderungen unterstützt werden können.
type HTTPSource struct {
    baseURL    string
    httpClient *http.Client
    rootCert   *x509.CertPool   // für TLS-Pinning
    mapping    ResponseMapping
    cache      sync.Map          // serial → cachedHTTPResult
    cacheTTL   time.Duration
}

// ResponseMapping beschreibt wie die CA-Antwort interpretiert wird.
type ResponseMapping struct {
    // HTTP-Pfad der abgefragt wird: baseURL + "/certificates/" + serial (hex)
    // Konfigurierbar für verschiedene CA-APIs
    PathTemplate string `yaml:"path_template"`  // default: "/1.0/certificates/{serial}"

    // JSON-Pfad zum Status-Feld in der Antwort
    StatusField  string `yaml:"status_field"`   // default: "status"

    // Mapping von CA-Werten auf OCSP-Status
    GoodValues   []string `yaml:"good_values"`    // default: ["active", "valid"]
    RevokedValues []string `yaml:"revoked_values"` // default: ["revoked"]
    // Alle anderen Werte → StatusUnknown
}
```

Implementierung:
```
1. URL bauen: PathTemplate mit serial (hex) interpolieren
2. HTTP GET mit konfig. Timeout
3. Status-Code 404 → StatusUnknown (Cert unbekannt)
4. Status-Code 200 → JSON parsen, StatusField auslesen, Wert mappen
5. Bei Fehler: error zurück (Responder mappt zu StatusUnknown)
6. Ergebnis in In-Memory-Cache (TTL konfigurierbar)
7. Retry mit exponential Backoff (max 3 Versuche)
```

Config-Ergänzung:
```yaml
source:
  type: "http"
  http:
    base_url: "https://ca.example.local:9000"
    root_cert_file: "certs/root-ca.crt"   # TLS-Pinning, optional
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

Tests (`internal/source/http_test.go`):
```
TestHTTPSource_Good       → httptest.Server → 200 mit good_value → StatusGood
TestHTTPSource_Revoked    → 200 mit revoked_value → StatusRevoked
TestHTTPSource_Unknown    → 404 → StatusUnknown
TestHTTPSource_ServerError → 500 → error
TestHTTPSource_Timeout    → hängender Server → timeout error
TestHTTPSource_Retry      → erste zwei Requests schlagen fehl → dritter erfolgreich
TestHTTPSource_TLSPinning → falsches Cert → TLS-Fehler
TestHTTPSource_CacheHit   → zwei Requests für selbe Serial → Server nur einmal befragt
```

---

### P2.3 — Signer Cert Expiry Monitoring

Der Signer sollte proaktiv warnen wenn sein Cert bald abläuft.
Aktuell gibt es `Valid()` (boolean) aber keine gestaffelte Vorwarnung.

```go
// ExpiryStatus beschreibt wie nah der Signer am Ablauf ist.
type ExpiryStatus int

const (
    ExpiryOK      ExpiryStatus = iota // > 30 Tage verbleibend
    ExpiryWarning                     // 8–30 Tage verbleibend
    ExpiryCritical                    // < 8 Tage verbleibend
    ExpiryExpired                     // abgelaufen
)

func (s *Signer) ExpiryStatus() ExpiryStatus
func (s *Signer) DaysUntilExpiry() int
```

Background-Goroutine in `signer.go` die alle 24h prüft und loggt:
```
> 30 Tage:  kein Log
8–30 Tage: slog.Warn("OCSP signer certificate expires soon", "days", n)
< 8 Tage:  slog.Error("OCSP signer certificate expires very soon", "days", n)
Abgelaufen: slog.Error("OCSP signer certificate EXPIRED")
```

`/health` Endpunkt erweitern:
```json
{
  "status": "ok",
  "signer_valid": true,
  "signer_expires_in_days": 45,
  "signer_expiry_status": "ok",
  "source": "file",
  "source_healthy": true
}
```

---

### P2.4 — Prometheus Metrics (`GET /metrics`)

Standard `prometheus/client_golang` Metrics:

```go
// Counters
ocsp_requests_total{method="POST|GET", status="good|revoked|unknown|error"}

// Histograms
ocsp_request_duration_seconds{method="POST|GET"}

// Gauges
ocsp_cache_entries           // aktuelle Cache-Größe
ocsp_cache_hit_ratio         // Cache-Trefferquote (rollierendes Fenster)
ocsp_signer_days_until_expiry

// Source-spezifisch
ocsp_source_requests_total{source="file|http|static", result="ok|error"}
ocsp_source_crl_last_reload_timestamp_seconds  // nur file source
```

`/metrics` Endpunkt in `server.go` registrieren:
```go
mux.Handle("GET /metrics", promhttp.Handler())
```

Neue Dependency: `github.com/prometheus/client_golang`

---

### P2.5 — TLS für den HTTP Server

Wenn `server.tls.enabled: true`:

```go
if cfg.Server.TLS.Enabled {
    httpServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
    return httpServer.ListenAndServeTLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
}
return httpServer.ListenAndServe()
```

ACME-Kompatibilität: wenn `cert_file` leer aber `acme_host` konfiguriert →
`golang.org/x/crypto/acme/autocert` für automatisches Cert via ACME-Server.

Config-Ergänzung:
```yaml
server:
  tls:
    enabled: true
    cert_file: "certs/server.crt"
    key_file: "certs/server.key"
    acme_host: ""           # optional: "ocsp.example.local" für ACME
    acme_ca_url: ""         # optional: interne ACME CA (step-ca)
    min_version: "1.2"      # "1.2" | "1.3"
```

---

### P2.6 — Dockerfile

Minimales Multi-Stage Dockerfile:

```dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY . .
RUN go build -o ocsp-responder ./cmd/ocsp-responder

FROM alpine:latest
RUN adduser -D -H ocsp
COPY --from=builder /build/ocsp-responder /usr/local/bin/
USER ocsp
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/ocsp-responder"]
CMD ["--config", "/etc/ocsp-responder/ocsp-responder.yaml"]
```

Dazu `docker-compose.yaml` Beispiel mit Volume-Mounts für `certs/` und `config/`.

---

### P2.7 — systemd Unit Beispiel

```ini
# /etc/systemd/system/ocsp-responder.service
[Unit]
Description=OCSP Responder
After=network.target

[Service]
Type=simple
User=ocsp
Group=ocsp
ExecStart=/usr/local/bin/ocsp-responder --config /etc/ocsp-responder/ocsp-responder.yaml
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/log/ocsp-responder
ReadOnlyPaths=/etc/ocsp-responder /etc/ssl

[Install]
WantedBy=multi-user.target
```

Als `examples/systemd/ocsp-responder.service` ins Repo.

---

## Implementierungsreihenfolge

```
Woche 1: P2.1 (Bugfixes) — MUSS zuerst, bevor alles andere
Woche 2: P2.2 (HTTP Source) — Kern-Feature, größter Aufwand
Woche 3: P2.3 (Expiry Monitoring) + P2.4 (Metrics)
Woche 4: P2.5 (TLS) + P2.6 (Dockerfile) + P2.7 (systemd)
```

---

## Neue Dependencies

| Library | Zweck |
|---|---|
| `github.com/prometheus/client_golang` | Metrics |
| `golang.org/x/crypto/acme/autocert` | ACME TLS (optional) |

Keine neuen Dependencies für HTTP Source — `net/http` + `crypto/tls` reichen.

---

## Success Criteria Phase 2

- [ ] Alle 5 Bugs aus Phase 1 Review behoben
- [ ] `make test` — alle Tests grün inkl. neue HTTP Source Tests
- [ ] `source.type: "http"` funktioniert mit Mock-CA
- [ ] `GET /metrics` liefert Prometheus-kompatible Ausgabe
- [ ] `GET /health` enthält `signer_expires_in_days`
- [ ] OCSP Signer Expiry-Warning erscheint 30 Tage vor Ablauf im Log
- [ ] TLS für Server konfigurierbar
- [ ] Dockerfile baut und startet den Service
- [ ] systemd Unit Beispiel vorhanden
- [ ] `go.mod` deklariert Go 1.22 (nicht 1.25)
- [ ] `cache.enabled: false` deaktiviert tatsächlich das Caching

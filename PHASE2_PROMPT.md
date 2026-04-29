# ocsp-responder — Copilot Workspace Prompt (Phase 2)

## Setup

1. copilot-workspace.githubnext.com → `ocsp-responder` Repo öffnen
2. „New Task" → Text ab `## TASK` einfügen → „Create Plan" → „Implement"

---

## TASK

Read `DESIGN.md` and `PHASE2_PLAN.md` in this repository fully before writing any code.

**CRITICAL: Fix all Phase 1 bugs first (Part A). Do not start Part B until Part A is complete and all tests pass.**

This project is domain- and CA-agnostic. No references to Encromail, step-ca, or any specific CA in code or comments.

---

## PART A — Phase 1 Bugfixes (zuerst, vollständig)

### A1 — `go.mod`: Go Version korrigieren

```
go 1.22
```
Ändere `go 1.25.0` → `go 1.22`. Keine andere Änderung.

---

### A2 — `internal/signer/signer.go`: `SignRequest.Certificate` korrigieren

**Problem:** `req.Certificate` ist auf `s.issuerCert` gesetzt. Das ist semantisch falsch.
cfssl's `SignRequest.Certificate` erwartet ein Zertifikat das die SerialNumber
des zu prüfenden Zertifikats trägt — nicht den Issuer.

**Fix:** Synthetisches Zertifikat mit korrekter Serial erstellen:

```go
// Ersetze:
req := cfocsp.SignRequest{
    Certificate: s.issuerCert,
    ...
}

// Durch:
template := &x509.Certificate{SerialNumber: serial}
req := cfocsp.SignRequest{
    Certificate: template,
    Status:      ocspStatus,
    Reason:      reason,
    RevokedAt:   revokedAt,
    ThisUpdate:  &thisUpdate,
    NextUpdate:  &nextUpdate,
}
```

Vergewissere dich dass alle bestehenden Tests in `signer_test.go` und
`responder_test.go` nach dem Fix noch grün sind.

---

### A3 — `internal/responder/responder.go`: `cache.enabled` honorieren

**Problem:** Das Config-Feld `cache.enabled` wird nie ausgewertet. Caching
ist immer aktiv unabhängig von der Konfiguration.

**Fix:** `NewResponder` bekommt einen `enabled bool` Parameter, alternativ:
`cache` struct erhält ein `enabled` Feld:

```go
type cache struct {
    mu         sync.RWMutex
    entries    map[string]*cacheEntry
    ttl        time.Duration
    maxEntries int
    enabled    bool   // NEU: wenn false, get() gibt immer false zurück, set() tut nichts
}
```

`NewResponder` in `main.go` übergibt `cfg.Cache.Enabled`.
Passe `NewResponder`-Signatur entsprechend an — es ist ein internes Paket,
Breaking Change ist akzeptabel.

---

### A4 — `internal/signer/signer_test.go`: fehlenden Test hinzufügen

Füge `TestSigner_ExpiredCert` hinzu:

```go
func TestSigner_ExpiredCert(t *testing.T) {
    // Erstelle ein OCSP-Signer-Cert das bereits abgelaufen ist:
    // NotBefore: time.Now().Add(-48 * time.Hour)
    // NotAfter:  time.Now().Add(-1 * time.Hour)   ← bereits abgelaufen
    // ExtKeyUsage: OCSPSigning

    // NewSigner darf KEINEN Fehler zurückgeben — abgelaufenes Cert wird geladen
    // aber eine Warnung wird geloggt.
    // Stattdessen: signer.Valid() muss false zurückgeben.
    s, err := NewSigner(expiredCertPath, expiredKeyPath, issuerCertPath, time.Hour)
    if err != nil {
        t.Fatalf("expected no error, got %v", err)
    }
    if s.Valid() {
        t.Fatal("expected Valid() = false for expired cert")
    }
}
```

Generiere das expired Cert in `TestMain` analog zu den anderen Test-Certs.

---

### A5 — `internal/source/file_test.go`: Testname korrigieren

Benenne `TestFileSource_Unknown` um in `TestFileSource_NotInCRL`:

```go
// Vor: TestFileSource_Unknown
// Nach: TestFileSource_NotInCRL
// Kommentar: Serial not in CRL → StatusGood (CRL is authoritative)
func TestFileSource_NotInCRL(t *testing.T) { ... }
```

Der Test selbst bleibt unverändert — nur der Name.

---

### A6 — Verifiziere Part A vollständig

Fahre erst mit Part B fort wenn:
- [ ] `make build` → kein Fehler
- [ ] `make test` → alle Tests grün
- [ ] `go.mod` zeigt `go 1.22`
- [ ] `TestSigner_ExpiredCert` läuft durch
- [ ] `TestFileSource_NotInCRL` existiert und läuft durch

---

## PART B — Phase 2 Features (nur nach Part A)

### B1 — `internal/source/http.go`: HTTP Source implementieren

Implementiere `HTTPSource` — einen konfigurierbaren REST-Client für CA-APIs.

```go
package source

// ResponseMapping beschreibt wie die CA-API-Antwort interpretiert wird.
type ResponseMapping struct {
    PathTemplate  string   `yaml:"path_template"`   // default: "/1.0/certificates/{serial}"
    StatusField   string   `yaml:"status_field"`    // default: "status"
    GoodValues    []string `yaml:"good_values"`     // default: ["active", "valid"]
    RevokedValues []string `yaml:"revoked_values"`  // default: ["revoked"]
}

// HTTPSource fragt eine CA REST API nach Zertifikatsstatus ab.
// Implementiert das Source Interface.
// Ist safe for concurrent use.
type HTTPSource struct {
    baseURL    string
    httpClient *http.Client
    mapping    ResponseMapping
    retryCfg   retryConfig
    cache      *httpCache    // in-memory, TTL-basiert, sync.Map
}

type retryConfig struct {
    maxAttempts int
    backoff     time.Duration
}
```

Konstruktor:
```go
// NewHTTPSource erstellt eine HTTPSource.
// rootCertFile: optional, Pfad zu PEM-CA-Cert für TLS-Pinning.
//               Leer = Standard System-Truststore.
func NewHTTPSource(baseURL, rootCertFile string, timeout time.Duration, mapping ResponseMapping, maxRetries int, retryBackoff time.Duration, cacheTTL time.Duration) (*HTTPSource, error)

func (s *HTTPSource) GetStatus(serial *big.Int, issuer *x509.Certificate) (*CertStatus, error)
func (s *HTTPSource) Name() string    // returns "http"
func (s *HTTPSource) Healthy() bool   // true wenn letzter Request erfolgreich
```

`GetStatus` Logik:
```
1. Cache prüfen (serial.String() als Key) → bei Hit: gecachtes Ergebnis
2. URL bauen: PathTemplate mit serial (hex, uppercase) interpolieren
   z.B. "/1.0/certificates/{serial}" → "/1.0/certificates/2A3F..."
3. HTTP GET mit Timeout
4. HTTP 404 → return &CertStatus{Status: StatusUnknown}, nil
5. HTTP 200 → JSON parsen → StatusField auslesen
   - Wert in GoodValues?    → StatusGood
   - Wert in RevokedValues? → StatusRevoked (RevokedAt: time.Now(), Reason: 0)
   - Sonst:                 → StatusUnknown
6. Anderer Status-Code → retry mit exponential Backoff
7. Alle Versuche fehlgeschlagen → return nil, error
8. Ergebnis in Cache (TTL aus Config)
9. Healthy() = true nach erfolgreichem Request, false nach Fehler
```

Defaults wenn ResponseMapping-Felder leer:
```go
const (
    defaultPathTemplate  = "/1.0/certificates/{serial}"
    defaultStatusField   = "status"
)
var defaultGoodValues    = []string{"active", "valid"}
var defaultRevokedValues = []string{"revoked"}
```

**Tests** in `internal/source/http_test.go` (verwende `net/http/httptest`):

```
TestHTTPSource_Good          → httptest.Server gibt 200 + good_value → StatusGood
TestHTTPSource_Revoked       → 200 + revoked_value → StatusRevoked
TestHTTPSource_NotFound      → 404 → StatusUnknown (kein Fehler)
TestHTTPSource_ServerError   → 500 → error nach allen Retries
TestHTTPSource_Timeout       → hängender Server → context deadline exceeded
TestHTTPSource_RetrySuccess  → erste zwei Requests geben 500, dritter 200 → StatusGood
TestHTTPSource_CustomMapping → eigenes StatusField + GoodValues → korrekt gemappt
TestHTTPSource_CacheHit      → zwei Requests für selbe Serial → Server nur einmal gefragt
TestHTTPSource_TLSPinning    → Server mit self-signed Cert, rootCertFile gesetzt → Verbindung OK
                               Server ohne rootCertFile → TLS-Fehler
```

---

### B2 — `internal/signer/signer.go`: Expiry Monitoring erweitern

Ergänze `Signer` um gestaffelte Expiry-Erkennung:

```go
// ExpiryStatus beschreibt wie nah der Signer am Ablauf ist.
type ExpiryStatus int

const (
    ExpiryOK       ExpiryStatus = iota // > 30 Tage verbleibend
    ExpiryWarning                      // 8–30 Tage verbleibend
    ExpiryCritical                     // < 8 Tage verbleibend
    ExpiryExpired                      // abgelaufen
)

// ExpiryStatus gibt den aktuellen Ablaufstatus zurück.
func (s *Signer) ExpiryStatus() ExpiryStatus

// DaysUntilExpiry gibt verbleibende Tage bis zum Ablauf zurück (negativ wenn abgelaufen).
func (s *Signer) DaysUntilExpiry() int
```

Background-Goroutine die `Signer` alle 24h prüft und entsprechend loggt:
```go
// StartExpiryMonitor startet eine Goroutine die alle 24h den Signer-Cert-Status loggt.
// Beendet sich wenn ctx abgebrochen wird.
func (s *Signer) StartExpiryMonitor(ctx context.Context, logger *slog.Logger)
```

Logging-Verhalten:
```
ExpiryOK:       kein Log
ExpiryWarning:  slog.Warn("OCSP signer certificate expires soon", "days", n)
ExpiryCritical: slog.Error("OCSP signer certificate expires very soon", "days", n)
ExpiryExpired:  slog.Error("OCSP signer certificate is EXPIRED")
```

`main.go` ruft `sgn.StartExpiryMonitor(ctx, logger)` nach dem Start auf.
Übergib einen Context der auf SIGTERM reagiert.

Erweitere `/health` Response in `handler.go`:
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

`signer_expiry_status` Werte: `"ok"`, `"warning"`, `"critical"`, `"expired"`

---

### B3 — Prometheus Metrics (`GET /metrics`)

Füge `github.com/prometheus/client_golang` als Dependency hinzu.

Erstelle `internal/server/metrics.go`:

```go
package server

import "github.com/prometheus/client_golang/prometheus"

// Metrics hält alle registrierten Prometheus-Metriken.
type Metrics struct {
    RequestsTotal   *prometheus.CounterVec
    RequestDuration *prometheus.HistogramVec
    CacheEntries    prometheus.Gauge
    CacheHits       prometheus.Counter
    CacheMisses     prometheus.Counter
    SignerDaysLeft  prometheus.Gauge
    SourceRequests  *prometheus.CounterVec
}

// NewMetrics registriert und gibt alle Metriken zurück.
func NewMetrics() *Metrics
```

Labels:
- `RequestsTotal`: `{method="post|get", status="good|revoked|unknown|error"}`
- `RequestDuration`: `{method="post|get"}`
- `SourceRequests`: `{source="file|http|static", result="ok|error"}`

In `server.go` registrieren:
```go
mux.Handle("GET /metrics", promhttp.Handler())
```

`Responder.Handle()` bekommt ein optionales `*Metrics` Feld — wenn nil, kein Metriken-Update.
`NewResponder` Signatur um `metrics *Metrics` erweitern (nil = disabled).

---

### B4 — TLS für den HTTP Server

In `server.go`, `Start()` Methode:

```go
if s.cfg.Server.TLS.Enabled {
    if s.cfg.Server.TLS.CertFile == "" || s.cfg.Server.TLS.KeyFile == "" {
        return fmt.Errorf("ocsp-responder/server: TLS enabled but cert_file or key_file not set")
    }
    tlsCfg := &tls.Config{
        MinVersion: tls.VersionTLS12,
    }
    httpServer.TLSConfig = tlsCfg
    s.logger.Info("OCSP responder listening (TLS)", "addr", s.cfg.Server.ListenAddr)
    errCh <- httpServer.ListenAndServeTLS(s.cfg.Server.TLS.CertFile, s.cfg.Server.TLS.KeyFile)
} else {
    s.logger.Info("OCSP responder listening", "addr", s.cfg.Server.ListenAddr)
    errCh <- httpServer.ListenAndServe()
}
```

Config-Ergänzung in `config.go` (`TLSConfig` struct):
```go
type TLSConfig struct {
    Enabled    bool   `yaml:"enabled"`
    CertFile   string `yaml:"cert_file"`
    KeyFile    string `yaml:"key_file"`
    MinVersion string `yaml:"min_version"`  // "1.2" | "1.3", default "1.2"
}
```

---

### B5 — Dockerfile + docker-compose

Erstelle `Dockerfile`:

```dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o ocsp-responder ./cmd/ocsp-responder

FROM alpine:3.19
RUN apk --no-cache add ca-certificates && \
    addgroup -S ocsp && adduser -S -G ocsp ocsp
COPY --from=builder /build/ocsp-responder /usr/local/bin/
USER ocsp
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/ocsp-responder"]
CMD ["--config", "/etc/ocsp-responder/ocsp-responder.yaml"]
```

Erstelle `docker-compose.yaml` (Beispiel):

```yaml
services:
  ocsp-responder:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./config:/etc/ocsp-responder:ro
      - ./certs:/certs:ro
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:8080/health"]
      interval: 30s
      timeout: 5s
      retries: 3
```

---

### B6 — systemd Unit

Erstelle `examples/systemd/ocsp-responder.service`:

```ini
[Unit]
Description=OCSP Responder
Documentation=https://github.com/hartmann-it/ocsp-responder
After=network.target

[Service]
Type=simple
User=ocsp
Group=ocsp
ExecStart=/usr/local/bin/ocsp-responder --config /etc/ocsp-responder/ocsp-responder.yaml
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/ocsp-responder
ReadOnlyPaths=/etc/ocsp-responder /etc/ssl/certs

[Install]
WantedBy=multi-user.target
```

Erstelle `examples/systemd/README.md` mit Installationsanleitung:
```
1. Binary nach /usr/local/bin/ kopieren
2. Config nach /etc/ocsp-responder/ocsp-responder.yaml kopieren
3. Certs nach /certs/ kopieren
4. useradd -r -s /usr/sbin/nologin ocsp
5. systemctl enable --now ocsp-responder
```

---

### B7 — `config.go` + `encromail.yaml`: HTTP Source Config ergänzen

Ergänze `HTTPSourceConfig` in `config.go`:

```go
type HTTPSourceConfig struct {
    BaseURL      string          `yaml:"base_url"`
    RootCertFile string          `yaml:"root_cert_file"`
    Timeout      string          `yaml:"timeout"`
    RetryMax     int             `yaml:"retry_max"`
    RetryBackoff string          `yaml:"retry_backoff"`
    CacheTTL     string          `yaml:"cache_ttl"`
    Mapping      ResponseMapping `yaml:"response_mapping"`
}

type ResponseMapping struct {
    PathTemplate  string   `yaml:"path_template"`
    StatusField   string   `yaml:"status_field"`
    GoodValues    []string `yaml:"good_values"`
    RevokedValues []string `yaml:"revoked_values"`
}
```

Aktualisiere Validation in `config.go` für `source.type: "http"`:
- `base_url` required
- `timeout` required und parseable als Duration
- `retry_backoff` optional, default `"500ms"` wenn leer
- `retry_max` optional, default `3` wenn 0

Aktualisiere `config/ocsp-responder.yaml` Beispiel mit neuen Feldern.

Aktualisiere `main.go`: `newSource()` für `"http"` implementieren statt Error.

---

## Hard Constraints

- Kein Code der Encromail, step-ca oder andere spezifische Produkte referenziert
- `StatusGood` nie als Fallback bei Fehlern — immer `StatusUnknown`
- Private Keys nie loggen
- Kein Panic in Library-Code
- Error Wrapping: `fmt.Errorf("ocsp-responder/<pkg>: %w", err)`
- Tests neben Implementation

## Definition of Done Phase 2

- [ ] `make build` → kein Fehler, `go 1.22` im go.mod
- [ ] `make test` → alle Tests grün inkl. neue HTTP Source Tests
- [ ] `TestSigner_ExpiredCert` existiert und läuft durch
- [ ] `TestFileSource_NotInCRL` existiert (umbenannt)
- [ ] `cache.enabled: false` deaktiviert tatsächlich das Caching
- [ ] `source.type: "http"` startet ohne "not yet implemented" Fehler
- [ ] `GET /metrics` liefert Prometheus-kompatible Ausgabe
- [ ] `GET /health` enthält `signer_expires_in_days` und `signer_expiry_status`
- [ ] Signer Expiry Warnung erscheint im Log wenn < 30 Tage verbleiben
- [ ] TLS für Server konfigurierbar und funktionsfähig
- [ ] `Dockerfile` baut erfolgreich
- [ ] `docker-compose.yaml` und `examples/systemd/` vorhanden

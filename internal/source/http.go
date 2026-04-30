package source

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultPathTemplate  = "/1.0/certificates/{serial}"
	defaultStatusField   = "status"
)

var (
	defaultGoodValues    = []string{"active", "valid"}
	defaultRevokedValues = []string{"revoked"}
)

// ResponseMapping describes how to interpret a CA REST API response.
type ResponseMapping struct {
	PathTemplate  string   `yaml:"path_template"`
	StatusField   string   `yaml:"status_field"`
	GoodValues    []string `yaml:"good_values"`
	RevokedValues []string `yaml:"revoked_values"`
}

type retryConfig struct {
	maxAttempts int
	backoff     time.Duration
}

type httpCacheEntry struct {
	status    *CertStatus
	expiresAt time.Time
}

// HTTPSource queries a CA REST API for certificate status.
// It is safe for concurrent use.
type HTTPSource struct {
	baseURL    string
	httpClient *http.Client
	mapping    ResponseMapping
	retryCfg   retryConfig
	cache      sync.Map // serial string → *httpCacheEntry
	cacheTTL   time.Duration
	healthy    atomic.Bool
}

// NewHTTPSource creates an HTTPSource.
// rootCertFile: optional path to a PEM CA certificate for TLS pinning.
// An empty rootCertFile uses the system trust store.
func NewHTTPSource(baseURL, rootCertFile string, timeout time.Duration, mapping ResponseMapping, maxRetries int, retryBackoff time.Duration, cacheTTL time.Duration) (*HTTPSource, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("ocsp-responder/source: HTTPSource requires a non-empty base URL")
	}

	// Apply defaults to mapping.
	if mapping.PathTemplate == "" {
		mapping.PathTemplate = defaultPathTemplate
	}
	if mapping.StatusField == "" {
		mapping.StatusField = defaultStatusField
	}
	if len(mapping.GoodValues) == 0 {
		mapping.GoodValues = defaultGoodValues
	}
	if len(mapping.RevokedValues) == 0 {
		mapping.RevokedValues = defaultRevokedValues
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if rootCertFile != "" {
		pem, err := os.ReadFile(rootCertFile)
		if err != nil {
			return nil, fmt.Errorf("ocsp-responder/source: reading root cert file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ocsp-responder/source: no valid PEM certificates found in %s", rootCertFile)
		}
		tlsCfg.RootCAs = pool
	}

	transport := &http.Transport{TLSClientConfig: tlsCfg}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	if maxRetries <= 0 {
		maxRetries = 3
	}
	if retryBackoff <= 0 {
		retryBackoff = 500 * time.Millisecond
	}

	s := &HTTPSource{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: client,
		mapping:    mapping,
		retryCfg:   retryConfig{maxAttempts: maxRetries, backoff: retryBackoff},
		cacheTTL:   cacheTTL,
	}
	return s, nil
}

// Name returns the source identifier.
func (s *HTTPSource) Name() string { return "http" }

// Healthy returns true if the last request succeeded.
func (s *HTTPSource) Healthy() bool { return s.healthy.Load() }

// GetStatus returns the revocation status of the certificate with the given serial.
func (s *HTTPSource) GetStatus(serial *big.Int, issuer *x509.Certificate) (*CertStatus, error) {
	_ = issuer

	key := serial.String()

	// Check cache.
	if v, ok := s.cache.Load(key); ok {
		entry := v.(*httpCacheEntry)
		if time.Now().Before(entry.expiresAt) {
			return entry.status, nil
		}
		s.cache.Delete(key)
	}

	// Build URL: interpolate {serial} with uppercase hex serial number.
	path := strings.ReplaceAll(s.mapping.PathTemplate, "{serial}", strings.ToUpper(serial.Text(16)))
	url := s.baseURL + path

	cs, err := s.fetchWithRetry(url)
	if err != nil {
		s.healthy.Store(false)
		return nil, err
	}

	s.healthy.Store(true)

	// Cache result.
	if s.cacheTTL > 0 {
		s.cache.Store(key, &httpCacheEntry{status: cs, expiresAt: time.Now().Add(s.cacheTTL)})
	}

	return cs, nil
}

func (s *HTTPSource) fetchWithRetry(url string) (*CertStatus, error) {
	var lastErr error
	backoff := s.retryCfg.backoff

	for attempt := 0; attempt < s.retryCfg.maxAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff)
			backoff *= 2
		}

		cs, retry, err := s.fetchOnce(url)
		if err == nil {
			return cs, nil
		}
		if !retry {
			return nil, err
		}
		lastErr = err
	}
	return nil, fmt.Errorf("ocsp-responder/source: all %d attempts failed: %w", s.retryCfg.maxAttempts, lastErr)
}

// fetchOnce performs a single HTTP GET.
// Returns (result, shouldRetry, error).
func (s *HTTPSource) fetchOnce(url string) (*CertStatus, bool, error) {
	resp, err := s.httpClient.Get(url) //nolint:noctx
	if err != nil {
		return nil, true, fmt.Errorf("ocsp-responder/source: http get: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return &CertStatus{Status: StatusUnknown}, false, nil
	case http.StatusOK:
		// Parse JSON response.
		var body map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return nil, false, fmt.Errorf("ocsp-responder/source: decoding response: %w", err)
		}
		val, ok := body[s.mapping.StatusField]
		if !ok {
			return &CertStatus{Status: StatusUnknown}, false, nil
		}
		strVal, _ := val.(string)
		if contains(s.mapping.GoodValues, strVal) {
			return &CertStatus{Status: StatusGood}, false, nil
		}
		if contains(s.mapping.RevokedValues, strVal) {
			return &CertStatus{
				Status:         StatusRevoked,
				RevocationInfo: &RevocationInfo{RevokedAt: time.Now(), Reason: 0},
			}, false, nil
		}
		return &CertStatus{Status: StatusUnknown}, false, nil
	default:
		return nil, true, fmt.Errorf("ocsp-responder/source: unexpected status code %d", resp.StatusCode)
	}
}

func contains(list []string, val string) bool {
	for _, v := range list {
		if v == val {
			return true
		}
	}
	return false
}

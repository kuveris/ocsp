package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server  ServerConfig  `yaml:"server"`
	Signer  SignerConfig  `yaml:"signer"`
	Source  SourceConfig  `yaml:"source"`
	Cache   CacheConfig   `yaml:"cache"`
	Logging LoggingConfig `yaml:"logging"`
}

type ServerConfig struct {
	ListenAddr string    `yaml:"listen_addr"`
	TLS        TLSConfig `yaml:"tls"`
}

type TLSConfig struct {
	Enabled    bool   `yaml:"enabled"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	MinVersion string `yaml:"min_version"` // "1.2" | "1.3", default "1.2"
	ACMEHost   string `yaml:"acme_host"`   // optional: hostname for ACME certificate
	ACMECAUrl  string `yaml:"acme_ca_url"` // optional: ACME directory URL (for internal CAs)
	// ACMECacheDir is where issued certificates are persisted. Optional;
	// defaults to server.DefaultACMECacheDir. Must be writable by the service
	// user, or ACME certificates are re-ordered on every restart.
	ACMECacheDir string `yaml:"acme_cache_dir"`
}

type SignerConfig struct {
	CertFile         string `yaml:"cert_file"`
	KeyFile          string `yaml:"key_file"`
	IssuerCertFile   string `yaml:"issuer_cert_file"`
	ResponseValidity string `yaml:"response_validity"`
}

type SourceConfig struct {
	Type   string             `yaml:"type"`
	File   FileSourceConfig   `yaml:"file"`
	HTTP   HTTPSourceConfig   `yaml:"http"`
	Static StaticSourceConfig `yaml:"static"`
}

type FileSourceConfig struct {
	CRLPath        string `yaml:"crl_path"`
	ReloadInterval string `yaml:"reload_interval"`
	// ExpiryGrace keeps a CRL usable past its NextUpdate. Optional; empty
	// means strict, so an expired CRL is refused and answers become unknown.
	ExpiryGrace string `yaml:"expiry_grace"`
}

type HTTPSourceConfig struct {
	BaseURL      string          `yaml:"base_url"`
	RootCertFile string          `yaml:"root_cert_file"`
	Timeout      string          `yaml:"timeout"`
	RetryMax     int             `yaml:"retry_max"`
	RetryBackoff string          `yaml:"retry_backoff"`
	CacheTTL     string          `yaml:"cache_ttl"`
	Mapping      ResponseMapping `yaml:"response_mapping"`
}

// ResponseMapping describes how to interpret CA API responses.
type ResponseMapping struct {
	PathTemplate  string   `yaml:"path_template"`
	StatusField   string   `yaml:"status_field"`
	GoodValues    []string `yaml:"good_values"`
	RevokedValues []string `yaml:"revoked_values"`
}

type StaticSourceConfig struct {
	Status string `yaml:"status"`
}

type CacheConfig struct {
	Enabled    bool   `yaml:"enabled"`
	TTL        string `yaml:"ttl"`
	MaxEntries int    `yaml:"max_entries"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ocsp-responder/config: %w", err)
	}

	// KnownFields makes a misspelled key an error rather than a silent no-op.
	// Without it `cache.enabeld: true` leaves the cache off and `crl_path`
	// under a typo'd parent points at nothing, with the result indistinguishable
	// from never having set the field — which for a revocation service means
	// running a configuration nobody intended.
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("ocsp-responder/config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// DefaultListenAddr is used when server.listen_addr is omitted.
//
// Without an explicit default, an empty address reaches http.Server, which
// binds :80 — privileged, and rarely what anyone omitting the field intended.
// 8080 matches the shipped example config, the Dockerfile's EXPOSE, and both
// Compose stacks, so the documented port and the actual one agree.
//
// This is the port *inside* the container. Host-side collisions are avoided by
// OCSP_PORT in the Compose files, which is where two projects on one machine
// would actually contend.
const DefaultListenAddr = "0.0.0.0:8080"

func (c *Config) validate() error {
	if c.Server.ListenAddr == "" {
		c.Server.ListenAddr = DefaultListenAddr
	}
	if c.Signer.CertFile == "" {
		return errors.New("ocsp-responder/config: signer.cert_file must be set")
	}
	if c.Signer.KeyFile == "" {
		return errors.New("ocsp-responder/config: signer.key_file must be set")
	}
	if c.Signer.IssuerCertFile == "" {
		return errors.New("ocsp-responder/config: signer.issuer_cert_file must be set")
	}

	switch c.Source.Type {
	case "file":
		if c.Source.File.CRLPath == "" {
			return errors.New("ocsp-responder/config: source.file.crl_path must be set when source.type is 'file'")
		}
		if c.Source.File.ReloadInterval == "" {
			return errors.New("ocsp-responder/config: source.file.reload_interval must be set when source.type is 'file'")
		}
		reloadInterval, err := time.ParseDuration(c.Source.File.ReloadInterval)
		if err != nil {
			return fmt.Errorf("ocsp-responder/config: invalid source.file.reload_interval: %w", err)
		}
		if reloadInterval <= 0 {
			return errors.New("ocsp-responder/config: source.file.reload_interval must be greater than 0")
		}
		if c.Source.File.ExpiryGrace != "" {
			grace, err := time.ParseDuration(c.Source.File.ExpiryGrace)
			if err != nil {
				return fmt.Errorf("ocsp-responder/config: invalid source.file.expiry_grace: %w", err)
			}
			if grace < 0 {
				return errors.New("ocsp-responder/config: source.file.expiry_grace must not be negative")
			}
		}
	case "http":
		if c.Source.HTTP.BaseURL == "" {
			return errors.New("ocsp-responder/config: source.http.base_url must be set when source.type is 'http'")
		}
		if c.Source.HTTP.Timeout == "" {
			return errors.New("ocsp-responder/config: source.http.timeout must be set when source.type is 'http'")
		}
		if _, err := time.ParseDuration(c.Source.HTTP.Timeout); err != nil {
			return fmt.Errorf("ocsp-responder/config: invalid source.http.timeout: %w", err)
		}
		if c.Source.HTTP.RetryBackoff != "" {
			if _, err := time.ParseDuration(c.Source.HTTP.RetryBackoff); err != nil {
				return fmt.Errorf("ocsp-responder/config: invalid source.http.retry_backoff: %w", err)
			}
		} else {
			c.Source.HTTP.RetryBackoff = "500ms"
		}
		if c.Source.HTTP.RetryMax == 0 {
			c.Source.HTTP.RetryMax = 3
		}
		if c.Source.HTTP.CacheTTL != "" {
			if _, err := time.ParseDuration(c.Source.HTTP.CacheTTL); err != nil {
				return fmt.Errorf("ocsp-responder/config: invalid source.http.cache_ttl: %w", err)
			}
		}
	case "static":
		if c.Source.Static.Status == "" {
			return errors.New("ocsp-responder/config: source.static.status must be set when source.type is 'static'")
		}
		if c.Source.Static.Status != "good" && c.Source.Static.Status != "revoked" && c.Source.Static.Status != "unknown" {
			return fmt.Errorf("ocsp-responder/config: invalid source.static.status %q (must be 'good', 'revoked', or 'unknown')", c.Source.Static.Status)
		}
	default:
		return fmt.Errorf("ocsp-responder/config: invalid source.type %q", c.Source.Type)
	}

	responseValidity, err := time.ParseDuration(c.Signer.ResponseValidity)
	if err != nil {
		return fmt.Errorf("ocsp-responder/config: invalid signer.response_validity: %w", err)
	}
	if responseValidity <= 0 {
		return errors.New("ocsp-responder/config: signer.response_validity must be greater than 0")
	}
	if _, err := time.ParseDuration(c.Cache.TTL); err != nil {
		return fmt.Errorf("ocsp-responder/config: invalid cache.ttl: %w", err)
	}

	return nil
}

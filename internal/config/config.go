package config

import (
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
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type SignerConfig struct {
	CertFile         string `yaml:"cert_file"`
	KeyFile          string `yaml:"key_file"`
	IssuerCertFile   string `yaml:"issuer_cert_file"`
	ResponseValidity string `yaml:"response_validity"`
}

type SourceConfig struct {
	Type   string          `yaml:"type"`
	File   FileSourceConfig   `yaml:"file"`
	HTTP   HTTPSourceConfig   `yaml:"http"`
	Static StaticSourceConfig `yaml:"static"`
}

type FileSourceConfig struct {
	CRLPath         string `yaml:"crl_path"`
	ReloadInterval  string `yaml:"reload_interval"`
}

type HTTPSourceConfig struct {
	BaseURL      string `yaml:"base_url"`
	RootCertFile string `yaml:"root_cert_file"`
	Timeout      string `yaml:"timeout"`
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

	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("ocsp-responder/config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *Config) validate() error {
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
	case "file", "http", "static":
	default:
		return fmt.Errorf("ocsp-responder/config: invalid source.type %q", c.Source.Type)
	}

	if _, err := time.ParseDuration(c.Signer.ResponseValidity); err != nil {
		return fmt.Errorf("ocsp-responder/config: %w", err)
	}
	if _, err := time.ParseDuration(c.Cache.TTL); err != nil {
		return fmt.Errorf("ocsp-responder/config: %w", err)
	}

	return nil
}


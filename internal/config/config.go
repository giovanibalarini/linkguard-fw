package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config holds all application configuration.
type Config struct {
	// Server settings
	ListenAddr string `json:"listen_addr"`
	Port       int    `json:"port"`

	// Database
	DBPath string `json:"db_path"`

	// Security
	JWTSecret string `json:"jwt_secret"`

	// HTTPS / TLS. When TLSEnabled is true the panel is served over HTTPS; if
	// the cert/key files are missing they are auto-generated (self-signed).
	TLSEnabled bool   `json:"tls_enabled"`
	TLSCert    string `json:"tls_cert"`
	TLSKey     string `json:"tls_key"`

	// Operation mode
	DryRun bool `json:"dry_run"`
	Debug  bool `json:"debug"`

	// Monitoring
	MonitorInterval int `json:"monitor_interval_seconds"`

	// Failover
	FailoverEnabled       bool `json:"failover_enabled"`
	FailThreshold         int  `json:"fail_threshold"`
	RecoverThreshold      int  `json:"recover_threshold"`
	FailoverCooldownSecs  int  `json:"failover_cooldown_seconds"`

	// Log file
	LogFile string `json:"log_file"`
}

// Default returns a Config with sensible defaults.
func Default() *Config {
	return &Config{
		ListenAddr:           "127.0.0.1",
		Port:                 8080,
		DBPath:               "/var/lib/linkguard-fw/linkguard.db",
		JWTSecret:            "change-me-in-production",
		TLSEnabled:           false,
		TLSCert:              "/etc/linkguard-fw/tls/cert.pem",
		TLSKey:               "/etc/linkguard-fw/tls/key.pem",
		DryRun:               true,
		Debug:                false,
		MonitorInterval:      30,
		FailoverEnabled:      true,
		FailThreshold:        3,
		RecoverThreshold:     2,
		FailoverCooldownSecs: 60,
		LogFile:              "/var/log/linkguard-fw/linkguard.log",
	}
}

// Load reads configuration from a JSON file. Missing fields fall back to defaults.
func Load(path string) (*Config, error) {
	cfg := Default()

	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Save writes the configuration to a JSON file.
func Save(cfg *Config, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// Addr returns the full listen address (host:port).
func (c *Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.ListenAddr, c.Port)
}

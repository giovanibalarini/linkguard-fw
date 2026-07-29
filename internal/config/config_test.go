package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/config"
)

func TestDefaultConfig(t *testing.T) {
	cfg := config.Default()
	if cfg.ListenAddr == "" {
		t.Error("expected non-empty ListenAddr")
	}
	if cfg.Port == 0 {
		t.Error("expected non-zero Port")
	}
	if cfg.DBPath == "" {
		t.Error("expected non-empty DBPath")
	}
	if cfg.JWTSecret == "" {
		t.Error("expected non-empty JWTSecret")
	}
	if cfg.ProbeIntervalSeconds != 10 {
		t.Errorf("expected ProbeIntervalSeconds=10, got %d", cfg.ProbeIntervalSeconds)
	}
	if cfg.ProbeCount != 3 {
		t.Errorf("expected ProbeCount=3, got %d", cfg.ProbeCount)
	}
}

func TestLoadSaveConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := config.Default()
	cfg.Port = 9090
	cfg.ListenAddr = "127.0.0.1"
	cfg.DBPath = filepath.Join(dir, "test.db")

	if err := config.Save(cfg, path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Port != 9090 {
		t.Errorf("expected Port=9090, got %d", loaded.Port)
	}
	if loaded.ListenAddr != "127.0.0.1" {
		t.Errorf("expected ListenAddr=127.0.0.1, got %s", loaded.ListenAddr)
	}
}

func TestLoadMissingFile(t *testing.T) {
	// Loading a nonexistent path should return the default config, not an error.
	cfg, err := config.Load("/nonexistent/path/config.json")
	if err != nil {
		t.Fatalf("expected no error for missing file, got %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not-valid-json"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := config.Load(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestValidateRejectsShortSecret(t *testing.T) {
	c := config.Default()
	c.JWTSecret = "curto"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for short jwt_secret, got nil")
	}
}

func TestValidateRejectsDefaultPlaceholder(t *testing.T) {
	c := config.Default()
	// "change-me-in-production" tem 24 chars — abaixo do piso de 32, então já
	// falha pelo mesmo motivo do teste acima; este teste documenta
	// explicitamente que o valor padrão do struct NUNCA deveria passar sem o
	// admin trocar, não só que "é curto".
	if len(c.JWTSecret) >= 32 {
		t.Fatalf("default placeholder JWTSecret unexpectedly >= 32 chars (%d) — Validate's length check would silently accept the shipped default", len(c.JWTSecret))
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for the unmodified default JWTSecret, got nil")
	}
}

func TestValidateAcceptsStrongSecret(t *testing.T) {
	c := config.Default()
	c.JWTSecret = "a-random-64-char-secret-generated-by-postinst-1234567890ab"
	if err := c.Validate(); err != nil {
		t.Fatalf("expected a 32+ char secret to be valid, got: %v", err)
	}
}

func TestConfigJSON(t *testing.T) {
	cfg := config.Default()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var out config.Config
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.Port != cfg.Port {
		t.Errorf("round-trip Port mismatch: %d != %d", out.Port, cfg.Port)
	}
}

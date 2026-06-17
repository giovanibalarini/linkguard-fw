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

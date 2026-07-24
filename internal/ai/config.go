// Package ai wraps the Claude API (BYOK) as an advisory layer: it explains
// degradation patterns and suggests calibration, but never decides failover,
// weight, or eviction — that stays in internal/balancer, deterministic and
// offline-capable. See docs/superpowers/specs/2026-07-24-camada-de-ia-byok-design.md.
package ai

import (
	"encoding/json"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

const configKey = "ai_config"

// Config is the persisted, non-secret configuration for the AI layer. The
// API token itself is never here — see internal/secrets, key "ai_api_token".
type Config struct {
	Enabled           bool            `json:"enabled"`
	Model             string          `json:"model"`
	Effort            string          `json:"effort"`
	MonthlyBudgetUSD  float64         `json:"monthly_budget_usd"`
	SpentThisMonthUSD float64         `json:"spent_this_month_usd"`
	BudgetResetAt     time.Time       `json:"budget_reset_at"`
	TelemetryConsent  map[string]bool `json:"telemetry_consent"`
	DigestHour        int             `json:"digest_hour"`
}

func defaults() Config {
	return Config{
		Enabled: false, Model: "claude-opus-4-8", Effort: "high",
		MonthlyBudgetUSD: 5.0, DigestHour: 6,
		TelemetryConsent: map[string]bool{"hostname": false, "mac": false, "dns_queries": false},
	}
}

// LoadConfig returns the persisted config, or defaults (disabled) if unset.
func LoadConfig(db *storage.DB) Config {
	c := defaults()
	raw, err := db.GetSetting(configKey)
	if err != nil || raw == "" {
		return c
	}
	_ = json.Unmarshal([]byte(raw), &c)
	if c.TelemetryConsent == nil {
		c.TelemetryConsent = map[string]bool{}
	}
	return c
}

// SaveConfig persists the config.
func SaveConfig(db *storage.DB, c Config) error {
	out, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return db.SetSetting(configKey, string(out))
}

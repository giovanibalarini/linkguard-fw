package monitoring

import (
	"encoding/json"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

const configKey = "monitoring"

// Config is the persisted monitoring/alerting configuration. Absence of the
// settings key means "all defaults" — monitoring is ON out of the box.
type Config struct {
	Enabled          bool     `json:"enabled"`
	Services         []string `json:"services"`
	DiskThresholdPct int      `json:"disk_threshold_pct"`
}

func defaults() Config {
	return Config{
		Enabled:          true,
		Services:         []string{"kea-dhcp4-server", "unbound", "nftables"},
		DiskThresholdPct: 90,
	}
}

// LoadConfig returns the persisted config, or zero-config defaults if unset.
func LoadConfig(db *storage.DB) Config {
	raw, err := db.GetSetting(configKey)
	if err != nil || raw == "" {
		return defaults()
	}
	c := defaults()
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return defaults()
	}
	if c.DiskThresholdPct <= 0 || c.DiskThresholdPct > 100 {
		c.DiskThresholdPct = 90
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

package qos

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func validConfig() Config {
	return Config{
		Interface:    "wan0.100",
		Enabled:      true,
		UploadMbps:   50,
		DownloadMbps: 500,
		Interactive:  true,
	}
}

func TestConfigValidateAcceptsBandwidthBoundaries(t *testing.T) {
	for _, bandwidth := range []int{1, 1_000_000} {
		t.Run(fmt.Sprintf("%d_Mbps", bandwidth), func(t *testing.T) {
			cfg := validConfig()
			cfg.UploadMbps = bandwidth
			cfg.DownloadMbps = bandwidth

			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() error = %v; want nil for %d Mbps", err, bandwidth)
			}
		})
	}
}

func TestConfigValidateRejectsBandwidthOutsideLimitsWhenEnabled(t *testing.T) {
	tests := []struct {
		name     string
		upload   int
		download int
	}{
		{name: "zero upload", upload: 0, download: 100},
		{name: "negative upload", upload: -1, download: 100},
		{name: "upload above maximum", upload: 1_000_001, download: 100},
		{name: "zero download", upload: 100, download: 0},
		{name: "negative download", upload: 100, download: -1},
		{name: "download above maximum", upload: 100, download: 1_000_001},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.UploadMbps = tt.upload
			cfg.DownloadMbps = tt.download

			if err := cfg.Validate(); err == nil {
				t.Fatalf("Validate() error = nil for upload=%d download=%d; want error", tt.upload, tt.download)
			}
		})
	}
}

func TestConfigValidateAllowsDisabledZeroOrRetainedBandwidth(t *testing.T) {
	for _, limits := range [][2]int{{0, 0}, {50, 500}} {
		cfg := validConfig()
		cfg.Enabled = false
		cfg.UploadMbps = limits[0]
		cfg.DownloadMbps = limits[1]

		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate() error = %v for disabled limits %v; want nil", err, limits)
		}
	}
}

func TestConfigValidateRejectsUnsafeInterfaceNames(t *testing.T) {
	invalid := []string{
		"",
		strings.Repeat("a", 16),
		"wan 0",
		"wan/0",
		"wan;reboot",
		"wan$(id)",
		"wan\n0",
		"wãn0",
	}

	for _, iface := range invalid {
		t.Run(iface, func(t *testing.T) {
			cfg := validConfig()
			cfg.Interface = iface
			if err := cfg.Validate(); err == nil {
				t.Fatalf("Validate() error = nil for interface %q; want error", iface)
			}
		})
	}
}

func TestIFBNameIsStableSafeAndLimitedToLinuxInterfaceLength(t *testing.T) {
	first := IFBName("wan0.100")
	second := IFBName("wan0.100")
	other := IFBName("wan0.101")

	if first != second {
		t.Fatalf("IFBName() is not deterministic: %q then %q", first, second)
	}
	if first == other {
		t.Fatalf("IFBName() collision for different interfaces: %q", first)
	}
	if len(first) > 15 {
		t.Fatalf("len(IFBName()) = %d; want <= 15 (%q)", len(first), first)
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9._-]+$`).MatchString(first) {
		t.Fatalf("IFBName() = %q; want a safe interface name", first)
	}
}

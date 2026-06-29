package updater

import "testing"

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{"v1.0.38": "1.0.38", "1.0.0": "1.0.0", " v2.3 ": "2.3"} {
		if got := normalize(in); got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.38", "1.0.37", 1},
		{"1.0.37", "1.0.38", -1},
		{"1.0.0", "1.0.0", 0},
		{"1.1.0", "1.0.99", 1},
		{"2.0.0", "1.9.9", 1},
		{"1.0", "1.0.0", 0},
		{"1.0.1", "1.0", 1},
	}
	for _, tt := range tests {
		if got := compareVersions(tt.a, tt.b); got != tt.want {
			t.Errorf("compareVersions(%q,%q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestDebURLMatchesArch(t *testing.T) {
	s := &Service{}
	rel := Release{Assets: []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	}{
		{Name: "linkguard-fw_1.0.38_amd64.deb", BrowserDownloadURL: "https://x/amd64"},
		{Name: "linkguard-fw_1.0.38_arm64.deb", BrowserDownloadURL: "https://x/arm64"},
	}}
	got := s.debURL(rel)
	if got == "" {
		t.Fatal("expected a matching deb URL for the test arch")
	}
}

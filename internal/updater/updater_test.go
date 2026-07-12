package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
	rel := Release{Assets: []Asset{
		{Name: "linkguard-fw_1.0.38_amd64.deb", BrowserDownloadURL: "https://x/amd64"},
		{Name: "linkguard-fw_1.0.38_arm64.deb", BrowserDownloadURL: "https://x/arm64"},
	}}
	if s.debURL(rel) == "" {
		t.Fatal("expected a matching deb URL for the test arch")
	}
}

type recExec struct{ cmds []string }

func (e *recExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	e.cmds = append(e.cmds, cmd+" "+strings.Join(args, " "))
	return "", nil
}
func (e *recExec) ExecuteRead(_ context.Context, _ string, _ ...string) (string, error) {
	return "", nil
}
func (e *recExec) IsDryRun() bool { return false }

// TestCheckSendsTokenForPrivateRepo verifies the updater authenticates so a
// PRIVATE repo's releases/latest doesn't 404.
func TestCheckSendsTokenForPrivateRepo(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		fmt.Fprintf(w, `{"tag_name":"v9.9.9","html_url":"h","assets":[{"id":1,"name":"linkguard-fw_9.9.9_%s.deb","browser_download_url":"b"}]}`, debArch())
	}))
	defer srv.Close()

	s := NewService(&recExec{}, "1.0.0", func() string { return "TESTTOK" })
	s.apiBase = srv.URL
	res, err := s.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if gotAuth != "Bearer TESTTOK" {
		t.Errorf("Authorization = %q, want Bearer TESTTOK", gotAuth)
	}
	if !res.UpdateAvailable || res.Latest != "9.9.9" {
		t.Errorf("unexpected result: %+v", res)
	}
}

// TestApplyDownloadsViaAssetAPIAndVerifies checks the full install path against a
// fake private GitHub: auth + Accept octet-stream on the asset endpoint, checksum
// verified, dpkg invoked.
func TestApplyDownloadsViaAssetAPIAndVerifies(t *testing.T) {
	debBytes := []byte("fake-debian-package-contents")
	sum := sha256.Sum256(debBytes)
	debName := "linkguard-fw_9.9.9_" + debArch() + ".deb"
	var assetAccept, assetAuth string

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/giovanibalarini/linkguard-fw/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"tag_name":"v9.9.9","html_url":"h","assets":[
			{"id":1,"name":%q,"browser_download_url":"b"},
			{"id":2,"name":"sha256sums.txt","browser_download_url":"s"}]}`, debName)
	})
	mux.HandleFunc("/repos/giovanibalarini/linkguard-fw/releases/assets/1", func(w http.ResponseWriter, r *http.Request) {
		assetAccept = r.Header.Get("Accept")
		assetAuth = r.Header.Get("Authorization")
		w.Write(debBytes)
	})
	mux.HandleFunc("/repos/giovanibalarini/linkguard-fw/releases/assets/2", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  %s\n", hex.EncodeToString(sum[:]), debName)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	exec := &recExec{}
	s := NewService(exec, "1.0.0", func() string { return "TESTTOK" })
	s.apiBase = srv.URL

	if err := s.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if assetAccept != "application/octet-stream" {
		t.Errorf("asset Accept = %q, want application/octet-stream", assetAccept)
	}
	if assetAuth != "Bearer TESTTOK" {
		t.Errorf("asset Authorization = %q, want Bearer TESTTOK", assetAuth)
	}
	if len(exec.cmds) != 1 || !strings.HasPrefix(exec.cmds[0], "dpkg -i ") {
		t.Errorf("expected one dpkg -i call, got %v", exec.cmds)
	}
}

// TestVerifyChecksumMismatchAborts ensures a tampered package is rejected.
func TestApplyChecksumMismatchAborts(t *testing.T) {
	debName := "linkguard-fw_9.9.9_" + debArch() + ".deb"
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/giovanibalarini/linkguard-fw/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"tag_name":"v9.9.9","assets":[
			{"id":1,"name":%q},{"id":2,"name":"sha256sums.txt"}]}`, debName)
	})
	mux.HandleFunc("/repos/giovanibalarini/linkguard-fw/releases/assets/1", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("real-bytes"))
	})
	mux.HandleFunc("/repos/giovanibalarini/linkguard-fw/releases/assets/2", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  %s\n", strings.Repeat("0", 64), debName) // wrong hash
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	exec := &recExec{}
	s := NewService(exec, "1.0.0", nil)
	s.apiBase = srv.URL
	if err := s.Apply(context.Background()); err == nil {
		t.Fatal("expected checksum mismatch to abort install")
	}
	if len(exec.cmds) != 0 {
		t.Errorf("dpkg must NOT run on checksum mismatch, got %v", exec.cmds)
	}
}

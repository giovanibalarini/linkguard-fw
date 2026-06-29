// Package updater checks GitHub for newer releases and installs them in place.
// Self-update is an admin-triggered action: the matching .deb is downloaded and
// dpkg-installed; the package's postinst restarts the service onto the new
// version.
package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

const repo = "giovanibalarini/linkguard-fw"

// Release is the subset of the GitHub release we use.
type Release struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// CheckResult is returned to the UI.
type CheckResult struct {
	Current         string `json:"current"`
	Latest          string `json:"latest"`
	UpdateAvailable bool   `json:"update_available"`
	NotesURL        string `json:"notes_url"`
	DebURL          string `json:"deb_url"`
}

// Service performs update checks and installs.
type Service struct {
	exec    firewall.Executor
	client  *http.Client
	current string
}

// NewService creates an updater Service.
func NewService(exec firewall.Executor, currentVersion string) *Service {
	return &Service{exec: exec, client: &http.Client{Timeout: 20 * time.Second}, current: currentVersion}
}

// Check queries GitHub for the latest release and compares versions.
func (s *Service) Check(ctx context.Context) (CheckResult, error) {
	rel, err := s.latest(ctx)
	if err != nil {
		return CheckResult{}, err
	}
	deb := s.debURL(rel)
	res := CheckResult{
		Current:         normalize(s.current),
		Latest:          normalize(rel.TagName),
		UpdateAvailable: compareVersions(normalize(rel.TagName), normalize(s.current)) > 0 && deb != "",
		NotesURL:        rel.HTMLURL,
		DebURL:          deb,
	}
	return res, nil
}

// Apply downloads the latest .deb and installs it. The caller should respond to
// the client before the service restarts (postinst), so this is meant to be run
// detached.
func (s *Service) Apply(ctx context.Context) error {
	rel, err := s.latest(ctx)
	if err != nil {
		return err
	}
	deb := s.debURL(rel)
	if deb == "" {
		return fmt.Errorf("nenhum pacote .deb para a arquitetura %s na última release", debArch())
	}
	path, err := s.download(ctx, deb)
	if err != nil {
		return err
	}
	defer os.Remove(path)
	out, err := s.exec.Execute(ctx, "dpkg", "-i", path)
	if err != nil {
		return fmt.Errorf("dpkg: %v (%s)", err, strings.TrimSpace(out))
	}
	return nil
}

func (s *Service) latest(ctx context.Context) (Release, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := s.client.Do(req)
	if err != nil {
		return Release{}, fmt.Errorf("consultar GitHub: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Release{}, fmt.Errorf("GitHub respondeu %d", resp.StatusCode)
	}
	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return Release{}, err
	}
	return rel, nil
}

func (s *Service) download(ctx context.Context, url string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("baixar pacote: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download respondeu %d", resp.StatusCode)
	}
	f, err := os.CreateTemp("", "linkguard-update-*.deb")
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), f.Close()
}

func debArch() string {
	if runtime.GOARCH == "arm64" {
		return "arm64"
	}
	return "amd64"
}

func (s *Service) debURL(rel Release) string {
	arch := debArch()
	for _, a := range rel.Assets {
		if strings.HasSuffix(a.Name, arch+".deb") {
			return a.BrowserDownloadURL
		}
	}
	return ""
}

func normalize(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "v")
}

// compareVersions returns >0 if a>b, 0 if equal, <0 if a<b (dotted integers).
func compareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var ai, bi int
		if i < len(as) {
			ai, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			bi, _ = strconv.Atoi(bs[i])
		}
		if ai != bi {
			if ai > bi {
				return 1
			}
			return -1
		}
	}
	return 0
}

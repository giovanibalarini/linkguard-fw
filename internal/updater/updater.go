// Package updater checks GitHub for newer releases and installs them in place.
// Self-update is an admin-triggered action: the matching .deb is downloaded and
// dpkg-installed; the package's postinst restarts the service onto the new
// version.
package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

const repo = "giovanibalarini/linkguard-fw"
const defaultAPIBase = "https://api.github.com"

// Asset is one release asset. ID is used to download via the API asset endpoint
// (which works for PRIVATE repos with auth; browser_download_url does not).
type Asset struct {
	ID                 int    `json:"id"`
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// Release is the subset of the GitHub release we use.
type Release struct {
	TagName string  `json:"tag_name"`
	HTMLURL string  `json:"html_url"`
	Assets  []Asset `json:"assets"`
}

// CheckResult is returned to the UI.
type CheckResult struct {
	Current         string `json:"current"`
	Latest          string `json:"latest"`
	UpdateAvailable bool   `json:"update_available"`
	NotesURL        string `json:"notes_url"`
	DebURL          string `json:"deb_url"`
	// PackageMissing diz que existe versão mais nova sem pacote para esta
	// arquitetura. Ver Check.
	PackageMissing bool `json:"package_missing"`
}

// spoolDir é onde o .deb baixado é gravado, e NÃO é /tmp de propósito.
//
// O unit tem PrivateTmp=yes: o /tmp do serviço é um namespace só dele. O dpkg
// roda numa unidade transiente (ver Apply), que enxerga OUTRO /tmp — um caminho
// em /tmp seria entregue a ela e simplesmente não existiria. Medido na VM, não
// deduzido: com PrivateTmp, a unidade transiente não vê o arquivo; em
// /var/lib/linkguard-fw, vê.
//
// E este caminho já está em ReadWritePaths=, então o serviço pode escrever nele
// sem afrouxar nada.
const spoolDir = "/var/lib/linkguard-fw"

// Service performs update checks and installs.
type Service struct {
	exec    firewall.Executor
	client  *http.Client
	current string
	apiBase string
	tokenFn func() string // returns the configured GitHub token (may be empty)
	// spool é injetável só para teste; em produção é spoolDir.
	spool string
}

// NewService creates an updater Service. tokenFn supplies a GitHub token (for
// private repos); it may be nil or return "".
func NewService(exec firewall.Executor, currentVersion string, tokenFn func() string) *Service {
	return &Service{
		exec:    exec,
		client:  &http.Client{Timeout: 20 * time.Second},
		current: currentVersion,
		apiBase: defaultAPIBase,
		tokenFn: tokenFn,
		spool:   spoolDir,
	}
}

// SetSpoolDir troca o diretório onde o .deb é gravado. Existe para teste: em
// produção o padrão é o único caminho que serve (ver spoolDir).
func (s *Service) SetSpoolDir(dir string) { s.spool = dir }

// authReq builds a GET request with the given Accept header and, when a token is
// configured, an Authorization header — required so a PRIVATE repo's API doesn't
// answer 404. On a cross-host redirect (GitHub → S3) Go strips the auth header.
func (s *Service) authReq(ctx context.Context, url, accept string) *http.Request {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Accept", accept)
	if s.tokenFn != nil {
		if tok := strings.TrimSpace(s.tokenFn()); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}
	return req
}

// assetBody opens a release asset via the API asset endpoint (auth + octet-
// stream), which works for private repos. Caller closes the body.
func (s *Service) assetBody(ctx context.Context, id int) (io.ReadCloser, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/assets/%d", s.apiBase, repo, id)
	resp, err := s.client.Do(s.authReq(ctx, url, "application/octet-stream"))
	if err != nil {
		return nil, fmt.Errorf("baixar asset: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("download respondeu %d", resp.StatusCode)
	}
	return resp.Body, nil
}

func findAsset(rel Release, suffix string) (Asset, bool) {
	for _, a := range rel.Assets {
		if strings.HasSuffix(a.Name, suffix) {
			return a, true
		}
	}
	return Asset{}, false
}

// Check queries GitHub for the latest release and compares versions.
func (s *Service) Check(ctx context.Context) (CheckResult, error) {
	rel, err := s.latest(ctx)
	if err != nil {
		return CheckResult{}, err
	}
	deb := s.debURL(rel)
	maisNova := compareVersions(normalize(rel.TagName), normalize(s.current)) > 0
	res := CheckResult{
		Current:         normalize(s.current),
		Latest:          normalize(rel.TagName),
		UpdateAvailable: maisNova && deb != "",
		NotesURL:        rel.HTMLURL,
		DebURL:          deb,
		// AS DUAS RAZÕES DE NÃO HAVER O QUE INSTALAR SÃO DIFERENTES, e colapsá-las
		// num booleano só fazia a tela mentir.
		//
		// "Não há versão nova" e "há versão nova, mas o pacote para esta
		// arquitetura ainda não foi publicado" davam os dois `false` — e o
		// painel respondia "está atualizado", em verde, LOGO ABAIXO de mostrar
		// "atual v1.0.140 / última v1.0.141". Duas afirmações contraditórias na
		// mesma tela.
		//
		// A janela em que isso acontece é curta e é justamente a que o admin
		// pega: entre o release ser criado e os .deb terminarem de subir. Foi o
		// que aconteceu quando pedi para clicarem no botão.
		PackageMissing: maisNova && deb == "",
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
	want := normalize(rel.TagName)
	debAsset, ok := findAsset(rel, debArch()+".deb")
	if !ok {
		return fmt.Errorf("nenhum pacote .deb para a arquitetura %s na última release", debArch())
	}
	path, err := s.downloadAsset(ctx, debAsset.ID)
	if err != nil {
		return err
	}
	defer os.Remove(path)

	// Integrity: never dpkg-install a package we can't verify against the
	// release's sha256sums.txt (guards against a corrupt/tampered download).
	if err := s.verifyChecksum(ctx, rel, debAsset.Name, path); err != nil {
		return err
	}

	// O dpkg roda numa UNIDADE TRANSIENTE, fora do sandbox deste serviço.
	//
	// Por que: o unit tem ProtectSystem=strict e ReadWritePaths= não lista
	// /var/lib/dpkg nem /usr/local/bin. O serviço é root, mas dentro de um
	// sandbox onde o banco do dpkg é somente-leitura — e o `dpkg -i` direto
	// morria com "unable to access the dpkg database directory /var/lib/dpkg:
	// Read-only file system". Não era regressão: a auto-atualização nunca
	// funcionou em máquina nenhuma (#100).
	//
	// A alternativa seria listar /var/lib/dpkg, /usr, /etc, /var/log e
	// /usr/share/doc em ReadWritePaths=. Isso é desmontar o ProtectSystem que
	// protege os outros 99,99% do tempo, para um caminho que roda uma vez por
	// upgrade. A unidade transiente paga o custo só no instante em que ele
	// acontece.
	//
	// --wait é de propósito, e a assimetria é o ponto: quando o dpkg FALHA não
	// há reinício, então o erro chega aqui e vira alerta (#101). Quando dá
	// certo, o postinst reinicia o serviço e este processo morre no meio do
	// wait — o que não é problema nenhum, porque `--collect` deixa a unidade
	// terminar sozinha, e a prova do sucesso é a versão nova respondendo.
	out, err := s.exec.Execute(ctx, "systemd-run",
		"--collect", "--wait", "--quiet",
		"--unit", "linkguard-selfupdate",
		"--description", "LinkGuard FW self-update",
		"dpkg", "-i", path)
	if err == nil {
		return nil
	}

	// ERRO AQUI NÃO SIGNIFICA FALHA, e ignorar isso era o defeito que a
	// primeira versão desta correção introduziu.
	//
	// O caminho de SUCESSO passa por aqui: o postinst reinicia o
	// linkguard-fw.service, e o cliente do `systemd-run --wait` é filho DESTE
	// processo, no MESMO cgroup — ele morre junto, com "signal: terminated". O
	// dpkg em si não morre: a unidade transiente tem cgroup próprio e conclui
	// sozinha (medido na VM: `Unpacking 1.0.125 over 1.0.100` e
	// `Deactivated successfully` no journal da unidade, com o serviço já
	// reiniciado).
	//
	// Ou seja: toda atualização bem-sucedida devolveria erro daqui. Com o
	// alerta da #101 ligado, isso seria um aviso de falha em cima de cada
	// atualização que deu certo — mais barulhento e mais enganoso que o
	// silêncio que estamos corrigindo.
	//
	// A pergunta certa não é "o comando devolveu erro?", é "o pacote está
	// instalado?". Quem responde é o dpkg.
	if inst, qerr := s.installedVersion(ctx); qerr == nil && inst == want {
		slog.Info("o pacote foi instalado; o wait foi interrompido pelo reinício do próprio serviço",
			"versao", inst)
		return nil
	}
	return fmt.Errorf("instalar o pacote: %v (%s)", err, strings.TrimSpace(out))
}

// installedVersion pergunta ao dpkg qual versão está instalada AGORA.
//
// É a fonte da verdade sobre o resultado da instalação, e a única que não
// depende de o nosso processo continuar vivo para observar o desfecho.
func (s *Service) installedVersion(ctx context.Context) (string, error) {
	out, err := s.exec.ExecuteRead(ctx, "dpkg-query", "-W", "-f=${Version}", "linkguard-fw")
	if err != nil {
		return "", err
	}
	return normalize(strings.TrimSpace(out)), nil
}

// verifyChecksum computes the downloaded file's SHA-256 and compares it to the
// expected hash from the release's sha256sums.txt asset. Any mismatch or missing
// checksum aborts the install.
func (s *Service) verifyChecksum(ctx context.Context, rel Release, debName, path string) error {
	sumsAsset, ok := findAsset(rel, "sha256sums.txt")
	if !ok {
		return fmt.Errorf("release sem sha256sums.txt — instalação abortada por segurança")
	}

	body, err := s.assetBody(ctx, sumsAsset.ID)
	if err != nil {
		return fmt.Errorf("baixar checksums: %w", err)
	}
	defer body.Close()
	sums, err := io.ReadAll(io.LimitReader(body, 1<<20))
	if err != nil {
		return err
	}

	var expected string
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		// sha256sum binary mode writes "HASH *name"; strip the '*' so both text
		// and binary formats match.
		if len(f) >= 2 && filepath.Base(strings.TrimPrefix(f[1], "*")) == debName {
			expected = strings.ToLower(f[0])
			break
		}
	}
	if expected == "" {
		return fmt.Errorf("hash de %s não está no sha256sums.txt — instalação abortada", debName)
	}

	fh, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fh.Close()
	h := sha256.New()
	if _, err := io.Copy(h, fh); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, expected) {
		return fmt.Errorf("checksum do pacote não confere — instalação abortada (integridade)")
	}
	return nil
}

func (s *Service) latest(ctx context.Context) (Release, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/latest", s.apiBase, repo)
	resp, err := s.client.Do(s.authReq(ctx, url, "application/vnd.github+json"))
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

func (s *Service) downloadAsset(ctx context.Context, id int) (string, error) {
	body, err := s.assetBody(ctx, id)
	if err != nil {
		return "", err
	}
	defer body.Close()
	if err := os.MkdirAll(s.spool, 0o755); err != nil {
		return "", fmt.Errorf("preparar o diretório do pacote: %w", err)
	}
	f, err := os.CreateTemp(s.spool, "linkguard-update-*.deb")
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(f, body); err != nil {
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

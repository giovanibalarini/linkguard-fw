package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
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
func (e *recExec) IsDryRun() bool                              { return false }
func (_ *recExec) WriteFile(string, []byte, os.FileMode) error { return nil }

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
	s.SetSpoolDir(t.TempDir())

	if err := s.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if assetAccept != "application/octet-stream" {
		t.Errorf("asset Accept = %q, want application/octet-stream", assetAccept)
	}
	if assetAuth != "Bearer TESTTOK" {
		t.Errorf("asset Authorization = %q, want Bearer TESTTOK", assetAuth)
	}
	// ATUALIZADO na #100: o dpkg não é mais chamado direto — ele roda numa
	// unidade transiente, porque o sandbox do serviço deixa /var/lib/dpkg
	// somente-leitura e o `dpkg -i` direto nunca funcionou em máquina nenhuma.
	if len(exec.cmds) != 1 {
		t.Fatalf("esperava uma chamada, veio %v", exec.cmds)
	}
	if !strings.HasPrefix(exec.cmds[0], "systemd-run ") {
		t.Errorf("o dpkg não foi isolado numa unidade transiente: %q", exec.cmds[0])
	}
	if !strings.Contains(exec.cmds[0], "dpkg -i ") {
		t.Errorf("a unidade transiente não instala o pacote: %q", exec.cmds[0])
	}
}

// TestApplyEntregaOCaminhoDoSpool é a metade da correção que é fácil de
// esquecer.
//
// O unit tem PrivateTmp=yes: o /tmp do serviço é um namespace só dele, e a
// unidade transiente enxerga OUTRO. Um caminho em /tmp seria entregue ao dpkg e
// simplesmente não existiria lá dentro — medido na VM, não deduzido.
//
// O que ele afirma é o par: o arquivo sai do spool configurado, e é esse MESMO
// caminho que chega à linha de comando. Uma versão anterior deste teste também
// procurava "/tmp" no comando e falhava sempre — t.TempDir() devolve um caminho
// dentro de /tmp, então ela acusava o próprio diretório do teste. Quem carrega
// a afirmação "o padrão não é /tmp" é TestSpoolPadraoEhOCompartilhado, onde ela
// pode ser feita sem essa ambiguidade.
func TestApplyEntregaOCaminhoDoSpool(t *testing.T) {
	debBytes := []byte("pacote")
	sum := sha256.Sum256(debBytes)
	debName := "linkguard-fw_9.9.9_" + debArch() + ".deb"

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/giovanibalarini/linkguard-fw/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"tag_name":"v9.9.9","html_url":"h","assets":[
			{"id":1,"name":%q,"browser_download_url":"b"},
			{"id":2,"name":"sha256sums.txt","browser_download_url":"s"}]}`, debName)
	})
	mux.HandleFunc("/repos/giovanibalarini/linkguard-fw/releases/assets/1", func(w http.ResponseWriter, r *http.Request) {
		w.Write(debBytes)
	})
	mux.HandleFunc("/repos/giovanibalarini/linkguard-fw/releases/assets/2", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  %s\n", hex.EncodeToString(sum[:]), debName)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	spool := t.TempDir()
	exec := &recExec{}
	s := NewService(exec, "1.0.0", nil)
	s.apiBase = srv.URL
	s.SetSpoolDir(spool)

	if err := s.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	cmd := exec.cmds[0]
	if !strings.Contains(cmd, spool) {
		t.Errorf("o caminho entregue ao dpkg não é o do spool (%s):\n%s", spool, cmd)
	}
}

// TestSpoolPadraoEhOCompartilhado: o default de produção não pode ser /tmp, e
// tem de ser um caminho que o unit já declara em ReadWritePaths=. Trocá-lo por
// um que o serviço não pode escrever quebra a atualização de novo, e só numa
// máquina de verdade.
func TestSpoolPadraoEhOCompartilhado(t *testing.T) {
	s := NewService(&recExec{}, "1.0.0", nil)
	if s.spool != "/var/lib/linkguard-fw" {
		t.Errorf("spool padrão = %q; esperado /var/lib/linkguard-fw, que é o que o unit declara em ReadWritePaths", s.spool)
	}
	// E ele não pode voltar a ser /tmp: com PrivateTmp=yes o arquivo ficaria
	// invisível para a unidade transiente que roda o dpkg.
	if strings.HasPrefix(s.spool, "/tmp") {
		t.Error("o spool voltou a ser /tmp; com PrivateTmp a unidade transiente não enxerga o arquivo (#100)")
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

// execComResultado é um Executor que falha no systemd-run e responde ao
// dpkg-query com a versão que o teste escolher — as duas metades de que Apply
// precisa para decidir se a instalação deu certo apesar do erro.
type execComResultado struct {
	recExec
	instalada string
	queryErr  error
}

func (e *execComResultado) Execute(ctx context.Context, cmd string, args ...string) (string, error) {
	out, _ := e.recExec.Execute(ctx, cmd, args...)
	return out, errors.New("signal: terminated")
}

func (e *execComResultado) ExecuteRead(_ context.Context, _ string, _ ...string) (string, error) {
	if e.queryErr != nil {
		return "", e.queryErr
	}
	return e.instalada, nil
}

func servidorDeRelease(t *testing.T) *httptest.Server {
	t.Helper()
	debBytes := []byte("pacote")
	sum := sha256.Sum256(debBytes)
	debName := "linkguard-fw_9.9.9_" + debArch() + ".deb"
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/giovanibalarini/linkguard-fw/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"tag_name":"v9.9.9","html_url":"h","assets":[
			{"id":1,"name":%q,"browser_download_url":"b"},
			{"id":2,"name":"sha256sums.txt","browser_download_url":"s"}]}`, debName)
	})
	mux.HandleFunc("/repos/giovanibalarini/linkguard-fw/releases/assets/1", func(w http.ResponseWriter, r *http.Request) {
		w.Write(debBytes)
	})
	mux.HandleFunc("/repos/giovanibalarini/linkguard-fw/releases/assets/2", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  %s\n", hex.EncodeToString(sum[:]), debName)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestApplyNaoAcusaFalhaQuandoOPacoteEntrou é a regressão do defeito que a
// PRIMEIRA versão desta correção introduziu, e que só apareceu na VM.
//
// O caminho de SUCESSO devolve erro: o postinst reinicia o linkguard-fw, e o
// cliente do `systemd-run --wait` é filho deste processo, no mesmo cgroup —
// morre junto, com "signal: terminated". O dpkg não morre (a unidade transiente
// tem cgroup próprio e conclui).
//
// Sem esta checagem, o alerta da #101 dispararia em cima de TODA atualização
// bem-sucedida: mais enganoso que o silêncio que estamos corrigindo.
func TestApplyNaoAcusaFalhaQuandoOPacoteEntrou(t *testing.T) {
	srv := servidorDeRelease(t)
	e := &execComResultado{instalada: "9.9.9"}
	s := NewService(e, "1.0.0", nil)
	s.apiBase = srv.URL
	s.SetSpoolDir(t.TempDir())

	if err := s.Apply(context.Background()); err != nil {
		t.Fatalf("o comando morreu com o reinício e a versão nova ESTÁ instalada; isso não é falha:\n%v", err)
	}
}

// E o contrário continua sendo falha: se o dpkg não instalou, o erro tem de
// chegar ao operador. Um "está tudo bem" aqui devolveria o silêncio da #101 por
// outro caminho.
func TestApplyAcusaFalhaQuandoOPacoteNaoEntrou(t *testing.T) {
	srv := servidorDeRelease(t)
	e := &execComResultado{instalada: "1.0.0"} // continua na versão velha
	s := NewService(e, "1.0.0", nil)
	s.apiBase = srv.URL
	s.SetSpoolDir(t.TempDir())

	if err := s.Apply(context.Background()); err == nil {
		t.Fatal("o pacote não foi instalado e Apply devolveu sucesso")
	}
}

// E se nem dá para perguntar ao dpkg, o lado seguro é reportar a falha: dizer
// que deu certo sem conseguir verificar é a mentira que custa caro.
func TestApplyReportaFalhaQuandoNaoConsegueVerificar(t *testing.T) {
	srv := servidorDeRelease(t)
	e := &execComResultado{queryErr: errors.New("dpkg-query indisponível")}
	s := NewService(e, "1.0.0", nil)
	s.apiBase = srv.URL
	s.SetSpoolDir(t.TempDir())

	if err := s.Apply(context.Background()); err == nil {
		t.Fatal("não deu para verificar a instalação e Apply respondeu sucesso")
	}
}

// TestVersaoNovaSemPacoteNaoEhEstarAtualizado é a regressão do que o admin
// encontrou na prática.
//
// "Não há versão nova" e "há versão nova, mas o pacote para esta arquitetura
// ainda não subiu" davam os dois `update_available: false` — e a tela respondia
// "está atualizado", em verde, LOGO ABAIXO de mostrar "atual v1.0.140 / última
// v1.0.141". Duas afirmações contraditórias na mesma tela, e nada para clicar.
//
// A janela é curta e é justamente a que o admin pega: entre o release ser criado
// e os .deb terminarem de subir.
func TestVersaoNovaSemPacoteNaoEhEstarAtualizado(t *testing.T) {
	rel := Release{TagName: "v1.0.141", HTMLURL: "https://exemplo/rel"}
	s := &Service{current: "v1.0.140"}

	// Sem asset nenhum: versão nova existe, pacote não.
	res := CheckResult{
		Current:         normalize(s.current),
		Latest:          normalize(rel.TagName),
		UpdateAvailable: compareVersions(normalize(rel.TagName), normalize(s.current)) > 0 && s.debURL(rel) != "",
		PackageMissing:  compareVersions(normalize(rel.TagName), normalize(s.current)) > 0 && s.debURL(rel) == "",
	}
	if res.UpdateAvailable {
		t.Error("ofereceu instalar sem pacote publicado")
	}
	if !res.PackageMissing {
		t.Error("a tela diria 'está atualizado' com uma versão mais nova disponível")
	}

	// Já na última versão: nenhum dos dois.
	mesma := &Service{current: "v1.0.141"}
	if compareVersions(normalize(rel.TagName), normalize(mesma.current)) > 0 {
		t.Error("versão igual foi tratada como mais nova")
	}
}

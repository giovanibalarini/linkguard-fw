package pktcapture

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

// ─── filtro ──────────────────────────────────────────────────────────────────

func TestBuildExprVazioNaoFiltra(t *testing.T) {
	expr, err := BuildExpr(Filter{})
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if len(expr) != 0 {
		t.Errorf("filtro vazio virou %q", expr)
	}
}

func TestBuildExprCombinaCampos(t *testing.T) {
	expr, err := BuildExpr(Filter{Proto: "tcp", Host: "192.168.3.50", Port: 443})
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	want := "tcp and host 192.168.3.50 and port 443"
	if got := strings.Join(expr, " "); got != want {
		t.Errorf("expr = %q, queria %q", got, want)
	}
}

func TestBuildExprCIDRViraNet(t *testing.T) {
	// "host 192.168.3.0/24" não é expressão válida de BPF; a palavra é "net".
	// Errar isto faria o tcpdump recusar o filtro e a captura falhar inteira.
	expr, err := BuildExpr(Filter{Host: "192.168.3.0/24"})
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if got := strings.Join(expr, " "); got != "net 192.168.3.0/24" {
		t.Errorf("expr = %q", got)
	}
}

func TestBuildExprDirecao(t *testing.T) {
	casos := map[string]string{
		"from": "src host 192.168.3.50 and src port 443",
		"to":   "dst host 192.168.3.50 and dst port 443",
		"any":  "host 192.168.3.50 and port 443",
	}
	for dir, want := range casos {
		expr, err := BuildExpr(Filter{Host: "192.168.3.50", Port: 443, Direction: dir})
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		if got := strings.Join(expr, " "); got != want {
			t.Errorf("%s: expr = %q, queria %q", dir, got, want)
		}
	}
}

func TestBuildExprRejeita(t *testing.T) {
	casos := []struct {
		nome string
		f    Filter
	}{
		// O caso que importa para segurança: campo que viraria FLAG do tcpdump.
		// O argv é separado, então não há shell aqui — mas "-w" como token de
		// filtro faria o tcpdump gravar um arquivo escolhido por quem chamou.
		{"host que parece flag", Filter{Host: "-w"}},
		{"host com espaço e comando", Filter{Host: "1.2.3.4 or -r /etc/shadow"}},
		{"host não é IP", Filter{Host: "example.com"}},
		{"cidr inválido", Filter{Host: "192.168.3.0/99"}},
		{"porta zero negativa", Filter{Port: -1}},
		{"porta acima da faixa", Filter{Port: 70000}},
		{"protocolo inventado", Filter{Proto: "quic"}},
		{"direção inventada", Filter{Direction: "para-cima"}},
		{"icmp com porta", Filter{Proto: "icmp", Port: 443}},
	}
	for _, c := range casos {
		if _, err := BuildExpr(c.f); err == nil {
			t.Errorf("%s: devia ter sido recusado", c.nome)
		}
	}
}

func TestBuildExprNenhumTokenVirouFlag(t *testing.T) {
	// Rede de segurança para quem acrescentar campo novo ao filtro sem lembrar
	// da regra: nenhum token pode começar com "-".
	oks := []Filter{
		{}, {Proto: "udp"}, {Host: "10.0.0.1"}, {Host: "10.0.0.0/8", Direction: "from"},
		{Proto: "tcp", Port: 22, Direction: "to"},
	}
	for _, f := range oks {
		expr, err := BuildExpr(f)
		if err != nil {
			t.Fatalf("%+v: %v", f, err)
		}
		for _, tok := range expr {
			if strings.HasPrefix(tok, "-") {
				t.Errorf("%+v gerou token de flag: %q", f, tok)
			}
		}
	}
}

// ─── serviço ─────────────────────────────────────────────────────────────────

// bloqExec trava no Execute até que libera seja fechado, para o teste poder
// observar uma captura "em andamento" de forma determinística.
type bloqExec struct {
	firewall.Executor
	libera   chan struct{}
	mu       sync.Mutex
	leituras int
}

func (e *bloqExec) Execute(ctx context.Context, _ string, _ ...string) (string, error) {
	select {
	case <-e.libera:
	case <-ctx.Done():
	}
	return "", nil
}
func (e *bloqExec) ExecuteRead(context.Context, string, ...string) (string, error) {
	e.mu.Lock()
	e.leituras++
	e.mu.Unlock()
	return "", nil
}

func (e *bloqExec) contaLeituras() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.leituras
}
func (e *bloqExec) IsDryRun() bool { return false }
func (e *bloqExec) WriteFile(string, []byte, os.FileMode) error {
	return nil
}

func novoServicoBloqueado(t *testing.T) (*Service, chan struct{}) {
	t.Helper()
	libera := make(chan struct{})
	ex := &bloqExec{libera: libera}
	s := NewService(ex, ex, t.TempDir())
	// Destravar o executor NÃO basta: é preciso esperar a goroutine da captura
	// sair antes de o t.TempDir() ser removido.
	//
	// POR QUÊ. A goroutine pode ainda nem ter chegado ao ensureDir quando o
	// teste termina. Os cleanups rodam em ordem inversa, então o RemoveAll do
	// TempDir vem logo depois deste — e um MkdirAll que acontece DEPOIS do
	// RemoveAll recria o diretório, deixando o diretório-pai não vazio. O
	// sintoma é "TempDir RemoveAll cleanup: directory not empty", num teste
	// que não tem nada a ver com o que falhou.
	//
	// Isto não é teoria: passou no CI da PR e quebrou o job de release, onde a
	// suíte inteira roda junto e o escalonamento é outro. Teste que falha por
	// sorte do relógio derruba release (é a issue #71 outra vez, por outro
	// caminho).
	t.Cleanup(func() {
		close(libera)
		prazo := time.Now().Add(3 * time.Second)
		for time.Now().Before(prazo) {
			if c := s.Status(); c == nil || c.State != StateRunning {
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
		t.Error("a goroutine da captura não terminou antes da limpeza do teste")
	})
	return s, libera
}

func TestStartRejeitaInterfaceInvalida(t *testing.T) {
	s, _ := novoServicoBloqueado(t)
	for _, iface := range []string{"", "..", "-i", "eth0; rm -rf /", "interface-com-nome-longo-demais"} {
		if _, err := s.Start(Params{Interface: iface}, "tester"); err == nil {
			t.Errorf("interface %q devia ter sido recusada", iface)
		}
	}
}

func TestStartUmaCapturaPorVez(t *testing.T) {
	// Duas capturas simultâneas em link cheio derrubam a máquina de
	// referência; e o serviço guarda uma captura só, então a segunda
	// sobrescreveria a primeira no meio.
	s, _ := novoServicoBloqueado(t)
	if _, err := s.Start(Params{Interface: "eth0"}, "tester"); err != nil {
		t.Fatalf("primeira captura: %v", err)
	}
	if _, err := s.Start(Params{Interface: "eth0"}, "tester"); err == nil {
		t.Error("a segunda captura simultânea devia ter sido recusada")
	}
}

func TestStartAplicaOsTetos(t *testing.T) {
	s, _ := novoServicoBloqueado(t)
	c, err := s.Start(Params{Interface: "eth0", DurationSec: 9999, MaxPackets: 9999999}, "tester")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if c.DurationSec != MaxDurationSec {
		t.Errorf("duração = %d, queria o teto %d", c.DurationSec, MaxDurationSec)
	}
	if c.MaxPackets != MaxPackets {
		t.Errorf("pacotes = %d, queria o teto %d", c.MaxPackets, MaxPackets)
	}
}

func TestStartUsaPadraoQuandoNaoPedem(t *testing.T) {
	s, _ := novoServicoBloqueado(t)
	c, _ := s.Start(Params{Interface: "eth0"}, "tester")
	if c.DurationSec != DefaultDurationSec || c.MaxPackets != DefaultPackets {
		t.Errorf("padrões: %d s, %d pacotes", c.DurationSec, c.MaxPackets)
	}
	if c.SnapLen != SnapLen {
		t.Errorf("snaplen = %d, queria %d", c.SnapLen, SnapLen)
	}
}

func TestDryRunNaoCaptura(t *testing.T) {
	ex := firewall.NewDryRunExecutor()
	s := NewService(ex, ex, t.TempDir())
	if _, err := s.Start(Params{Interface: "eth0"}, "tester"); err != nil {
		t.Fatalf("start: %v", err)
	}
	c := esperaFim(t, s)
	if c.State != StateDone {
		t.Errorf("estado = %q", c.State)
	}
	if !strings.Contains(c.Message, "dry-run") {
		t.Errorf("a mensagem tem de dizer que nada foi executado: %q", c.Message)
	}
	if len(ex.Commands) != 0 {
		t.Errorf("dry-run executou comando: %q", ex.Commands)
	}
}

func TestStatusDevolveCopiaEnaoOEstadoVivo(t *testing.T) {
	// O handler faz json.Marshal do que sai daqui enquanto a goroutine da
	// captura ainda pode estar escrevendo. Devolver o ponteiro vivo é corrida
	// garantida sob -race.
	s, _ := novoServicoBloqueado(t)
	if _, err := s.Start(Params{Interface: "eth0"}, "tester"); err != nil {
		t.Fatalf("start: %v", err)
	}
	a := s.Status()
	a.Packets = append(a.Packets, Packet{Src: "invadido"})
	a.Summary.Packets = 999
	b := s.Status()
	if len(b.Packets) != 0 || b.Summary.Packets != 0 {
		t.Error("mexer no que Status() devolveu alterou o estado do serviço")
	}
}

func TestFilePathRecusaIDComCaminho(t *testing.T) {
	// O ID vem da URL. Sem a checagem, ".." desce para fora do diretório e o
	// download vira leitura de arquivo arbitrário do sistema.
	s, _ := novoServicoBloqueado(t)
	for _, id := range []string{"../../etc/passwd", "..", "x/y", "20260819T120000/../../etc/shadow", ""} {
		if _, ok := s.FilePath(id); ok {
			t.Errorf("id %q devia ter sido recusado", id)
		}
	}
}

func TestSweepRemoveVencidoEMantemRecente(t *testing.T) {
	dir := t.TempDir()
	velho := filepath.Join(dir, "20260101T000000.pcap")
	novo := filepath.Join(dir, "20260819T120000.pcap")
	outro := filepath.Join(dir, "naoehcaptura.txt")
	for _, f := range []string{velho, novo, outro} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	antigo := time.Now().Add(-2 * FileTTL)
	if err := os.Chtimes(velho, antigo, antigo); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(outro, antigo, antigo); err != nil {
		t.Fatal(err)
	}

	ex := &bloqExec{libera: make(chan struct{})}
	NewService(ex, ex, dir) // NewService já varre no boot

	if _, err := os.Stat(velho); !os.IsNotExist(err) {
		t.Error("captura vencida continuou no disco")
	}
	if _, err := os.Stat(novo); err != nil {
		t.Error("captura dentro do prazo foi removida")
	}
	if _, err := os.Stat(outro); err != nil {
		t.Error("arquivo que não é captura foi removido")
	}
}

func esperaFim(t *testing.T, s *Service) *Capture {
	t.Helper()
	prazo := time.Now().Add(3 * time.Second)
	for time.Now().Before(prazo) {
		if c := s.Status(); c != nil && c.State != StateRunning {
			return c
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("a captura não terminou no prazo do teste")
	return nil
}

func TestMensagemDeFalhaExplicaAppArmor(t *testing.T) {
	// Arquivo ausente depois de um tcpdump que "rodou" é a falha mais confusa
	// desta feature. A mensagem tem de citar as duas causas reais em vez de
	// repassar o erro cru.
	msg := captureFailureMessage(nil, os.ErrNotExist, "/var/lib/linkguard-fw/captures")
	for _, termo := range []string{"AppArmor", "tcpdump", "/var/lib/linkguard-fw/captures"} {
		if !strings.Contains(msg, termo) {
			t.Errorf("a mensagem não cita %q: %s", termo, msg)
		}
	}
}

func TestAvailableNaoGastaUmProcessoPorConsulta(t *testing.T) {
	// A tela consulta o status a cada 1,5 s enquanto captura. Sem cache, cada
	// consulta viraria um `tcpdump --version` — trinta processos por captura
	// de 45 s, no hardware que este produto existe para caber.
	// Canal já liberado: este teste não quer nada travado — o Install abaixo
	// passa pelo mesmo executor e ficaria preso no bloqueio.
	liberado := make(chan struct{})
	close(liberado)
	ex := &bloqExec{libera: liberado}
	s := NewService(ex, ex, t.TempDir())
	for i := 0; i < 10; i++ {
		if !s.Available(context.Background()) {
			t.Fatal("devia estar disponível")
		}
	}
	if n := ex.contaLeituras(); n != 1 {
		t.Errorf("%d execuções de tcpdump --version para 10 consultas; queria 1", n)
	}

	// E o cache tem de cair quando o admin instala, senão a tela insiste em
	// "não instalado" por um minuto depois de o pacote entrar.
	if err := s.Install(context.Background()); err == nil {
		_ = err // o apt não roda em teste; o que importa é a invalidação
	}
	_ = s.Available(context.Background())
	if n := ex.contaLeituras(); n < 2 {
		t.Errorf("instalar não invalidou o cache de disponibilidade (%d leituras)", n)
	}
}

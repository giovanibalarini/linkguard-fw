// Package pktcapture faz captura de pacotes sob demanda — limitada, só de
// cabeçalho — e transforma o resultado em algo que se lê no painel.
//
// POR QUE EXISTE. "O pacote chega?" era a última pergunta grande do produto
// que só tinha resposta por SSH. O admin via a regra aplicada, o contador
// zerado, e não tinha como saber se o pacote sequer entrava na interface. Este
// pacote fecha esse buraco sem transformar o firewall num sniffer de conteúdo.
//
// O QUE ELE CAPTURA, COM PRECISÃO. `-s 96` manda o kernel copiar só os
// primeiros 96 bytes de cada quadro: Ethernet (14) + IP (20) + TCP com opções
// (até 60) cabem aí. Em pacote de cabeçalho curto — UDP tem 8 bytes de
// cabeçalho — sobram algumas dezenas de bytes que são, sim, início de payload.
// Então a frase honesta não é "o payload não é capturado", é: **não dá para
// reconstruir conteúdo a partir do que fica no arquivo**, e a tabela do painel
// nunca mostra nada derivado de payload (o parser descarta o texto descritivo
// que o tcpdump imprime; só campos estruturados sobrevivem).
//
// A diferença entre a TABELA e o ARQUIVO é real e foi medida na VM: um
// `tcpdump -r` do .pcap de uma sessão SSH imprime o banner do serviço
// ("SSH-2.0-OpenSSH_10.0p2"), porque ele cabe nos bytes que sobram depois do
// cabeçalho. A tabela do painel, do mesmo pacote, mostrou só hora, endereços,
// protocolo, flags e tamanho. Quem baixa o arquivo recebe mais do que quem lê
// a tela — e o texto da tela diz isso, em vez de deixar a pessoa descobrir.
//
// POR QUE tcpdump, E NÃO UM SNIFFER PRÓPRIO EM GO. O filtro BPF roda no
// kernel: em link saturado é ele que impede o processo de acordar a cada
// pacote. Escrever o sniffer com AF_PACKET é fácil; compilar uma expressão de
// filtro para BPF sem libpcap não é. A dependência de um binário externo é o
// preço de não copiar gigabit para o userspace na máquina de referência
// (i3-3220 de 2012).
//
// FORMATO DE JOB, E NÃO STREAM. Uma captura começa, roda até o limite de tempo
// ou de pacotes, e vira resultado. Não há tail ao vivo porque o
// firewall.Executor é requisição/resposta, e inventar uma camada de streaming
// para isto custaria mais do que a feature inteira. O painel mostra progresso
// consultando o status.
package pktcapture

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/bootstrapdeps"
	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/validate"
)

const (
	// SnapLen é quanto de cada quadro o kernel copia. Ver o comentário do
	// pacote para o que isso significa (e o que NÃO significa) na prática.
	SnapLen = 96

	// DefaultDurationSec/DefaultPackets são o que a tela propõe; Max* são o
	// teto que o backend impõe mesmo que alguém chame a API direto.
	DefaultDurationSec = 15
	MaxDurationSec     = 120
	DefaultPackets     = 5000
	MaxPackets         = 20000

	// MaxRows limita as linhas devolvidas ao painel. O resumo continua sendo
	// calculado sobre a captura INTEIRA, e o .pcap tem tudo — o corte é só do
	// JSON, que a 20.000 linhas passaria de 2 MB por consulta de status.
	MaxRows = 2000

	// FileTTL é por quanto tempo o .pcap fica disponível para download. Curto
	// de propósito: é registro de tráfego alheio, não arquivo de trabalho.
	FileTTL = time.Hour

	// DefaultDir fica sob /var/lib/linkguard-fw, que já é ReadWritePaths da
	// unidade — um diretório novo fora dali não seria gravável (o namespace é
	// montado no start do serviço).
	DefaultDir = "/var/lib/linkguard-fw/captures"
)

// Estados de uma captura.
const (
	StateRunning = "running"
	StateDone    = "done"
	StateAborted = "aborted"
	StateError   = "error"
)

// Filter é o filtro montado POR CAMPOS, e não uma expressão BPF livre.
//
// A diferença importa: o argv é separado, então expressão livre não é injeção
// de shell — mas é injeção de *flag* do tcpdump, e `-w`, `-r` e `-z` gravam
// arquivo e executam comando. Campos validados não têm como virar flag.
type Filter struct {
	Host      string `json:"host"`      // IP ou CIDR
	Port      int    `json:"port"`      // 1..65535
	Proto     string `json:"proto"`     // tcp | udp | icmp | "" (qualquer)
	Direction string `json:"direction"` // any | from | to
}

// Params é o pedido de captura vindo da API.
type Params struct {
	Interface   string `json:"interface"`
	Filter      Filter `json:"filter"`
	DurationSec int    `json:"duration_sec"`
	MaxPackets  int    `json:"max_packets"`
	SaveFile    bool   `json:"save_file"` // manter o .pcap para download
}

// Capture é uma captura e seu estado — vivo ou final.
type Capture struct {
	ID          string   `json:"id"`
	Interface   string   `json:"interface"`
	Filter      Filter   `json:"filter"`
	FilterExpr  string   `json:"filter_expr"` // o que foi realmente passado ao tcpdump
	DurationSec int      `json:"duration_sec"`
	MaxPackets  int      `json:"max_packets"`
	SnapLen     int      `json:"snaplen"`
	State       string   `json:"state"`
	Message     string   `json:"message"`
	StartedBy   string   `json:"started_by"`
	StartedAt   string   `json:"started_at"`
	EndedAt     string   `json:"ended_at"`
	Packets     []Packet `json:"packets"`
	RowsShown   int      `json:"rows_shown"`
	Truncated   bool     `json:"truncated"` // havia mais linhas que MaxRows
	Summary     Summary  `json:"summary"`
	HasFile     bool     `json:"has_file"`
	FileBytes   int64    `json:"file_bytes"`
}

// Service roda uma captura por vez.
type Service struct {
	// exec é o executor da aplicação (30 s): serve para ler o arquivo de volta
	// e para checar se o tcpdump existe. capExec tem prazo dimensionado para a
	// captura em si — com o executor de 30 s, toda captura de mais de meio
	// minuto morreria no deadline e reportaria falha que não houve. Mesmo
	// motivo do pkgExec para o apt.
	exec    firewall.Executor
	capExec firewall.Executor
	// installExec roda o apt-get da instalação sob demanda do tcpdump. Mesmo
	// motivo do installExec do timesync/keaunbound: 30 s é prazo de `nft`, não
	// de download de pacote, e quando ele estoura o apt NÃO morre junto — o
	// LinkGuard reportaria uma falha que não está acontecendo.
	installExec firewall.Executor
	dir         string

	mu     sync.Mutex
	active *Capture
	cancel context.CancelFunc

	// A tela consulta o status a cada 1,5 s enquanto a captura roda. Sem estes
	// dois caches, cada consulta gastaria um processo (`tcpdump --version`) e
	// uma leitura de diretório — trinta vezes mais caro que a resposta, e num
	// i3 de 2012 isso aparece.
	availUntil time.Time
	availLast  bool
	lastSweep  time.Time

	nowFn  func() time.Time
	nextID func() string
}

const (
	availTTL = time.Minute
	sweepTTL = time.Minute
)

// NewService cria o serviço. capExec pode ser nil em teste — cai no exec.
func NewService(exec, capExec firewall.Executor, dir string) *Service {
	if capExec == nil {
		capExec = exec
	}
	if dir == "" {
		dir = DefaultDir
	}
	s := &Service{
		exec:        exec,
		capExec:     capExec,
		installExec: exec,
		dir:         dir,
		nowFn:       time.Now,
		nextID:      func() string { return time.Now().UTC().Format("20060102T150405") },
	}
	// Varre no boot: um .pcap de antes de um restart não tem dono nem prazo
	// vivo, e ficaria parado no disco até alguém abrir a tela.
	s.Sweep()
	return s
}

// Status devolve uma cópia da captura atual ou da última (nil se nenhuma).
//
// Cópia profunda porque o handler que chama isto faz json.Marshal enquanto a
// goroutine da captura ainda pode estar escrevendo — mesmo motivo do
// stresstest.snapshot.
func (s *Service) Status() *Capture {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	return snapshot(s.active)
}

// Available diz se o tcpdump está instalado, com cache curto. A tela pergunta
// isto a cada consulta de status; sem cache, seria um processo por consulta.
func (s *Service) Available(ctx context.Context) bool {
	s.mu.Lock()
	if s.nowFn().Before(s.availUntil) {
		v := s.availLast
		s.mu.Unlock()
		return v
	}
	s.mu.Unlock()

	_, err := s.exec.ExecuteRead(ctx, "tcpdump", "--version")

	s.mu.Lock()
	s.availLast = err == nil
	s.availUntil = s.nowFn().Add(availTTL)
	v := s.availLast
	s.mu.Unlock()
	return v
}

func snapshot(c *Capture) *Capture {
	if c == nil {
		return nil
	}
	cp := *c
	// make, e não append em slice nil: precisa marshalar como [] e nunca null,
	// senão a tela quebra ao iterar.
	cp.Packets = append(make([]Packet, 0, len(c.Packets)), c.Packets...)
	cp.Summary = c.Summary.clone()
	return &cp
}

// Stop aborta a captura em andamento. O arquivo parcial continua válido: o
// tcpdump roda com -U (grava pacote a pacote), justamente para que abortar não
// devolva um arquivo vazio.
func (s *Service) Stop() {
	s.mu.Lock()
	c := s.cancel
	s.mu.Unlock()
	if c != nil {
		c()
	}
}

// Start valida o pedido e dispara a captura.
func (s *Service) Start(p Params, by string) (*Capture, error) {
	s.mu.Lock()
	if s.active != nil && s.active.State == StateRunning {
		s.mu.Unlock()
		return nil, fmt.Errorf("já existe uma captura em andamento")
	}
	s.mu.Unlock()

	// validate.Iface é a validação do produto; a segunda condição é local e
	// deliberada. O charset dele aceita "-" e exige um alfanumérico, então
	// "-i" passa — e aqui o valor vira argv logo depois de "-i". Nome de
	// interface começando com hífen não existe na prática e não custa nada
	// recusar; o que custaria é confiar que o próximo campo interpolado num
	// argv também não começa com flag. Mesma regra do guarda de BuildExpr.
	if !validate.Iface(p.Interface) || strings.HasPrefix(p.Interface, "-") {
		return nil, fmt.Errorf("interface inválida")
	}
	expr, err := BuildExpr(p.Filter)
	if err != nil {
		return nil, err
	}
	if p.DurationSec <= 0 {
		p.DurationSec = DefaultDurationSec
	}
	if p.DurationSec > MaxDurationSec {
		p.DurationSec = MaxDurationSec
	}
	if p.MaxPackets <= 0 {
		p.MaxPackets = DefaultPackets
	}
	if p.MaxPackets > MaxPackets {
		p.MaxPackets = MaxPackets
	}

	c := &Capture{
		ID:          s.nextID(),
		Interface:   p.Interface,
		Filter:      p.Filter,
		FilterExpr:  strings.Join(expr, " "),
		DurationSec: p.DurationSec,
		MaxPackets:  p.MaxPackets,
		SnapLen:     SnapLen,
		State:       StateRunning,
		StartedBy:   by,
		StartedAt:   s.nowFn().Format("15:04:05"),
		Packets:     []Packet{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.active = c
	s.cancel = cancel
	s.mu.Unlock()

	go s.run(ctx, c, expr, p.SaveFile)

	s.mu.Lock()
	out := snapshot(c)
	s.mu.Unlock()
	return out, nil
}

// SetInstallExecutor aponta a instalação sob demanda para um executor com
// prazo de gerenciador de pacote. Ver o campo installExec.
func (s *Service) SetInstallExecutor(e firewall.Executor) {
	if e != nil {
		s.installExec = e
	}
}

// Install instala o tcpdump. É botão explícito na tela, nunca automático: o
// appliance instala sozinho o que é pré-requisito do produto (nftables), e
// pergunta antes do que é ferramenta de diagnóstico que nem todo mundo quer na
// máquina — mesma regra do chrony.
func (s *Service) Install(ctx context.Context) error {
	err := bootstrapdeps.InstallPackages(ctx, s.installExec, "tcpdump")
	// Invalida o cache de disponibilidade: sem isto, a tela continuaria
	// dizendo "não instalado" por até um minuto DEPOIS de o admin instalar, e
	// ele clicaria de novo achando que falhou.
	s.mu.Lock()
	s.availUntil = time.Time{}
	s.mu.Unlock()
	return err
}

// FilePath devolve o caminho do .pcap de uma captura, se ele ainda existir.
func (s *Service) FilePath(id string) (string, bool) {
	if !reID.MatchString(id) {
		return "", false
	}
	p := filepath.Join(s.dir, id+".pcap")
	st, err := os.Stat(p)
	if err != nil || st.IsDir() {
		return "", false
	}
	return p, true
}

// ─── execução ────────────────────────────────────────────────────────────────

func (s *Service) run(ctx context.Context, c *Capture, expr []string, keepFile bool) {
	if s.exec.IsDryRun() {
		s.finish(c, StateDone, "dry-run: nenhuma captura foi executada.")
		return
	}
	if err := s.ensureDir(); err != nil {
		s.finish(c, StateError, "não consegui preparar o diretório de captura: "+err.Error())
		return
	}
	file := filepath.Join(s.dir, c.ID+".pcap")

	args := []string{
		"-i", c.Interface,
		"-s", strconv.Itoa(SnapLen),
		"-c", strconv.Itoa(c.MaxPackets),
		// -U grava pacote a pacote. Sem ele, o buffer do tcpdump só vai a
		// disco quando enche — e uma captura abortada (ou que termina pelo
		// prazo) devolveria um arquivo vazio, que é o pior resultado possível
		// para quem estava justamente diagnosticando.
		"-U",
		"-w", file,
	}
	args = append(args, expr...)

	// O prazo é do LinkGuard, não do tcpdump: `-c` faz ele sair sozinho quando
	// junta pacote suficiente, mas se o tráfego for raro ele esperaria para
	// sempre. O contexto com deadline é o que fecha a janela de tempo, e o
	// CommandContext mata o processo quando ele fecha.
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(c.DurationSec)*time.Second)
	defer cancel()

	_, err := s.capExec.Execute(runCtx, "tcpdump", args...)
	aborted := ctx.Err() != nil
	// Sair por deadline/kill é o caminho NORMAL desta feature (a janela
	// fechou), então erro de execução só importa se não sobrou arquivo.
	st, statErr := os.Stat(file)
	if statErr != nil || st.Size() == 0 {
		_ = os.Remove(file)
		s.finish(c, StateError, captureFailureMessage(err, statErr, s.dir))
		return
	}

	packets, summary, perr := s.readBack(file)
	if perr != nil {
		s.finish(c, StateError, "capturei os pacotes mas não consegui ler o arquivo de volta: "+perr.Error())
		return
	}

	s.mu.Lock()
	c.Summary = summary
	if len(packets) > MaxRows {
		c.Packets = packets[:MaxRows]
		c.Truncated = true
	} else {
		c.Packets = packets
	}
	c.RowsShown = len(c.Packets)
	if keepFile {
		c.HasFile = true
		c.FileBytes = st.Size()
	}
	s.mu.Unlock()

	if !keepFile {
		if err := os.Remove(file); err != nil {
			slog.Warn("pktcapture: não consegui remover o .pcap temporário", "arquivo", file, "err", err)
		}
	}

	state, msg := StateDone, doneMessage(summary, c.Truncated)
	if aborted {
		state, msg = StateAborted, fmt.Sprintf("Captura interrompida. %s", doneMessage(summary, c.Truncated))
	}
	s.finish(c, state, msg)
}

// readBack lê o .pcap de volta em texto. É uma segunda invocação do tcpdump, e
// não uma segunda captura: garante que a tabela mostrada e o arquivo baixado
// descrevem exatamente os mesmos pacotes.
func (s *Service) readBack(file string) ([]Packet, Summary, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := s.exec.ExecuteRead(ctx, "tcpdump", "-r", file, "-nn", "-tt")
	if err != nil {
		// Arquivo truncado (captura abortada no meio de um registro) faz o
		// tcpdump sair diferente de zero DEPOIS de imprimir tudo que
		// conseguiu ler. Descartar essa saída perderia justamente a captura
		// que o admin interrompeu porque já tinha visto o que queria.
		if strings.TrimSpace(out) == "" {
			return nil, Summary{}, err
		}
		slog.Info("pktcapture: tcpdump -r saiu com erro mas imprimiu linhas; usando o que veio", "err", err)
	}
	packets := ParseLines(out)
	return packets, Summarize(packets), nil
}

func (s *Service) finish(c *Capture, state, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.State = state
	c.Message = msg
	c.EndedAt = s.nowFn().Format("15:04:05")
}

// ensureDir cria o diretório das capturas e, quando o usuário `tcpdump`
// existe, entrega o diretório a ele.
//
// POR QUÊ. O tcpdump do Debian larga privilégio para o usuário `tcpdump` antes
// de abrir o arquivo de saída. Rodando como root num diretório root:root 0700,
// o efeito é a captura "funcionar" e o arquivo não aparecer — falha silenciosa
// e confusa. Entregar o diretório ao usuário para o qual ele mesmo vai
// rebaixar resolve isso sem precisar mantê-lo privilegiado com `-Z root`, que
// seria o caminho fácil e o errado: o dissecador do tcpdump é superfície
// histórica de CVE, e ele roda sobre tráfego hostil por definição aqui.
func (s *Service) ensureDir() error {
	if err := os.MkdirAll(s.dir, 0o750); err != nil {
		return err
	}
	u, err := user.Lookup("tcpdump")
	if err != nil {
		// Sem o usuário, o tcpdump não rebaixa e escreve como root. Não é erro.
		return nil
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return nil
	}
	if err := os.Chown(s.dir, uid, gid); err != nil {
		slog.Warn("pktcapture: diretório de captura não pôde ser entregue ao usuário tcpdump; "+
			"se a captura sair vazia, é isto", "dir", s.dir, "err", err)
	}
	return nil
}

// Sweep apaga .pcap vencido. Roda no boot e a cada consulta de status — sem
// goroutine própria, porque o custo é um ReadDir e a alternativa seria mais uma
// rotina de fundo para varrer um diretório que quase sempre está vazio.
func (s *Service) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
}

func (s *Service) sweepLocked() {
	if s.exec.IsDryRun() {
		return
	}
	now := s.nowFn()
	if !s.lastSweep.IsZero() && now.Sub(s.lastSweep) < sweepTTL {
		return
	}
	s.lastSweep = now
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return // diretório ainda não existe: nada a varrer
	}
	cutoff := now.Add(-FileTTL)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pcap") {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		path := filepath.Join(s.dir, e.Name())
		if err := os.Remove(path); err != nil {
			slog.Warn("pktcapture: não consegui remover captura vencida", "arquivo", path, "err", err)
			continue
		}
		// Se o que venceu é o arquivo da captura em memória, o painel precisa
		// parar de oferecer download — senão o botão existe e devolve 404.
		if s.active != nil && e.Name() == s.active.ID+".pcap" {
			s.active.HasFile = false
			s.active.FileBytes = 0
		}
	}
}

// ─── construção do filtro ────────────────────────────────────────────────────

// BuildExpr transforma o filtro por campos na expressão que o tcpdump recebe,
// um token por argv. Devolve erro em vez de silenciosamente ignorar campo
// inválido: filtro que não é o que o admin pediu produz diagnóstico errado, que
// é pior que nenhum.
func BuildExpr(f Filter) ([]string, error) {
	var parts [][]string

	switch f.Direction {
	case "", "any", "from", "to":
	default:
		return nil, fmt.Errorf("direção inválida")
	}

	switch strings.ToLower(f.Proto) {
	case "":
	case "tcp", "udp", "icmp":
		parts = append(parts, []string{strings.ToLower(f.Proto)})
	default:
		return nil, fmt.Errorf("protocolo inválido")
	}

	if h := strings.TrimSpace(f.Host); h != "" {
		keyword := "host"
		if strings.Contains(h, "/") {
			if _, _, err := net.ParseCIDR(h); err != nil {
				return nil, fmt.Errorf("host inválido")
			}
			keyword = "net"
		} else if net.ParseIP(h) == nil {
			return nil, fmt.Errorf("host inválido")
		}
		parts = append(parts, append(dirPrefix(f.Direction), keyword, h))
	}

	if f.Port != 0 {
		if f.Port < 1 || f.Port > 65535 {
			return nil, fmt.Errorf("porta inválida")
		}
		if strings.ToLower(f.Proto) == "icmp" {
			return nil, fmt.Errorf("icmp não tem porta")
		}
		parts = append(parts, append(dirPrefix(f.Direction), "port", strconv.Itoa(f.Port)))
	}

	var expr []string
	for i, p := range parts {
		if i > 0 {
			expr = append(expr, "and")
		}
		expr = append(expr, p...)
	}

	// Defesa em profundidade: nenhum token pode começar com "-", ou ele deixa
	// de ser filtro e vira flag do tcpdump. Os campos já são validados acima;
	// isto é a rede que sobrevive a alguém acrescentar um campo novo sem
	// lembrar da regra.
	for _, tok := range expr {
		if strings.HasPrefix(tok, "-") {
			return nil, fmt.Errorf("filtro inválido")
		}
	}
	return expr, nil
}

func dirPrefix(dir string) []string {
	switch dir {
	case "from":
		return []string{"src"}
	case "to":
		return []string{"dst"}
	default:
		return nil
	}
}

// ─── mensagens ───────────────────────────────────────────────────────────────

// captureFailureMessage explica a falha mais comum em vez de repassar o erro
// cru do exec. Arquivo ausente depois de um tcpdump que "rodou" tem três
// causas de verdade, e as três têm conserto diferente.
func captureFailureMessage(runErr, statErr error, dir string) string {
	switch {
	case runErr != nil && strings.Contains(runErr.Error(), "executable file not found"):
		return "o tcpdump não está instalado nesta máquina."
	case runErr != nil && strings.Contains(strings.ToLower(runErr.Error()), "no such device"):
		return "a interface não existe (ou foi renomeada)."
	case runErr != nil && strings.Contains(strings.ToLower(runErr.Error()), "permission denied"):
		return "sem permissão para capturar nesta interface."
	}
	base := fmt.Sprintf("a captura terminou sem gravar nada em %s. ", dir)
	base += "As causas conhecidas são o perfil AppArmor do tcpdump (usr.sbin.tcpdump) barrando a escrita — " +
		"confira com `dmesg | grep DENIED` — ou o diretório não ser gravável pelo usuário `tcpdump`, " +
		"para o qual o tcpdump do Debian rebaixa privilégio antes de abrir o arquivo."
	if runErr != nil {
		base += " Erro do tcpdump: " + runErr.Error()
	} else if statErr != nil {
		base += " (" + statErr.Error() + ")"
	}
	return base
}

func doneMessage(s Summary, truncated bool) string {
	if s.Packets == 0 {
		return "Nenhum pacote casou com o filtro na janela pedida."
	}
	msg := fmt.Sprintf("%d pacotes em %.1fs.", s.Packets, s.DurationSec)
	if len(s.Unanswered) > 0 {
		msg += fmt.Sprintf(" %d conexão(ões) sem resposta.", len(s.Unanswered))
	}
	if truncated {
		msg += fmt.Sprintf(" A tabela mostra as primeiras %d linhas; o resumo é sobre a captura inteira.", MaxRows)
	}
	return msg
}

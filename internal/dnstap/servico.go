package dnstap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// O coletor: escuta o socket que o unbound escreve e alimenta o mapa.
//
// QUEM CONECTA É O UNBOUND. Ele é o cliente do Frame Streams; a gente cria o
// socket unix e fica ouvindo. Isso importa para o desenho: se o coletor não
// estiver de pé, o unbound simplesmente não consegue entregar — e não trava,
// não enfileira sem limite e não deixa de responder consulta. dnstap foi feito
// para poder ser ignorado.
//
// O SOCKET VIVE ONDE O UNBOUND ALCANÇA. O pacote do Debian compila com
// `--with-dnstap-socket-path=/run/dnstap.sock`, e o unbound roda com o perfil
// AppArmor do pacote — que é a razão de o caminho ser esse e não um dentro de
// /var/lib/linkguard-fw. Mudar o caminho exigiria mexer no perfil alheio, que é
// a mesma armadilha que a captura de pacotes já pagou com o tcpdump.

const (
	// SocketPath é onde o coletor escuta e o unbound entrega.
	//
	// NÃO É O CAMINHO COMPILADO POR PADRÃO (/run/dnstap.sock), e a razão foi
	// medida, não suposta: o serviço roda com ProtectSystem=strict, que deixa
	// /run somente-leitura — criar o socket lá falha com "read-only file
	// system". O diretório abaixo é criado pelo systemd via RuntimeDirectory=,
	// já gravável e removido quando o serviço para.
	//
	// E o unbound só alcança este caminho porque o produto acrescenta a regra
	// no ponto de extensão documentado do perfil AppArmor dele — ver
	// EscreverRegraAppArmor. O perfil de fábrica permite exatamente três
	// caminhos em /run (unbound.pid, unbound.ctl e systemd/notify), nenhum de
	// dnstap: sem a regra, nem o caminho compilado por padrão funcionaria.
	SocketPath = "/run/linkguard-fw/dnstap.sock"

	// intervaloLimpeza é de quanto em quanto tempo as entradas vencidas saem.
	intervaloLimpeza = 5 * time.Minute
)

// Servico escuta o socket e mantém o mapa.
type Servico struct {
	caminho string
	mapa    *Mapa
	// observador é avisado de cada resposta aprendida. Ver SetObservador.
	observador func(*Resposta)
}

// NovoServico cria o coletor.
func NovoServico() *Servico {
	return &Servico{caminho: SocketPath, mapa: NovoMapa()}
}

// SetCaminho aponta o socket para outro lugar. Existe para o teste usar
// t.TempDir(); em produção o valor vem de SocketPath.
func (s *Servico) SetCaminho(p string) { s.caminho = p }

// Mapa devolve o mapa endereço → nome.
func (s *Servico) Mapa() *Mapa { return s.mapa }

// SetObservador liga um segundo consumidor das respostas aprendidas.
//
// O CONTRATO É NÃO BLOQUEAR, e não é recomendação. O observador é chamado de
// dentro do laço que lê o frame stream do unbound, que é o mesmo laço que drena
// o socket unix: parar ali para de drenar, o buffer enche e o unbound passa a
// DESCARTAR entrega. dnstap foi feito para poder ser ignorado (ver o cabeçalho
// deste arquivo), e o preço de esquecer isso é contrapressão no resolver da
// rede inteira por causa de um consumidor lento.
//
// E O CONTRATO É TAMBÉM NÃO ENTRAR EM PÂNICO. O laço que chama isto é o que
// drena o socket: um pânico no observador derruba a goroutine da conexão e o
// mapa para de aprender. A chamada é envolvida em recover mesmo assim — o ponto
// deste arquivo é que o consumidor não pode machucar o caminho do resolver, e
// isso tem de valer por construção, não por inspeção do consumidor da vez.
//
// Chamar ANTES de Run: o campo é lido pelas goroutines de conexão sem lock, e
// o único ponto em que trocá-lo é seguro é antes de existir conexão.
func (s *Servico) SetObservador(f func(*Resposta)) { s.observador = f }

// Run escuta até o contexto acabar.
//
// Erro ao criar o socket NÃO derruba o produto: dnstap é opt-in e acessório. O
// que ele não pode fazer é falhar em silêncio — sem o registro abaixo, o admin
// ligaria o recurso na tela e não teria como saber por que o mapa fica vazio.
func (s *Servico) Run(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(s.caminho), 0o755); err != nil {
		return err
	}
	// Socket de execução anterior fica para trás quando o processo morre sem
	// fechar; sem isto o bind falha com "address already in use" depois de todo
	// crash.
	_ = os.Remove(s.caminho)

	ln, err := net.Listen("unix", s.caminho)
	if err != nil {
		return err
	}
	defer ln.Close()
	// O unbound roda como outro usuário: sem isto ele não consegue conectar, e
	// o sintoma é um mapa vazio sem nenhuma mensagem de erro em lugar nenhum.
	if err := os.Chmod(s.caminho, 0o666); err != nil {
		slog.Warn("dnstap: não consegui abrir a permissão do socket; o unbound pode não conseguir entregar", "err", err)
	}
	slog.Info("dnstap: coletor ouvindo", "socket", s.caminho)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	limpeza := time.NewTicker(intervaloLimpeza)
	defer limpeza.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-limpeza.C:
				if n := s.mapa.Limpar(); n > 0 {
					slog.Debug("dnstap: entradas vencidas removidas", "n", n)
				}
			}
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.atender(conn)
	}
}

// atender consome uma conexão do unbound até ela acabar.
func (s *Servico) atender(conn net.Conn) {
	defer conn.Close()
	fr := NewReader(conn)
	for {
		quadro, err := fr.Next()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				slog.Debug("dnstap: conexão encerrada", "err", err)
			}
			return
		}
		fio, err := RespostaDNS(quadro)
		if err != nil || fio == nil {
			continue
		}
		r, err := Extrair(fio)
		if err != nil || r == nil {
			continue
		}
		s.mapa.Aprender(r)
		// FORA do lock do mapa, e o lugar não é acidente: Aprender solta o
		// m.mu no defer dele, e chamar o observador lá dentro deixaria a tela
		// (Mapa.Nome, Mapa.Amostra) e a limpeza de 5 minutos presas ao que o
		// observador fizer. Mesmo aqui fora, este laço é o que DRENA o socket
		// do unbound — por isso o contrato de SetObservador é não bloquear.
		s.avisarObservador(r)
	}
}

// avisarObservador chama o consumidor com recover em volta.
//
// Três linhas que compram uma garantia por CONSTRUÇÃO. Sem elas, um pânico
// dentro do observador derruba a goroutine desta conexão — quer dizer, o
// consumidor de dnstap machucando o caminho do resolver, que é exatamente o que
// o cabeçalho deste arquivo diz não poder acontecer. Que o observador de hoje
// não tenha como entrar em pânico é uma propriedade do observador de hoje.
func (s *Servico) avisarObservador(r *Resposta) {
	if s.observador == nil {
		return
	}
	defer func() {
		p := recover()
		if p != nil {
			slog.Error("dnstap: o observador entrou em pânico", "panico", p)
		}
	}()
	s.observador(r)
}

// A regra de AppArmor que deixa o unbound entregar (issue #116).
//
// MEDIDO NO PERFIL DE FÁBRICA do Debian 13: usr.sbin.unbound permite três
// caminhos em /run — unbound.pid, unbound.ctl e systemd/notify. Nenhum socket
// de dnstap, nem sequer o /run/dnstap.sock que o próprio pacote compilou como
// padrão. Sem uma regra a mais, dnstap não funciona nesta distribuição, ponto.
//
// O ARQUIVO É O PONTO DE EXTENSÃO DOCUMENTADO, e isso é o que separa esta
// mudança de mexer em perfil alheio: o perfil de fábrica termina com
// `#include <local/usr.sbin.unbound>`, e /etc/apparmor.d/local/ existe com um
// README dizendo que é ali que adições locais moram. A gente escreve o nosso
// arquivo, não edita o deles — um upgrade do pacote unbound não sobrescreve
// isto, e remover o recurso é apagar um arquivo.

// CaminhoRegraAppArmor é o arquivo local que autoriza o unbound.
const CaminhoRegraAppArmor = "/etc/apparmor.d/local/usr.sbin.unbound"

// RegraAppArmor é o conteúdo escrito.
const RegraAppArmor = `# Escrito pelo LinkGuard FW (issue #116).
# Sem esta linha o unbound não consegue entregar as respostas de DNS ao coletor,
# e o mapa endereço → nome fica vazio para sempre — sem erro visível, porque
# quem recusa é o AppArmor e não o unbound.
` + SocketPath + ` rw,
`

// EscreverRegraAppArmor grava a regra e recarrega o perfil.
//
// Devolve erro em vez de engolir: sem a regra o recurso NÃO FUNCIONA, e o
// sintoma é um mapa vazio que parece "ninguém consultou nada". Quem liga o
// recurso precisa saber na hora.
func EscreverRegraAppArmor(exec interface {
	Execute(ctx context.Context, cmd string, args ...string) (string, error)
	WriteFile(path string, data []byte, perm os.FileMode) error
}, ctx context.Context) error {
	if err := exec.WriteFile(CaminhoRegraAppArmor, []byte(RegraAppArmor), 0o644); err != nil {
		return fmt.Errorf("escrever a regra de AppArmor do unbound: %w", err)
	}
	// Recarrega só o perfil do unbound. `apparmor_parser -r` é idempotente.
	if out, err := exec.Execute(ctx, "apparmor_parser", "-r", "/etc/apparmor.d/usr.sbin.unbound"); err != nil {
		return fmt.Errorf("recarregar o perfil de AppArmor do unbound: %w (%s)", err, strings.TrimSpace(out))
	}
	return nil
}

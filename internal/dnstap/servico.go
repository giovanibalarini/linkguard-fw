package dnstap

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
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
	// SocketPath é onde o unbound do Debian espera entregar.
	SocketPath = "/run/dnstap.sock"

	// intervaloLimpeza é de quanto em quanto tempo as entradas vencidas saem.
	intervaloLimpeza = 5 * time.Minute
)

// Servico escuta o socket e mantém o mapa.
type Servico struct {
	caminho string
	mapa    *Mapa
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
	}
}

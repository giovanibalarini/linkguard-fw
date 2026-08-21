package keaunbound

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
)

// A reserva de DHCP com endereço IPv6 (issue #152).
//
// A FORMA DO DEFEITO, que é o que estes testes prendem: a API aceitava o valor,
// respondia 200 porque o apply é assíncrono, e o `kea-dhcp4 -t` recusava a
// config INTEIRA depois. Nada era aplicado — nem faixa nova, nem DNS aos
// clientes, nem outra reserva — e a linha ruim continuava no banco, refeita em
// todo apply seguinte. O admin ficava com o subsistema travado e a única
// mensagem disponível era a do kea, que não nomeia a reserva culpada.

func TestGeracaoRecusaReservaSemIPv4ENomeiaOCulpado(t *testing.T) {
	res := []netsvc.Reservation{
		{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.3.10", Hostname: "ok"},
		{MAC: "aa:bb:cc:dd:ee:02", IP: "fd00::50", Hostname: "problema"},
	}
	err := reservasSemIPv4(res)
	if err == nil {
		t.Fatal("a geração aceitou uma reserva IPv6: o apply falharia no kea, sem dizer qual reserva")
	}
	// O MAC precisa estar na mensagem: a lista da tela é POR MAC, então dizer só
	// o endereço deixa o admin sabendo que há um problema e sem saber qual linha
	// apagar. Mesma decisão da #59.
	if !strings.Contains(err.Error(), "aa:bb:cc:dd:ee:02") {
		t.Errorf("a mensagem não nomeia o aparelho culpado: %v", err)
	}
	if !strings.Contains(err.Error(), "fd00::50") {
		t.Errorf("a mensagem não mostra o endereço recusado: %v", err)
	}
}

func TestGeracaoAceitaSoIPv4(t *testing.T) {
	res := []netsvc.Reservation{
		{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.3.10"},
		{MAC: "aa:bb:cc:dd:ee:02", IP: "192.168.3.11"},
	}
	if err := reservasSemIPv4(res); err != nil {
		t.Errorf("reservas válidas recusadas: %v", err)
	}
	if err := reservasSemIPv4(nil); err != nil {
		t.Errorf("lista vazia recusada: %v", err)
	}
}

func TestApplyRecusaEnderecoQueNaoExisteNaMaquina(t *testing.T) {
	// A GUARDA QUE IMPEDE UM APAGÃO, e não só um travamento (#161).
	//
	// O gateway vira `interface: <addr>` no unbound.conf — o endereço em que ele
	// ESCUTA. Medido: kea-dhcp4 -t aceita e unbound-checkconf responde "no
	// errors", porque nenhum dos dois checa bindabilidade. Os arquivos eram
	// escritos, o unbound reiniciava e morria com "can't bind socket", e o
	// arquivo ruim ficava em disco: a máquina voltava do reboot sem DNS.
	s := &Service{exec: &execSemEndereco{}}
	if err := s.enderecoBindavel(context.Background(), "203.0.113.9"); err == nil {
		t.Fatal("aceitou escutar num endereço que a máquina não tem")
	}
	if err := s.enderecoBindavel(context.Background(), "192.168.3.3"); err != nil {
		t.Errorf("recusou um endereço que a máquina tem: %v", err)
	}
	// Sem gateway não é erro: o unbound escuta só em 127.0.0.1, que é
	// configuração legítima de caixa sem LAN servida.
	if err := s.enderecoBindavel(context.Background(), ""); err != nil {
		t.Errorf("gateway vazio virou erro: %v", err)
	}
}

func TestNaoConseguirPerguntarNaoViraPodeEscrever(t *testing.T) {
	// Um apply que segue às cegas aqui é o apagão de volta. A alternativa —
	// recusar — custa uma alteração adiada, que é infinitamente mais barato.
	s := &Service{exec: &execQueFalha{}}
	if err := s.enderecoBindavel(context.Background(), "192.168.3.3"); err == nil {
		t.Error("a leitura falhou e o apply seguiu adiante")
	}
}

type execSemEndereco struct{ recExec }

func (e *execSemEndereco) ExecuteRead(_ context.Context, cmd string, _ ...string) (string, error) {
	if cmd == "ip" {
		return "2: br10    inet 192.168.3.3/24 brd 192.168.3.255 scope global br10\n", nil
	}
	return "", nil
}

type execQueFalha struct{ recExec }

func (e *execQueFalha) ExecuteRead(context.Context, string, ...string) (string, error) {
	return "", errors.New("ip: comando não encontrado")
}

package keaunbound

import (
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

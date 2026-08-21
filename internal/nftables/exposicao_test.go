package nftables

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func servicoComExposicao(t *testing.T, valorSysctl string) (*Service, *execGravador) {
	t.Helper()
	e := &execGravador{}
	s := servicoComExec(e)
	if valorSysctl == "ausente" {
		s.SetIPv6ForwardingPath(filepath.Join(t.TempDir(), "nao-existe"))
		return s, e
	}
	p := filepath.Join(t.TempDir(), "forwarding")
	if err := os.WriteFile(p, []byte(valorSysctl), 0o644); err != nil {
		t.Fatal(err)
	}
	s.SetIPv6ForwardingPath(p)
	return s, e
}

func TestExposicaoDizOEstadoDoForwardingIPv6(t *testing.T) {
	// TRÊS ESTADOS, E O TERCEIRO É O QUE IMPORTA: "não consegui ler" não é
	// "está desligado". Responder "off" a uma leitura que falhou seria inventar
	// a resposta tranquilizadora, que é o oposto do que esta fase entrega.
	for _, c := range []struct{ valor, quer string }{
		{"0\n", "off"},
		{"1\n", "on"},
		{"2\n", "on"},
		{"ausente", "unknown"},
		{"", "unknown"},
	} {
		s, _ := servicoComExposicao(t, c.valor)
		if got := s.ExposureNow().IPv6Forwarding; got != c.quer {
			t.Errorf("sysctl %q: veio %q, queria %q", c.valor, got, c.quer)
		}
	}
}

func TestExposicaoAnunciaAsPortasAbertasNaWAN(t *testing.T) {
	s, _ := servicoComExposicao(t, "0\n")
	s.SetWANInterfacesSource(func() ([]string, error) { return []string{"wan0", "wan1"}, nil })
	s.SetAdminAccessSource(func() (AdminAccess, error) {
		return AdminAccess{SSHPorts: []int{2222}, PanelPort: 9997}, nil
	})

	e := s.ExposureNow()
	if !e.ManagementOpenOnWAN {
		t.Error("a liberação de gerência existe na chain e a tela não a anuncia")
	}
	if !reflect.DeepEqual(e.ManagementPorts, []int{2222, 9997}) {
		t.Errorf("portas anunciadas: %v", e.ManagementPorts)
	}
	if !reflect.DeepEqual(e.WANInterfaces, []string{"wan0", "wan1"}) {
		t.Errorf("interfaces anunciadas: %v", e.WANInterfaces)
	}
}

func TestSemWANNadaEhAnunciadoComoAberto(t *testing.T) {
	// Sem WAN conhecida a proteção não emite regra nenhuma — então não há
	// liberação a anunciar. Dizer "aberto" aqui seria verdade pelo motivo
	// errado: está aberto porque não há regra, não porque a liberação existe.
	s, _ := servicoComExposicao(t, "0\n")
	s.SetWANInterfacesSource(func() ([]string, error) { return nil, nil })
	if e := s.ExposureNow(); e.ManagementOpenOnWAN || len(e.WANInterfaces) > 0 {
		t.Errorf("anunciou exposição sem WAN: %+v", e)
	}
}

func TestNaoSaberAsPortasVIRAERRONaTela(t *testing.T) {
	// Este é o estado em que a caixa está MAIS ABERTA: sem saber as portas,
	// reconcileInputChain cancela a proteção inteira. É justamente quando o
	// painel teria a melhor cara, e por isso é quando ele mais precisa falar.
	s, _ := servicoComExposicao(t, "0\n")
	s.SetWANInterfacesSource(func() ([]string, error) { return []string{"wan0"}, nil })
	s.SetAdminAccessSource(func() (AdminAccess, error) { return AdminAccess{}, errors.New("banco fora") })

	e := s.ExposureNow()
	if e.Error == "" {
		t.Error("a leitura falhou e a tela não teria como saber")
	}
	if e.ManagementOpenOnWAN {
		t.Error("anunciou a liberação que a reconciliação cancelou")
	}
}

func TestAExcecaoDoBloqueioPorHostEhDitaJunto(t *testing.T) {
	// Dizer "as regras por endereço só valem IPv4" sem a exceção assustaria à
	// toa; dizer a exceção sem a regra seria a mentira de sempre.
	s, _ := servicoComExposicao(t, "0\n")
	e := s.ExposureNow()
	if !e.AddressRulesIPv4Only {
		t.Error("a tela deixaria de avisar que regra por endereço não casa IPv6")
	}
	if !e.HostBlockCoversIPv6 {
		t.Error("a exceção da fase 2 sumiu: bloqueio de host vale nas duas famílias")
	}
	_ = context.Background()
}

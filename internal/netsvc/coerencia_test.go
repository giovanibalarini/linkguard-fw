package netsvc

import "testing"

// A coerência entre os campos da tela de DHCP/DNS (issue #161).
//
// Cada caso abaixo foi MEDIDO nos binários do Debian 13 antes de virar guarda:
// o que o kea-dhcp4 2.6.3 e o unbound-checkconf 1.22.0 recusam de verdade, e
// não o que a man page sugere.

func TestGatewayForaDaSubredeEhRecusado(t *testing.T) {
	// O kea ACEITA um gateway fora da sub-rede sem dizer nada — quem quebra é o
	// unbound, tentando escutar num endereço que a máquina não tem. Por isso a
	// checagem é nossa, e não deles.
	err := ValidaConfig(Config{SubnetCIDR: "192.168.3.0/24", Gateway: "192.168.0.3"})
	if err == nil {
		t.Fatal("gateway fora da sub-rede foi aceito")
	}
	if ValidaConfig(Config{SubnetCIDR: "192.168.3.0/24", Gateway: "192.168.3.3"}) != nil {
		t.Error("gateway dentro da sub-rede foi recusado")
	}
}

func TestGatewayIPv6EhRecusadoComOMotivo(t *testing.T) {
	err := ValidaConfig(Config{SubnetCIDR: "192.168.3.0/24", Gateway: "fd00::3"})
	if err == nil {
		t.Fatal("gateway IPv6 foi aceito: o unbound escutaria nele e o DNS da LAN cairia")
	}
}

func TestFaixaForaDaSubredeEhRecusada(t *testing.T) {
	// Medido: "a pool of type V4 ... does not match the prefix of a subnet".
	base := Config{SubnetCIDR: "192.168.3.0/24", Gateway: "192.168.3.3"}
	for _, c := range []Config{
		{SubnetCIDR: base.SubnetCIDR, Gateway: base.Gateway, RangeStart: "10.0.0.10", RangeEnd: "192.168.3.200"},
		{SubnetCIDR: base.SubnetCIDR, Gateway: base.Gateway, RangeStart: "192.168.3.100", RangeEnd: "10.0.0.50"},
	} {
		if ValidaConfig(c) == nil {
			t.Errorf("faixa fora da sub-rede aceita: %q-%q", c.RangeStart, c.RangeEnd)
		}
	}
	ok := Config{SubnetCIDR: base.SubnetCIDR, Gateway: base.Gateway, RangeStart: "192.168.3.100", RangeEnd: "192.168.3.200"}
	if err := ValidaConfig(ok); err != nil {
		t.Errorf("faixa válida recusada: %v", err)
	}
}

func TestSubredeVaziaNaoImpedeOResto(t *testing.T) {
	// Quem ainda não escolheu a rede não pode ser impedido de preencher o
	// formulário — o kea só reclama quando as duas coisas existem.
	if err := ValidaConfig(Config{Gateway: "192.168.3.3", RangeStart: "192.168.3.10"}); err != nil {
		t.Errorf("sem sub-rede definida, a validação atrapalhou: %v", err)
	}
}

func TestDNSAosClientesPrecisaSerIPv4(t *testing.T) {
	c := Config{SubnetCIDR: "192.168.3.0/24", Gateway: "192.168.3.3", DNSToClients: []string{"1.1.1.1", "fd00::1"}}
	if ValidaConfig(c) == nil {
		t.Error("DNS IPv6 entregue a clientes DHCPv4 foi aceito")
	}
}

func TestDominioLocalComRotuloInvalido(t *testing.T) {
	// Fronteira medida no unbound 1.22.0: rótulo de 63 caracteres passa, 64
	// recusa; rótulo vazio ("a..b") recusa.
	base := Config{SubnetCIDR: "192.168.3.0/24", Gateway: "192.168.3.3"}
	r63 := ""
	for i := 0; i < 63; i++ {
		r63 += "a"
	}
	base.DomainSuffix = r63 + ".local"
	if err := ValidaConfig(base); err != nil {
		t.Errorf("rótulo de 63 caracteres recusado: %v", err)
	}
	base.DomainSuffix = r63 + "a.local"
	if ValidaConfig(base) == nil {
		t.Error("rótulo de 64 caracteres aceito: o unbound recusa a config inteira")
	}
	base.DomainSuffix = "casa..local"
	if ValidaConfig(base) == nil {
		t.Error("rótulo vazio aceito: um ponto digitado duas vezes travaria todo apply")
	}
}

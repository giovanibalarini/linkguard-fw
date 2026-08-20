package nftables

import (
	"context"
	"strings"
	"testing"
)

func regrasComoTexto(rs [][]string) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, strings.Join(r, " "))
	}
	return out
}

func TestRedirecionamentoCapturaUDPeTCP(t *testing.T) {
	// Só UDP não basta: resposta grande e transferência de zona usam TCP, e um
	// cliente que caia para TCP escaparia do resolver local sem ninguém notar.
	got := regrasComoTexto(dnsRedirectRules(DNSGuardConfig{
		ForceLocal: true, LANInterface: "br10", Resolver: "192.168.3.3",
	}))
	if len(got) != 2 {
		t.Fatalf("queria uma regra por protocolo, veio %d: %v", len(got), got)
	}
	if got[0] != `iifname "br10" udp dport 53 counter dnat ip to 192.168.3.3:53` {
		t.Errorf("regra udp: %q", got[0])
	}
	if got[1] != `iifname "br10" tcp dport 53 counter dnat ip to 192.168.3.3:53` {
		t.Errorf("regra tcp: %q", got[1])
	}
}

func TestDesligadoNaoGeraRegra(t *testing.T) {
	// Desligar no painel tem de desligar de verdade: a chain é reconstruída
	// vazia, e não deixada como estava.
	if got := dnsRedirectRules(DNSGuardConfig{ForceLocal: false, LANInterface: "br10", Resolver: "192.168.3.3"}); len(got) != 0 {
		t.Errorf("redirecionamento desligado gerou regras: %v", got)
	}
	if got := dnsGuardRules(DNSGuardConfig{BlockDoT: false, LANInterface: "br10"}); len(got) != 0 {
		t.Errorf("recusa de DoT desligada gerou regras: %v", got)
	}
}

func TestSemResolverNaoRedireciona(t *testing.T) {
	// Redirecionar para um endereço inválido capturaria a consulta e a jogaria
	// no vazio — a LAN inteira ficaria sem DNS, que é bem pior que a fuga.
	casos := []string{"", "nao-e-ip", "2001:db8::1"}
	for _, r := range casos {
		if got := dnsRedirectRules(DNSGuardConfig{ForceLocal: true, LANInterface: "br10", Resolver: r}); len(got) != 0 {
			t.Errorf("resolver %q gerou regras: %v", r, got)
		}
	}
}

func TestSemInterfaceDeLANNaoRedireciona(t *testing.T) {
	if got := dnsRedirectRules(DNSGuardConfig{ForceLocal: true, LANInterface: "", Resolver: "192.168.3.3"}); len(got) != 0 {
		t.Errorf("sem interface gerou regras: %v", got)
	}
}

func TestExcecoesEntramNaRegra(t *testing.T) {
	// Quem roda resolver próprio na LAN de propósito seria quebrado pelo
	// redirecionamento sem entender por quê.
	got := regrasComoTexto(dnsRedirectRules(DNSGuardConfig{
		ForceLocal: true, LANInterface: "br10", Resolver: "192.168.3.3",
		ExceptIPs: []string{"192.168.3.9", "192.168.3.10"},
	}))
	if !strings.Contains(got[0], `ip saddr != { 192.168.3.9, 192.168.3.10 }`) {
		t.Errorf("exceções não entraram: %q", got[0])
	}
}

func TestExcecoesInvalidasSaoDescartadas(t *testing.T) {
	// Um set vazio é recusado pelo nft e derrubaria a regra inteira.
	got := regrasComoTexto(dnsRedirectRules(DNSGuardConfig{
		ForceLocal: true, LANInterface: "br10", Resolver: "192.168.3.3",
		ExceptIPs: []string{"", "lixo", "2001:db8::1"},
	}))
	if strings.Contains(got[0], "saddr") {
		t.Errorf("exceção inválida virou regra: %q", got[0])
	}
}

func TestDoTEhRecusadoComRSTeNaoDescartado(t *testing.T) {
	// Descartado em silêncio deixa o cliente pendurado até o timeout antes de
	// tentar DNS comum — o usuário sente isso como internet lenta.
	got := regrasComoTexto(dnsGuardRules(DNSGuardConfig{BlockDoT: true, LANInterface: "br10"}))
	if len(got) != 1 {
		t.Fatalf("queria 1 regra, veio %v", got)
	}
	if !strings.Contains(got[0], "reject with tcp reset") {
		t.Errorf("DoT não é recusado com RST: %q", got[0])
	}
	if !strings.Contains(got[0], "tcp dport 853") {
		t.Errorf("porta errada: %q", got[0])
	}
}

func TestPrioridadesDasChains(t *testing.T) {
	// O redirecionamento vem DEPOIS do encaminhamento de porta (dstnat + 10):
	// um admin que publicou um DNS próprio por DNAT continua mandando nele.
	if !strings.Contains(dnsRedirectChainSpec, "dstnat + 10") {
		t.Errorf("redirecionamento não vem depois do DNAT: %q", dnsRedirectChainSpec)
	}
	// A recusa vem ANTES das regras do admin (filter - 10): é enforcement, do
	// mesmo jeito que os bloqueios administrativos da Fase C1 vencem sempre.
	if !strings.Contains(dnsGuardChainSpec, "filter - 10") {
		t.Errorf("recusa não vem antes das regras do admin: %q", dnsGuardChainSpec)
	}
}

func TestEnsureDNSGuardDryRunNaoExecuta(t *testing.T) {
	ex := &execFalso{dryRun: true}
	s := &Service{exec: ex}
	if err := s.EnsureDNSGuard(context.Background(), DNSGuardConfig{ForceLocal: true, LANInterface: "br10", Resolver: "192.168.3.3"}); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if len(ex.comandos) != 0 {
		t.Errorf("dry-run executou: %v", ex.comandos)
	}
}

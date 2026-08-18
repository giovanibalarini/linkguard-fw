package nftables

import (
	"strings"
	"testing"
)

// A lista de sobrevivência é o que separa "bloquear tudo" de "eu me tranquei
// fora" (issue #78). Estes testes existem para que ela seja revisável ANTES de
// ser ligada — e para que o que foi deixado de fora fique tão explícito quanto
// o que entrou.

func linhas(rs [][]string) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = strings.Join(r, " ")
	}
	return out
}

func contem(rs [][]string, trecho string) bool {
	for _, l := range linhas(rs) {
		if strings.Contains(l, trecho) {
			return true
		}
	}
	return false
}

// TestSurvivalNaoAceitaEstablished é a asserção mais importante do arquivo, e
// ela afirma uma AUSÊNCIA.
//
// Com `ct state established accept`, a sessão SSH do operador sobrevive ao
// próprio bloqueio: ele testa, vê tudo funcionando, confirma — e descobre na
// próxima reconexão, já sem rede embaixo. O teste dos 90 segundos passa a
// mentir, que é o modo de falha que reconcile.go:483-491 proíbe em código.
//
// Se alguém acrescentar `established` aqui um dia, este teste quebra e obriga a
// pessoa a ler o porquê. Que é exatamente o que se quer: a decisão é de
// desenho e está aberta na #78 (item D), não é detalhe para resolver no meio de
// outra mudança.
func TestSurvivalNaoAceitaEstablished(t *testing.T) {
	rs := SurvivalRules(AdminAccess{PanelPort: 9997, LANNetworks: []string{"192.168.3.0/24"}, WANIsDHCP: true})
	for _, l := range linhas(rs) {
		if strings.Contains(l, "established") {
			t.Fatalf("a lista aceita established: %q\n\n"+
				"Isso faz a sessão SSH do operador sobreviver ao próprio bloqueio, e o\n"+
				"teste da janela de 90 s deixa de provar qualquer coisa. Ver #78 item D\n"+
				"e o comentário de reconcile.go:483-491 antes de mudar isto.", l)
		}
	}
}

// TestSurvivalComecaPeloRelated: `related` continua sendo a primeira linha,
// como já é na chain de hoje. Ela é a mais barata e a mais universal — e é o
// que mantém o PMTUD e os erros de ICMP funcionando.
func TestSurvivalComecaPeloRelated(t *testing.T) {
	rs := SurvivalRules(AdminAccess{})
	if len(rs) == 0 {
		t.Fatal("lista vazia")
	}
	if got := strings.Join(rs[0], " "); got != "ct state related counter accept" {
		t.Errorf("primeira linha = %q, esperada a de related", got)
	}
}

// TestSurvivalSempreTemLoopbackESSH: são as duas que não dependem de
// configuração nenhuma. Um firewall que só protege o acesso quando o admin
// preencheu o campo certo é um firewall que guarda a armadilha armada.
func TestSurvivalSempreTemLoopbackESSH(t *testing.T) {
	rs := SurvivalRules(AdminAccess{}) // tudo no zero
	if !contem(rs, "iif lo counter accept") {
		t.Error("sem loopback: o painel em 127.0.0.1 ficaria inalcançável até por túnel SSH")
	}
	if !contem(rs, "tcp dport 22") {
		t.Error("sem SSH na porta padrão")
	}
}

// TestSurvivalIPv6VemAntesDoAcessoAdministrativo cobre uma ordem que parece
// arbitrária e não é: sem a descoberta de vizinhança, as linhas de SSH e painel
// são aceitas e NUNCA alcançadas por IPv6, porque a resolução falhou antes.
func TestSurvivalIPv6VemAntesDoAcessoAdministrativo(t *testing.T) {
	ls := linhas(SurvivalRules(AdminAccess{PanelPort: 9997}))
	iICMP, iTCP := -1, -1
	for i, l := range ls {
		if strings.Contains(l, "icmpv6") {
			iICMP = i
		}
		if strings.Contains(l, "tcp dport") && iTCP < 0 {
			iTCP = i
		}
	}
	if iICMP < 0 {
		t.Fatal("sem a linha de vizinhança IPv6: o IPv6 morreria inteiro e só ele")
	}
	if iTCP >= 0 && iICMP > iTCP {
		t.Errorf("vizinhança IPv6 (%d) depois do acesso administrativo (%d)", iICMP, iTCP)
	}
}

// TestSurvivalPortaDoPainelNaoEFixa: 9997 é o default do .deb, 8080 é o do
// binário, e quem põe um proxy na frente usa outra. Fixar o número aqui deixaria
// o anti-lockout mudo justamente em quem não usa o padrão.
func TestSurvivalPortaDoPainelNaoEFixa(t *testing.T) {
	if !contem(SurvivalRules(AdminAccess{PanelPort: 8443}), "8443") {
		t.Error("a porta configurada do painel não entrou")
	}
	if contem(SurvivalRules(AdminAccess{PanelPort: 0}), "9997") {
		t.Error("emitiu 9997 sem ninguém ter pedido")
	}
	// Painel na mesma porta do SSH não pode virar um set com o número repetido.
	ls := linhas(SurvivalRules(AdminAccess{SSHPort: 22, PanelPort: 22}))
	for _, l := range ls {
		if strings.Contains(l, "{ 22, 22 }") {
			t.Errorf("porta repetida no set: %q", l)
		}
	}
}

// TestSurvivalNaoAmarraInterface é a lição da #83, virada em asserção.
//
// Todo `iifname` deste projeto casa por NOME, e um nome inexistente carrega sem
// erro e nunca casa. Depois de um rename de NIC — que já aconteceu nesta
// produção, reconcile.go:26-28 — um anti-lockout amarrado à interface fica mudo
// e a política restritiva pega tudo, sem janela e sem auto-cura.
func TestSurvivalNaoAmarraInterface(t *testing.T) {
	for _, l := range linhas(SurvivalRules(AdminAccess{PanelPort: 9997})) {
		if strings.Contains(l, "iifname") {
			t.Errorf("regra de sobrevivência amarrada a nome de interface: %q\n"+
				"Um rename de NIC a deixaria muda depois de um reboot (#83).", l)
		}
	}
}

// TestSurvivalDHCPeDNSSoComRedeConfigurada: sem rede declarada, aceitar DHCP e
// DNS de qualquer origem abriria o resolver e o servidor de DHCP para a WAN.
func TestSurvivalDHCPeDNSSoComRedeConfigurada(t *testing.T) {
	semRede := SurvivalRules(AdminAccess{PanelPort: 9997})
	if contem(semRede, "dport 53") || contem(semRede, "dport 67") {
		t.Error("emitiu DNS/DHCP sem rede configurada — abriria o resolver para a WAN")
	}

	comRede := SurvivalRules(AdminAccess{PanelPort: 9997, LANNetworks: []string{"192.168.3.0/24"}})
	for _, esperado := range []string{
		"udp dport 67 ip saddr { 192.168.3.0/24 }",
		"udp dport 53 ip saddr { 192.168.3.0/24 }",
		"tcp dport 53 ip saddr { 192.168.3.0/24 }",
	} {
		if !contem(comRede, esperado) {
			t.Errorf("faltou %q", esperado)
		}
	}
}

// TestSurvivalClienteDHCPSoQuandoAWANEDHCP.
//
// Esta é a linha que a revisão adversarial encontrou faltando, e o motivo de
// ela ser fácil de esquecer: a renovação unicast em T1 passa por conntrack, e
// só o REBIND/DISCOVER não passa — ele sai de 0.0.0.0:68 para broadcast e não
// casa a tupla de retorno. O sintoma aparece dias depois de um flap de link,
// como "a internet caiu sozinha", sem relação visível com o firewall.
func TestSurvivalClienteDHCPSoQuandoAWANEDHCP(t *testing.T) {
	if !contem(SurvivalRules(AdminAccess{WANIsDHCP: true}), "udp dport 68") {
		t.Error("WAN por DHCP e nenhuma linha para a porta 68: a WAN pararia de renovar o endereço")
	}
	if contem(SurvivalRules(AdminAccess{WANIsDHCP: false}), "udp dport 68") {
		t.Error("emitiu a porta 68 numa máquina com endereçamento estático")
	}
}

// TestSurvivalRedeInvalidaNaoViraRegra: sanitizeNetworks já filtra, e este
// teste garante que a filtragem continua sendo aplicada AQUI — uma rede
// malformada interpolada num set faria o `nft -f` inteiro ser recusado, e com
// ele a chain toda, não só esta linha.
func TestSurvivalRedeInvalidaNaoViraRegra(t *testing.T) {
	rs := SurvivalRules(AdminAccess{LANNetworks: []string{"nao-e-rede", "", "999.999.999.999/24"}})
	if contem(rs, "nao-e-rede") || contem(rs, "999.999") {
		t.Errorf("rede inválida chegou à regra: %v", linhas(rs))
	}
	if contem(rs, "dport 53") {
		t.Error("sobrou linha de DNS com o set vazio")
	}
}

// TestSurvivalNaoTemLinhaVaziaNemToken vazio: cada elemento vira um argv, e um
// token em branco produz um argumento vazio que o nft recusa.
func TestSurvivalNaoTemLinhaVaziaNemToken(t *testing.T) {
	for i, r := range SurvivalRules(AdminAccess{PanelPort: 9997, LANNetworks: []string{"10.0.0.0/8"}, WANIsDHCP: true}) {
		if len(r) == 0 {
			t.Errorf("linha %d vazia", i)
		}
		for j, tok := range r {
			if strings.TrimSpace(tok) == "" {
				t.Errorf("linha %d, token %d em branco", i, j)
			}
		}
	}
}

// TestSurvivalTodaLinhaTerminaEmAccept: esta lista é só sobre o que SOBREVIVE.
// Uma linha de drop aqui seria política disfarçada de sobrevivência, e passaria
// despercebida por estar num arquivo cujo nome promete outra coisa.
func TestSurvivalTodaLinhaTerminaEmAccept(t *testing.T) {
	for _, r := range SurvivalRules(AdminAccess{PanelPort: 9997, LANNetworks: []string{"10.0.0.0/8"}, WANIsDHCP: true}) {
		if r[len(r)-1] != "accept" {
			t.Errorf("linha não termina em accept: %q", strings.Join(r, " "))
		}
	}
}

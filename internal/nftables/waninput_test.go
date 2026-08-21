package nftables

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A proteção de entrada das WANs (#119, fase 1).
//
// O primeiro teste é o que mais importa, e ele afirma uma NÃO-MUDANÇA: sem WAN
// conhecida, a chain é byte a byte a de antes. Toda instalação nova nasce assim.

// gerencia é o acesso administrativo típico: SSH no padrão e painel na porta do
// .deb. As portas de gerência NUNCA podem ser descartadas sem o admin mandar.
var gerencia = AdminAccess{PanelPort: 9997}

func TestSemWANConhecidaNadaEhEmitido(t *testing.T) {
	if r := WANInputRules(nil, gerencia); r != nil {
		t.Errorf("lista vazia gerou regras: %v", linhas(r))
	}
	if r := WANInputRules([]string{"", ""}, gerencia); r != nil {
		t.Errorf("só nomes vazios geraram regras: %v", linhas(r))
	}

	// E a chain inteira continua a de sempre.
	got := linhas(inputChainRules(nil, nil, false, PolicyAccept, AdminAccess{}, nil))
	querida := []string{"ct state related counter accept"}
	if len(got) != 1 || got[0] != querida[0] {
		t.Errorf("a chain input mudou para quem não tem WAN cadastrada:\n  veio     %v\n  esperada %v", got, querida)
	}
}

func TestODescarteCasaSomenteConexaoNova(t *testing.T) {
	// A REGRESSÃO QUE ESTE TESTE PRENDE. Se o descarte deixar de casar
	// `ct state new`, ele passa a pegar o RETORNO das conexões que a própria
	// caixa abriu — e o apt, o atualizador, a recursão do unbound e o chrony
	// morrem todos de uma vez, sem nada no ruleset dizendo por quê. É
	// exatamente o problema que trava a issue #78, e a razão de esta entrega
	// não precisar resolvê-lo.
	regras := linhas(WANInputRules([]string{"wan0"}, gerencia))
	drop := regras[len(regras)-1]
	if !strings.Contains(drop, "ct state new") {
		t.Fatalf("o descarte não está limitado a conexão nova: %q", drop)
	}
	if strings.Contains(drop, "established") {
		t.Errorf("o descarte encosta em conexão estabelecida: %q", drop)
	}
	if !strings.HasPrefix(drop, `iifname { "wan0" }`) {
		t.Errorf("o descarte não está escopado pela WAN: %q", drop)
	}
}

func TestOAdminNaoPodeSerTrancadoForaPelaLAN(t *testing.T) {
	// Nenhuma regra desta lista pode casar tráfego que não venha de uma WAN.
	// É esta propriedade — e não um teste de 90 segundos — que torna seguro
	// ligar a proteção sem o admin pedir.
	for _, r := range linhas(WANInputRules([]string{"wan0", "wan1"}, gerencia)) {
		if !strings.HasPrefix(r, "iifname {") {
			t.Errorf("regra sem escopo de interface, alcança a LAN: %q", r)
		}
	}
}

func TestLiberacoesQueEvitamQuebraDiasDepois(t *testing.T) {
	regras := strings.Join(linhas(WANInputRules([]string{"wan0"}, gerencia)), "\n")
	obrigatorias := map[string]string{
		"nd-router-advert":   "sem RA a rota padrão IPv6 expira e o IPv6 morre ~30min depois do deploy",
		"nd-neighbor-advert": "sem vizinhança IPv6 nada de IPv6 funciona",
		"udp dport 68":       "sem isto a WAN por DHCP não renova depois de um flap",
		"udp dport 546":      "sem isto o dia de ligar delegação de prefixo vira o dia de descobrir que o firewall bloqueia",
		"packet-too-big":     "sem isto o PMTUD do IPv6 trava páginas grandes no meio",
		"ct status dnat":     "sem isto encaminhamento de porta para a própria máquina morre",
	}
	for token, porque := range obrigatorias {
		if !strings.Contains(regras, token) {
			t.Errorf("falta a liberação %q: %s", token, porque)
		}
	}
}

func TestODescarteVemDepoisDeTudo(t *testing.T) {
	// A ORDEM É A DECISÃO. O descarte tem de ser a ÚLTIMA linha da chain:
	// depois dos jumps dos grupos, para que um grupo de escopo input que libere
	// algo vindo da WAN seja avaliado antes. Emiti-lo acima anularia em
	// silêncio uma decisão explícita do admin.
	g := StoredGroup{ID: "g1", Name: "libera", ChainName: "grp_libera", Enabled: true, Position: 1, Scope: ScopeInput}
	regras := linhas(inputChainRules([]StoredGroup{g}, nil, false, PolicyAccept, AdminAccess{}, []string{"wan0"}))

	ultima := regras[len(regras)-1]
	if !strings.Contains(ultima, "ct state new counter drop") {
		t.Fatalf("a última linha não é o descarte: %q\ntodas:\n%s", ultima, strings.Join(regras, "\n"))
	}
	iJump, iDrop := -1, len(regras)-1
	for i, r := range regras {
		if strings.Contains(r, "grp_libera") {
			iJump = i
		}
	}
	if iJump < 0 {
		t.Fatalf("o jump do grupo sumiu da chain:\n%s", strings.Join(regras, "\n"))
	}
	if iJump > iDrop {
		t.Errorf("o jump do grupo (%d) ficou DEPOIS do descarte (%d): o admin perdeu a decisão dele", iJump, iDrop)
	}
}

func TestNomeDeInterfaceInseguroEhIgnorado(t *testing.T) {
	// O nome sai do banco e é interpolado no argv do nft.
	regras := linhas(WANInputRules([]string{"wan0; drop", "wan1"}, gerencia))
	junto := strings.Join(regras, "\n")
	if strings.Contains(junto, "drop; ") || strings.Contains(junto, "wan0") {
		t.Errorf("nome inseguro chegou ao ruleset:\n%s", junto)
	}
	if !strings.Contains(junto, `"wan1"`) {
		t.Errorf("a interface boa foi perdida junto com a ruim:\n%s", junto)
	}
	// Só nomes ruins não pode virar uma chain sem proteção NEM uma regra torta:
	// vira lista vazia, e o log já registrou o motivo.
	if r := WANInputRules([]string{"wan0; drop"}, gerencia); r != nil {
		t.Errorf("nome inseguro sozinho gerou regra: %v", linhas(r))
	}
}

func TestInterfaceRepetidaNaoViraRegraRepetida(t *testing.T) {
	regras := linhas(WANInputRules([]string{"wan0", "wan0"}, gerencia))
	if n := strings.Count(regras[0], `"wan0"`); n != 1 {
		t.Errorf("a interface aparece %d vezes no set: %q", n, regras[0])
	}
}

func TestErroAoLerAsWANsAbortaSemTocarNaChain(t *testing.T) {
	// UM SELECT QUE FALHOU NÃO É "esta máquina não tem WAN". Obedecer a essa
	// lista vazia apagaria a proteção de uma caixa que a tem, e o painel
	// continuaria dizendo que ela está protegida. Mesmo contrato dos grupos.
	e := &execGravador{}
	s := servicoComExec(e)
	s.SetWANInterfacesSource(func() ([]string, error) { return nil, errors.New("banco fora") })

	if err := s.reconcileInputChain(context.Background(), nil, nil, false); err == nil {
		t.Fatal("a reconciliação seguiu adiante com a leitura das WANs falhando")
	}
	for _, c := range e.comandos {
		if linha := strings.Join(c, " "); strings.Contains(linha, InputChain) {
			t.Errorf("a chain foi tocada mesmo com a leitura falhando: %q", linha)
		}
	}
}

func TestFonteLigadaEmiteAProtecao(t *testing.T) {
	e := &execGravador{}
	s := servicoComExec(e)
	s.SetWANInterfacesSource(func() ([]string, error) { return []string{"wan0"}, nil })
	s.SetAdminAccessSource(func() (AdminAccess, error) { return gerencia, nil })

	if err := s.reconcileInputChain(context.Background(), nil, nil, false); err != nil {
		t.Fatalf("reconcileInputChain: %v", err)
	}
	var achou bool
	for _, c := range e.comandos {
		if strings.Contains(strings.Join(c, " "), "ct state new counter drop") {
			achou = true
		}
	}
	if !achou {
		t.Errorf("a proteção não chegou ao nft; comandos: %v", e.comandos)
	}
}

func TestPortasDeGerenciaNuncaSaoDescartadas(t *testing.T) {
	// O DEFEITO QUE ESTE TESTE PRENDE, E QUE UMA MÁQUINA DE VERDADE ACHOU.
	// A primeira versão desta lista não liberava porta nenhuma. Numa instalação
	// nova, o admin clica em "detectar links" — o caminho normal do produto —,
	// o auto-detect cadastra como WAN a interface que tem a rota padrão, e a
	// reconciliação seguinte descarta a porta 22 e a do painel. SSH e painel
	// mortos, sem nada na tela e sem caminho de volta.
	regras := linhas(WANInputRules([]string{"wan0"}, AdminAccess{PanelPort: 9997}))
	var libera string
	for _, r := range regras {
		if strings.Contains(r, "tcp dport") {
			libera = r
		}
	}
	if libera == "" {
		t.Fatalf("nenhuma liberação de porta de gerência:\n%s", strings.Join(regras, "\n"))
	}
	for _, porta := range []string{"22", "9997"} {
		if !strings.Contains(libera, porta) {
			t.Errorf("a porta %s não está liberada: %q", porta, libera)
		}
	}
	// E ela tem de vir ANTES do descarte, senão não serve para nada.
	if !strings.Contains(regras[len(regras)-1], "drop") {
		t.Errorf("o descarte deixou de ser a última linha: %v", regras)
	}
}

func TestPortaDoPainelNaoEhFixa(t *testing.T) {
	// 8080 é o default do binário, 9997 o do .deb, e quem põe proxy usa outra.
	// Fixá-la trancaria do lado de fora justamente quem não usa o padrão.
	regras := strings.Join(linhas(WANInputRules([]string{"wan0"}, AdminAccess{SSHPort: 2222, PanelPort: 8443})), "\n")
	if !strings.Contains(regras, "{ 2222, 8443 }") {
		t.Errorf("as portas configuradas não foram usadas:\n%s", regras)
	}
	// SSH e painel na MESMA porta não pode gerar um set com a porta repetida.
	uma := strings.Join(linhas(WANInputRules([]string{"wan0"}, AdminAccess{SSHPort: 9997, PanelPort: 9997})), "\n")
	if !strings.Contains(uma, "{ 9997 }") {
		t.Errorf("porta repetida no set: %s", uma)
	}
}

func TestSemSaberAsPortasAProtecaoNaoEhEmitida(t *testing.T) {
	// FAIL-OPEN DELIBERADO, e na direção que este produto já escolheu: um
	// firewall permissivo por meia hora é um problema; uma caixa que descarta a
	// própria porta do painel não tem caminho de volta. Emitir o descarte sem
	// saber o que liberar é exatamente o defeito que a VM achou.
	e := &execGravador{}
	s := servicoComExec(e)
	s.SetWANInterfacesSource(func() ([]string, error) { return []string{"wan0"}, nil })
	s.SetAdminAccessSource(func() (AdminAccess, error) { return AdminAccess{}, errors.New("banco fora") })

	if err := s.reconcileInputChain(context.Background(), nil, nil, false); err != nil {
		t.Fatalf("a reconciliação abortou em vez de seguir sem a proteção: %v", err)
	}
	for _, c := range e.comandos {
		if strings.Contains(strings.Join(c, " "), "counter drop") {
			t.Errorf("o descarte foi emitido sem a liberação de gerência: %v", c)
		}
	}
}

func TestPingNaWANTemTaxaLimitadaENaoEnfeite(t *testing.T) {
	// `limit rate` é um CASAMENTO, não um modificador (lição da #122). Se o
	// limite estiver na regra errada, ou o ping fica sem limite nenhum, ou o
	// excedente é aceito em vez de cair no descarte.
	regras := linhas(WANInputRules([]string{"wan0"}, gerencia))
	var echos []string
	for _, r := range regras {
		if strings.Contains(r, "echo-request") {
			echos = append(echos, r)
		}
	}
	if len(echos) != 2 {
		t.Fatalf("queria echo-request nas duas famílias, veio %d: %v", len(echos), echos)
	}
	for _, r := range echos {
		if !strings.Contains(r, "limit rate") {
			t.Errorf("ping sem limite de taxa: %q", r)
		}
		if !strings.HasSuffix(r, "accept") {
			t.Errorf("a regra de ping não termina em accept: %q", r)
		}
	}
	// E o descarte continua depois, para o excedente cair nele.
	if !strings.Contains(regras[len(regras)-1], "drop") {
		t.Errorf("o descarte deixou de ser a última linha: %v", regras)
	}
}

func TestBloqueioDeHostCasaEnderecoFisico(t *testing.T) {
	// #119, fase 2: o grupo do sistema tem de casar também por endereço físico,
	// que é a identidade sem família. Sem esta linha, "bloqueado" é uma
	// afirmação falsa na tela assim que a LAN ganhar IPv6.
	regras := linhas(systemGroupForwardRules[GroupKindBlockedHosts](false))
	var temEther, temV4 bool
	for _, r := range regras {
		if strings.Contains(r, "ether saddr @"+BlockedMACSet) {
			temEther = true
		}
		if strings.Contains(r, "ip saddr @"+BlockedSet) {
			temV4 = true
		}
	}
	if !temEther {
		t.Errorf("o bloqueio de host não casa endereço físico: %v", regras)
	}
	if !temV4 {
		t.Errorf("o casamento por IPv4 sumiu junto: %v", regras)
	}
	// `ether daddr` NÃO pode aparecer: no hook forward o endereço físico de
	// destino é o do próprio firewall, então casar por ele não bloquearia nada
	// e daria impressão de cobertura.
	for _, r := range regras {
		if strings.Contains(r, "ether daddr") {
			t.Errorf("casamento por ether daddr não bloqueia nada no hook forward: %q", r)
		}
	}
}

func TestEnderecoFisicoTortoNaoChegaAoNft(t *testing.T) {
	// net.ParseMAC aceita formas que o nft não escreve — traço, ponto e
	// endereços InfiniBand de 20 bytes. O valor sai do banco e é interpolado no
	// argv do nft.
	for _, ruim := range []string{
		"aa-bb-cc-dd-ee-ff",
		"aabb.ccdd.eeff",
		"00:00:00:00:fe:80:00:00:00:00:00:00:02:00:5e:10:00:00:00:01",
		"aa:bb:cc:dd:ee",
		"; drop",
		"",
	} {
		if _, err := macParaNft(ruim); err == nil {
			t.Errorf("endereço físico %q foi aceito", ruim)
		}
	}
	if got, err := macParaNft("AA:BB:CC:DD:EE:FF"); err != nil || got != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("maiúsculas: got %q, err %v", got, err)
	}
}

package nftables

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// O COMPORTAMENTO NA MÁQUINA DE UMA PLACA SÓ
//
// Os goldens congelam a FORMA das regras. Este arquivo afirma o que elas
// FAZEM — e a diferença importa, porque o defeito que as zonas corrigem nunca
// foi uma regra malformada: era uma regra perfeitamente válida que, naquela
// topologia, não significava nada. `iifname != { ens3 }` passa em qualquer
// revisão de forma; o que ele não faz é casar pacote.
//
// Então aqui as regras são AVALIADAS contra pacotes. O avaliador entende
// apenas o prefixo de zona (as oito formas que Zone renderiza) e recusa
// qualquer outra — se um gerador passar a emitir um eixo novo, estes testes
// param em vez de aprovar por omissão.
// ─────────────────────────────────────────────────────────────────────────────

// pacote é o mínimo que o eixo das regras olha.
type pacote struct {
	descricao    string
	iif, oif     string
	saddr, daddr string
	sport, dport int
}

// casaPrefixoDeZona avalia o prefixo de uma regra contra um pacote e devolve
// também quantos tokens o prefixo consumiu.
//
// FALHA O TESTE diante de uma forma que não conhece, de propósito: um
// avaliador que devolvesse "não casou" para o que não entende deixaria um eixo
// novo passar como se fosse tratado.
func casaPrefixoDeZona(t *testing.T, regra []string, p pacote) (casou bool, consumidos int) {
	t.Helper()
	if len(regra) < 2 {
		t.Fatalf("regra curta demais para ter prefixo de zona: %v", regra)
	}

	negado := func(i int) (bool, int) {
		if regra[i] == "!=" {
			return true, i + 1
		}
		return false, i
	}

	switch {
	case regra[0] == "iifname" || regra[0] == "oifname":
		neg, i := negado(1)
		valor := p.iif
		if regra[0] == "oifname" {
			valor = p.oif
		}
		dentro := contémInterface(t, regra[i], valor)
		return dentro != neg, i + 1

	case regra[0] == "ip" && (regra[1] == "saddr" || regra[1] == "daddr"):
		neg, i := negado(2)
		valor := p.saddr
		if regra[1] == "daddr" {
			valor = p.daddr
		}
		dentro := contémEndereco(t, regra[i], valor)
		return dentro != neg, i + 1
	}
	t.Fatalf("prefixo de zona desconhecido em %v.\nSe um eixo novo foi acrescentado a Zone, "+
		"ensine-o a este avaliador — senão estes testes aprovam sem avaliar nada.", regra)
	return false, 0
}

// contémInterface lê `{ "wan1", "wan2" }` — o literal que Zone.ifaceSet monta.
func contémInterface(t *testing.T, set, iface string) bool {
	t.Helper()
	for _, nome := range itensDoSet(t, set) {
		if strings.Trim(nome, `"`) == iface {
			return true
		}
	}
	return false
}

// contémEndereco lê `{ 10.0.0.0/24 }` — o literal que Zone.netSet monta.
func contémEndereco(t *testing.T, set, ip string) bool {
	t.Helper()
	addr := net.ParseIP(ip)
	if addr == nil {
		t.Fatalf("endereço de teste inválido: %q", ip)
	}
	for _, cidr := range itensDoSet(t, set) {
		_, rede, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("CIDR inválido no set %q: %v", set, err)
		}
		if rede.Contains(addr) {
			return true
		}
	}
	return false
}

func itensDoSet(t *testing.T, set string) []string {
	t.Helper()
	if !strings.HasPrefix(set, "{") || !strings.HasSuffix(set, "}") {
		t.Fatalf("esperava um set anônimo, veio %q", set)
	}
	corpo := strings.TrimSpace(set[1 : len(set)-1])
	if corpo == "" {
		t.Fatalf("set anônimo VAZIO (%q): o nft recusa esta regra. "+
			"O gerador tinha de ter omitido a regra em vez de emiti-la.", set)
	}
	var out []string
	for _, item := range strings.Split(corpo, ",") {
		out = append(out, strings.TrimSpace(item))
	}
	return out
}

// tuplaGravada lê o que um `update @set { campo . campo . campo }` escreveria
// para este pacote. É como se descobre se a chave saiu na ordem certa — ou
// espelhada, que era o defeito do registro de conversa em hairpin.
func tuplaGravada(t *testing.T, regra []string, p pacote) string {
	t.Helper()
	i := indiceDe(regra, "update")
	if i < 0 || i+2 >= len(regra) || regra[i+2] != "{" {
		t.Fatalf("regra sem `update @set {` reconhecível: %v", regra)
	}
	var campos []string
	atual := ""
	for _, tok := range regra[i+3:] {
		switch tok {
		case "}":
			campos = append(campos, strings.TrimSpace(atual))
			var vals []string
			for _, c := range campos {
				vals = append(vals, valorDoCampo(t, c, p))
			}
			return strings.Join(vals, " . ")
		case ".":
			campos = append(campos, strings.TrimSpace(atual))
			atual = ""
		default:
			atual += " " + tok
		}
	}
	t.Fatalf("update sem fechamento em %v", regra)
	return ""
}

func valorDoCampo(t *testing.T, campo string, p pacote) string {
	t.Helper()
	switch campo {
	case "ip saddr":
		return p.saddr
	case "ip daddr":
		return p.daddr
	case "th dport":
		return fmt.Sprintf("%d", p.dport)
	case "th sport":
		return fmt.Sprintf("%d", p.sport)
	}
	t.Fatalf("campo desconhecido na chave: %q", campo)
	return ""
}

func indiceDe(s []string, alvo string) int {
	for i, v := range s {
		if v == alvo {
			return i
		}
	}
	return -1
}

// ─── Os dois pacotes que contam ──────────────────────────────────────────────

// conversaEmHairpin é uma conversa real numa VM de VNIC única: o host 10.0.0.5
// da rede fala com 203.0.113.10 na porta 443. Os dois pacotes entram e saem
// pela MESMA interface — que é o fato que quebrava tudo.
func conversaEmHairpin() (ida, volta pacote) {
	ida = pacote{
		descricao: "10.0.0.5 → 203.0.113.10:443 (a ida, saindo para a internet)",
		iif:       "ens3", oif: "ens3",
		saddr: "10.0.0.5", daddr: "203.0.113.10",
		sport: 51000, dport: 443,
	}
	volta = pacote{
		descricao: "203.0.113.10:443 → 10.0.0.5 (a volta, chegando da internet)",
		iif:       "ens3", oif: "ens3",
		saddr: "203.0.113.10", daddr: "10.0.0.5",
		sport: 443, dport: 51000,
	}
	return ida, volta
}

func zonaDaVM() Zone { return zonaHairpin([]string{"10.0.0.0/24"}, "ens3") }

// ─── 1. A contabilidade ──────────────────────────────────────────────────────

// TestEmHairpinAContabilidadeCasaPorCIDREContaOHostEmVezDeDarZero é o defeito
// da #112 renascido por causa da topologia, e a prova de que ele morreu.
//
// COM O EIXO DE INTERFACE, NUMA VNIC SÓ, A CONTA DAVA ZERO EM SILÊNCIO. As duas
// regras da chain acct são `iifname != { ens3 }` e `oifname != { ens3 }`; numa
// caixa em que tudo entra e sai por ens3, NENHUMA das duas casa pacote nenhum.
// O set fica vazio, HostCounters devolve um mapa vazio sem erro, e a tela
// mostra zero — indistinguível de "ninguém trafegou", que é exatamente a
// confusão que a issue existe para acabar.
func TestEmHairpinAContabilidadeCasaPorCIDREContaOHostEmVezDeDarZero(t *testing.T) {
	ida, volta := conversaEmHairpin()

	// Primeiro, o defeito, escrito à mão: é a forma que o produto emitia antes
	// desta entrega. Se algum dia ela voltar, que volte com este teste vermelho.
	antigas := [][]string{
		{"iifname", "!=", `{ "ens3" }`, "update", "@acct_up", "{", "ip", "saddr", "}"},
		{"oifname", "!=", `{ "ens3" }`, "update", "@acct_down", "{", "ip", "daddr", "}"},
	}
	for _, r := range antigas {
		for _, p := range []pacote{ida, volta} {
			if casou, _ := casaPrefixoDeZona(t, r, p); casou {
				t.Fatalf("o eixo de interface não podia casar nada em hairpin, e casou %s com %v", p.descricao, r)
			}
		}
	}

	// Agora o produto de hoje.
	regras := acctChainRules(zonaDaVM())
	if len(regras) != 2 {
		t.Fatalf("esperava as duas regras da contabilidade, vieram %d: %v", len(regras), regras)
	}
	up, down := regras[0], regras[1]

	if casou, _ := casaPrefixoDeZona(t, up, ida); !casou {
		t.Errorf("a subida do host local não foi contada: %v não casou %s", up, ida.descricao)
	}
	if casou, _ := casaPrefixoDeZona(t, up, volta); casou {
		t.Errorf("a volta da internet foi contada como SUBIDA do host: %v casou %s", up, volta.descricao)
	}
	if casou, _ := casaPrefixoDeZona(t, down, volta); !casou {
		t.Errorf("a descida para o host local não foi contada: %v não casou %s", down, volta.descricao)
	}
	if casou, _ := casaPrefixoDeZona(t, down, ida); casou {
		t.Errorf("a ida para a internet foi contada como DESCIDA: %v casou %s", down, ida.descricao)
	}

	// E o que entra no set tem de ser o HOST, nunca o endereço da internet:
	// um set de contabilidade com endereço externo dentro é a medição contando
	// a internet em vez da rede.
	if got := tuplaGravada(t, up, ida); got != "10.0.0.5" {
		t.Errorf("a subida gravou %q; tinha de gravar o host local 10.0.0.5", got)
	}
	if got := tuplaGravada(t, down, volta); got != "10.0.0.5" {
		t.Errorf("a descida gravou %q; tinha de gravar o host local 10.0.0.5", got)
	}
}

// ─── 2. O registro de conversa, e o fantasma espelhado ───────────────────────

// TestEmHairpinCadaConversaEntraUmaVezSoSemOFantasmaEspelhado é o defeito mais
// caro dos três, porque ele não some: ele ENCHE.
//
// A segunda regra da chain flows casa `iifname { WAN }` POSITIVAMENTE, e em
// hairpin isso é "todo pacote". Então a IDA — que a primeira regra devia ter
// registrado e não registrou — caía nesta, e era gravada com os campos
// INVERTIDOS: `ip daddr . ip saddr . th sport`, isto é, o endereço da internet
// no campo do host. A volta era gravada certa. Resultado: duas linhas por
// conversa, uma verdadeira e um fantasma espelhado, comendo metade do teto de
// 32768 e mostrando na tela hosts que não existem na rede.
//
// A asserção que fecha isso é a do enunciado: NENHUM elemento pode ter o
// primeiro campo fora das redes locais.
func TestEmHairpinCadaConversaEntraUmaVezSoSemOFantasmaEspelhado(t *testing.T) {
	z := zonaDaVM()
	ida, volta := conversaEmHairpin()
	regras := flowsChainRules(z)
	if len(regras) != 2 {
		t.Fatalf("esperava as duas regras do registro de conversa, vieram %d: %v", len(regras), regras)
	}

	// `update` NÃO é terminal no nft: o pacote segue para a regra seguinte. Por
	// isso os dois pacotes são passados pelas DUAS regras — é assim que o
	// fantasma nascia, e é a única avaliação que o prova ausente.
	gravados := map[string]int{}
	for _, p := range []pacote{ida, volta} {
		for _, r := range regras {
			if casou, _ := casaPrefixoDeZona(t, r, p); casou {
				gravados[tuplaGravada(t, r, p)]++
			}
		}
	}

	esperada := "10.0.0.5 . 203.0.113.10 . 443"
	if len(gravados) != 1 {
		t.Fatalf("a conversa tinha de virar UMA tupla só; viraram %d: %v\n"+
			"Mais de uma é o fantasma espelhado de volta.", len(gravados), gravados)
	}
	if gravados[esperada] != 2 {
		t.Errorf("esperava a tupla %q escrita pela ida e pela volta (2 vezes, somando no mesmo contador); veio %v",
			esperada, gravados)
	}

	// A asserção do enunciado, escrita como asserção e não como consequência.
	for tupla := range gravados {
		primeiro := strings.Split(tupla, " . ")[0]
		if !contémEndereco(t, z.netSet(), primeiro) {
			t.Errorf("elemento com o primeiro campo FORA das redes locais: %q (campo %q). "+
				"É o fantasma espelhado: o endereço da internet gravado no lugar do host.", tupla, primeiro)
		}
	}
}

// ─── 3. A proteção de entrada ────────────────────────────────────────────────

// TestEmHairpinAProtecaoDeEntradaNaoCortaOTrafegoDaPropriaRede é o defeito que
// derruba serviço em vez de só medir errado.
//
// O descarte final da chain input era `iifname { WAN } ct state new drop`.
// Numa VM de VNIC única isso é "descarte toda conexão nova", ponto — inclusive
// DNS, NTP e painel vindos das outras máquinas da mesma rede, que chegam pela
// mesma interface porque não existe outra.
func TestEmHairpinAProtecaoDeEntradaNaoCortaOTrafegoDaPropriaRede(t *testing.T) {
	z := zonaDaVM()
	regras := WANInputRules(z, AdminAccess{SSHPorts: []int{22}, PanelPort: 9997, WANIsDHCP: true}, false, false, 51820)
	if len(regras) == 0 {
		t.Fatal("a proteção de entrada não emitiu regra nenhuma")
	}
	descarte := regras[len(regras)-1]
	if indiceDe(descarte, "drop") < 0 {
		t.Fatalf("a última regra da proteção tinha de ser o descarte, veio %v", descarte)
	}

	// O vizinho da própria rede: outra instância na mesma sub-rede, pedindo DNS.
	vizinho := pacote{
		descricao: "10.0.0.9 → 10.0.0.5:53 (outra máquina da mesma rede pedindo DNS)",
		iif:       "ens3", oif: "ens3",
		saddr: "10.0.0.9", daddr: "10.0.0.5", sport: 40000, dport: 53,
	}
	if casou, _ := casaPrefixoDeZona(t, descarte, vizinho); casou {
		t.Errorf("o descarte cortou o tráfego da própria rede: %v casou %s", descarte, vizinho.descricao)
	}

	// E continua cortando o que vem de fora sem ter sido pedido — senão a
	// correção teria trocado um defeito por uma exposição.
	deFora := pacote{
		descricao: "198.51.100.7 → 10.0.0.5:3306 (varredura vinda da internet)",
		iif:       "ens3", oif: "ens3",
		saddr: "198.51.100.7", daddr: "10.0.0.5", sport: 41000, dport: 3306,
	}
	if casou, _ := casaPrefixoDeZona(t, descarte, deFora); !casou {
		t.Errorf("o descarte deixou passar conexão nova vinda de fora: %v não casou %s", descarte, deFora.descricao)
	}

	// E o defeito antigo, à mão, para o caso de alguém restaurá-lo.
	antigo := []string{"iifname", `{ "ens3" }`, "ct", "state", "new", "counter", "drop"}
	if casou, _ := casaPrefixoDeZona(t, antigo, vizinho); !casou {
		t.Fatal("este teste parou de descrever o defeito: o descarte por interface TINHA de cortar o vizinho")
	}
}

// TestEmHairpinAsLinhasDeIPv6FicamNoEixoDeInterface registra uma LACUNA
// ENTREGUE ABERTA, com nome próprio, para que ela não seja descoberta por
// acidente por quem ligar IPv6 numa VM de nuvem.
//
// `ip saddr` só casa IPv4 na família inet. As quatro linhas exclusivamente
// IPv6 da proteção de entrada (vizinhança, erros de ICMPv6, cliente DHCPv6 e
// echo) continuam no eixo de interface justamente para não pararem de casar —
// são `accept`, então casar demais não afrouxa nada. O descarte final, esse,
// passa a valer só para IPv4: o que chegar de fora por IPv6 NÃO é descartado.
//
// Fechar isso exige o prefixo IPv6 da rede local, que nenhuma fonte deste
// produto conhece hoje. Ver o slog.Warn em WANInputRules.
func TestEmHairpinAsLinhasDeIPv6FicamNoEixoDeInterface(t *testing.T) {
	regras := WANInputRules(zonaDaVM(), AdminAccess{SSHPorts: []int{22}, PanelPort: 9997}, false, false)

	var v6PorInterface, v6PorCIDR int
	for _, r := range regras {
		soV6 := indiceDe(r, "icmpv6") >= 0 || (indiceDe(r, "dport") >= 0 && indiceDe(r, "546") >= 0)
		if !soV6 {
			continue
		}
		switch r[0] {
		case "iifname":
			v6PorInterface++
		case "ip":
			v6PorCIDR++
		}
	}
	if v6PorCIDR != 0 {
		t.Errorf("%d linha(s) exclusivamente IPv6 foram renderizadas por `ip saddr`, que não casa IPv6 "+
			"na família inet: elas deixariam de casar qualquer pacote e o IPv6 perderia a vizinhança", v6PorCIDR)
	}
	if v6PorInterface != 4 {
		t.Errorf("esperava as 4 linhas de IPv6 no eixo de interface, achei %d.\n"+
			"Se o conjunto mudou, atualize este teste E o aviso em WANInputRules — "+
			"esta contagem é o que impede a lacuna de virar surpresa.", v6PorInterface)
	}

	// E o descarte é v4-only. Este teste NÃO aprova isso: ele o REGISTRA.
	descarte := regras[len(regras)-1]
	if descarte[0] != "ip" || descarte[1] != "saddr" {
		t.Fatalf("o descarte mudou de forma: %v", descarte)
	}
}

// ─── 4. As chains nascem ─────────────────────────────────────────────────────

// execDeZona grava o que foi mandado ao nft. Local a este arquivo, como manda a
// convenção deste pacote — um executor falso compartilhado vira dependência
// entre testes que deviam ser independentes.
type execDeZona struct{ comandos []string }

func (e *execDeZona) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	e.comandos = append(e.comandos, cmd+" "+strings.Join(args, " "))
	return "", nil
}

func (e *execDeZona) ExecuteRead(ctx context.Context, cmd string, args ...string) (string, error) {
	return e.Execute(ctx, cmd, args...)
}
func (e *execDeZona) IsDryRun() bool                              { return false }
func (e *execDeZona) WriteFile(string, []byte, os.FileMode) error { return nil }

func (e *execDeZona) tem(trecho string) bool {
	for _, c := range e.comandos {
		if strings.Contains(c, trecho) {
			return true
		}
	}
	return false
}

func (e *execDeZona) regras() []string {
	var out []string
	for _, c := range e.comandos {
		if strings.HasPrefix(c, "nft add rule") {
			out = append(out, c)
		}
	}
	return out
}

// TestAsChainsNascemVaziasEmVezDeNaoNascerQuandoNaoHaWANCadastrada é o item (c)
// do incremento, afirmado sobre o Executor e não sobre o gerador.
//
// POR QUE A DIFERENÇA IMPORTA: nenhum teste de gerador consegue ver uma chain
// que não nasceu, porque `add chain` não é regra de chain nenhuma. Até aqui,
// numa caixa sem link cadastrado, EnsureAccounting, EnsureMSSClamp e
// EnsureConnMark devolviam nil ANTES do `add chain` — e o ruleset simplesmente
// não tinha acct, mss_clamp, conn_mark, conn_mark_out nem output_mark. Quem
// fosse conferir não achava a chain e não sabia dizer se a feature estava
// desligada ou quebrada.
func TestAsChainsNascemVaziasEmVezDeNaoNascerQuandoNaoHaWANCadastrada(t *testing.T) {
	casos := []struct {
		nome   string
		rodar  func(context.Context, *Service) error
		chains []string
		// regrasEsperadas é quantas regras a chain deve ganhar. Zero = nasce
		// vazia; a output_mark é a exceção, e é ganho líquido.
		regrasEsperadas int
	}{
		{
			nome:   "contabilidade por host",
			rodar:  func(ctx context.Context, s *Service) error { return s.EnsureAccounting(ctx, nil) },
			chains: []string{"add chain inet linkguard acct"},
		},
		{
			nome:   "ajuste de MSS",
			rodar:  func(ctx context.Context, s *Service) error { return s.EnsureMSSClamp(ctx, nil) },
			chains: []string{"add chain inet linkguard mss_clamp"},
		},
		{
			nome:  "marcação de conexão",
			rodar: func(ctx context.Context, s *Service) error { return s.EnsureConnMark(ctx, nil) },
			chains: []string{
				"add chain inet linkguard conn_mark ",
				"add chain inet linkguard conn_mark_out",
				"add chain inet linkguard output_mark",
			},
			// A output_mark NÃO depende de WAN nenhuma: a regra dela é
			// restoreMarkRule() puro. Ela passa a existir, e isso é correto.
			regrasEsperadas: 1,
		},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			ex := &execDeZona{}
			s := &Service{exec: ex}
			s.SetConfPath(t.TempDir() + "/nftables.conf")
			if err := c.rodar(context.Background(), s); err != nil {
				t.Fatalf("sem WAN cadastrada isto não pode ser erro: %v", err)
			}
			for _, chain := range c.chains {
				if !ex.tem(chain) {
					t.Errorf("a chain não nasceu: nenhum comando com %q.\ncomandos: %v", chain, ex.comandos)
				}
			}
			if got := ex.regras(); len(got) != c.regrasEsperadas {
				t.Errorf("esperava %d regra(s) numa caixa sem link cadastrado, vieram %d: %v",
					c.regrasEsperadas, len(got), got)
			}
		})
	}
}

// TestEmHairpinAsChainsPorLinkNascemVaziasPorqueNaoHaLinkAEscolher documenta a
// outra metade da decisão, que é fácil de ler como esquecimento.
//
// Numa VM de VNIC única, marcar conexão por WAN e ajustar MSS por WAN não
// decidem nada: existe um caminho só, nenhuma `ip rule fwmark` consome a marca,
// e platform.DeriveCapabilities já desligou MultiWAN, LinkFailover,
// LoadBalancing e PerLinkPolicyRouting na mesma máquina. As chains existem e
// ficam vazias — a forma do ruleset continua a mesma entre plataformas, e o
// gating de verdade fica para o incremento do uplink, onde ele pertence.
func TestEmHairpinAsChainsPorLinkNascemVaziasPorqueNaoHaLinkAEscolher(t *testing.T) {
	z := zonaDaVM()
	if z.PerLink() {
		t.Fatal("uma máquina de VNIC única não pode ter casamento por link")
	}
	if !z.Discriminates() {
		t.Fatal("com CIDR local conhecido a zona TEM de discriminar: é o que liga a medição na nuvem")
	}
	marcas := []WANMark{{Interface: "ens3", Mark: 0x64}}
	if r := mssClampRules(z); len(r) != 0 {
		t.Errorf("mss_clamp tinha de nascer vazia em hairpin, veio %v.\n"+
			"`rt mtu` leria a MTU ANUNCIADA pela interface (9000 na OCI), não a real (1500).", r)
	}
	if r := connMarkChainRules(z, marcas); len(r) != 0 {
		t.Errorf("conn_mark tinha de nascer vazia em hairpin, veio %v", r)
	}
	if r := connMarkOutChainRules(z, marcas); len(r) != 0 {
		t.Errorf("conn_mark_out tinha de nascer vazia em hairpin, veio %v", r)
	}
}

// ─── A garantia que manda no desenho ─────────────────────────────────────────

// TestLigarAZonaNaoMudaUmByteNaTopologiaDeProducao é o teste mais barato e mais
// forte deste incremento.
//
// A caixa do dono está em produção 24/7. O contrato é que, para a topologia de
// duas WANs mais LAN, o produto continue emitindo EXATAMENTE os mesmos
// comandos. Os goldens provam isso contra um arquivo; este teste prova a
// propriedade que os goldens dependem: uma zona ALIMENTADA com redes locais
// renderiza, fora do hairpin, token por token o mesmo que uma zona vazia.
//
// Se um renderizador passar a olhar para os CIDRs fora do hairpin, é aqui que
// aparece — e aparece como uma linha de diff, não como 24 goldens vermelhos.
func TestLigarAZonaNaoMudaUmByteNaTopologiaDeProducao(t *testing.T) {
	wans := []string{"ppp0", "enp2s0"}
	marcas := []WANMark{{Interface: "ppp0", Mark: 0x64}, {Interface: "enp2s0", Mark: 0xc8}}
	acesso := AdminAccess{SSHPorts: []int{22}, PanelPort: 9997, LANNetworks: []string{"192.168.3.0/24"}}

	semRedes := NewZone(wans, nil, false)
	comRedes := NewZone(wans, []string{"192.168.3.0/24", "192.168.9.0/24"}, false)

	geradores := map[string]func(Zone) [][]string{
		"acctChainRules":  acctChainRules,
		"mssClampRules":   mssClampRules,
		"flowsChainRules": flowsChainRules,
		"markHostsChainRules": func(z Zone) [][]string {
			return markHostsChainRules(NewZone(wanMarkIfaces(marcas), z.localNets, z.hairpin))
		},
		"connMarkChainRules":    func(z Zone) [][]string { return connMarkChainRules(z, marcas) },
		"connMarkOutChainRules": func(z Zone) [][]string { return connMarkOutChainRules(z, marcas) },
		"restoreReplyMarkRule":  func(z Zone) [][]string { return [][]string{restoreReplyMarkRule(z)} },
		"restoreOutbound":       func(z Zone) [][]string { return [][]string{restoreOutboundMarkRule(z)} },
		"abuseRules":            func(z Zone) [][]string { return abuseRules(z, "{ 22, 9997 }") },
		"WANInputRules":         func(z Zone) [][]string { return WANInputRules(z, acesso, false, true, 51820) },
	}
	for nome, gerar := range geradores {
		t.Run(nome, func(t *testing.T) {
			sem, com := textoDasRegras(gerar(semRedes)), textoDasRegras(gerar(comRedes))
			if sem != com {
				t.Errorf("alimentar a zona com redes locais mudou a saída numa caixa de VÁRIAS interfaces.\n"+
					"Fora do hairpin nenhum renderizador pode olhar para os CIDRs.\nsem redes:\n%scom redes:\n%s", sem, com)
			}
		})
	}

	// E o bootstrap, que embute mark_hosts como texto.
	if a, b := buildBootstrapRuleset(wans, ZoneFacts{}), buildBootstrapRuleset(wans, ZoneFacts{LocalNets: []string{"192.168.3.0/24"}}); a != b {
		t.Error("o ruleset de instalação nova mudou só por a zona ter redes locais alimentadas")
	}
}

// TestAFonteDaPlataformaAusenteSeComportaComoAMaquinaDeHoje prende o
// zero-value permissivo no lugar onde ele importa: o Service.
func TestAFonteDaPlataformaAusenteSeComportaComoAMaquinaDeHoje(t *testing.T) {
	s := &Service{exec: &execDeZona{}}
	z, err := s.zone([]string{"ppp0", "enp2s0"})
	if err != nil {
		t.Fatalf("sem fonte ligada não pode dar erro: %v", err)
	}
	if z.Hairpin() {
		t.Error("sem fonte ligada a máquina tem de ser tratada como caixa comum, não como hairpin")
	}
	if got := strings.Join(z.FromLocal(), " "); got != `iifname != { "ppp0", "enp2s0" }` {
		t.Errorf("o eixo padrão deixou de ser a interface: %q", got)
	}
}

// TestErroAoLerAPlataformaAbortaEmVezDeVirarCaixaComum é o outro lado do
// contrato, e o mais importante dos dois: uma leitura que FALHOU não é "esta
// máquina não é hairpin". Obedecer a esse silêncio escreveria a chain no eixo
// errado justamente na máquina que depende do outro.
func TestErroAoLerAPlataformaAbortaEmVezDeVirarCaixaComum(t *testing.T) {
	s := &Service{exec: &execDeZona{}}
	s.SetZoneFactsSource(func() (ZoneFacts, error) { return ZoneFacts{}, fmt.Errorf("banco fechado") })

	if _, err := s.zone([]string{"ens3"}); err == nil {
		t.Fatal("erro de leitura da plataforma tinha de propagar")
	}
	if err := s.EnsureAccounting(context.Background(), []string{"ens3"}); err == nil {
		t.Error("EnsureAccounting seguiu em frente sem saber em que máquina está")
	}
	if err := s.EnsureMSSClamp(context.Background(), []string{"ens3"}); err == nil {
		t.Error("EnsureMSSClamp seguiu em frente sem saber em que máquina está")
	}
	if err := s.EnsureConnMark(context.Background(), []WANMark{{Interface: "ens3", Mark: 1}}); err == nil {
		t.Error("EnsureConnMark seguiu em frente sem saber em que máquina está")
	}
}

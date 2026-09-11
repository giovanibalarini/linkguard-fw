package nftables

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// O CONGELAMENTO DA SAÍDA DOS GERADORES DE REGRA
//
// Este arquivo não testa comportamento novo: ele PRENDE o que o produto emite
// hoje, antes de o eixo das regras deixar de ser a interface. A máquina do dono
// está em produção 24/7 com duas WANs e uma LAN, e o contrato do incremento das
// zonas é que, para essa topologia, o produto continue emitindo EXATAMENTE os
// mesmos comandos — byte a byte, argumento a argumento.
//
// POR QUE DUAS CAMADAS, E NÃO UMA
//
// Os geradores devolvem [][]string de tokens, e rebuildChainIn transforma cada
// lista em `args := append([]string{"add","rule",…}, tokens...)`, que vai para o
// Executor como argv SEPARADO. O nft junta os argumentos com espaço antes de
// parsear. Então um golden que gravasse só `strings.Join(tokens, " ")` seria
// CEGO para a mudança de fronteira de token: trocar {"iifname","!=",set} por
// {"iifname !=", set} produz o mesmo comando no kernel, o mesmo texto no
// arquivo, e perde o contrato de argv sem que ninguém veja. É exatamente o tipo
// de mudança que uma refatoração de zona faz sem querer.
//
//   - Camada A (testdata/zonas/geradores): a saída pura de cada gerador, com
//     UM TOKEN POR ARGUMENTO, cada um entre aspas. Pega fusão de token, aspas
//     do nome de interface, espaçamento interno do set anônimo e a ordem das
//     regras dentro da chain.
//   - Camada B (testdata/zonas/comandos): a sequência ORDENADA de tudo o que o
//     método público manda ao Executor. É a única camada capaz de ver uma chain
//     NÃO NASCER — o golden de tokens não tem como notar um `add chain` que
//     deixou de ser emitido, porque `add chain` não é regra de chain nenhuma.
//
// SOBRE A FLAG -update
//
// Ela regrava os arquivos, e a corrida SEMPRE TERMINA VERMELHA quando algum
// arquivo muda. É de propósito: um golden que fica verde depois de se regravar
// sozinho é um botão de "faz passar", e aí ele deixa de proteger a produção
// para virar decoração. Vermelho obriga a olhar o diff do git e a justificar a
// mudança — que é o único uso legítimo desta flag.
// ─────────────────────────────────────────────────────────────────────────────

var atualizarGolden = flag.Bool("update", false,
	"regrava os arquivos golden de testdata/zonas; a corrida termina VERMELHA de propósito quando algum muda")

const dirGolden = "testdata/zonas"

// ─── Os cenários ─────────────────────────────────────────────────────────────

// cenario é uma topologia inteira, num lugar só, para que os dois goldens
// (tokens e comandos) leiam sempre a MESMA entrada.
type cenario struct {
	nome string
	// descricao vai para o cabeçalho de todo arquivo golden: o diff é a
	// interface, e quem o lê daqui a seis meses precisa saber que topologia é.
	descricao string
	// wans é a lista COMO O BANCO A ENTREGA — fora de ordem alfabética de
	// propósito. sanitizeInterfaces preserva a ordem de entrada e
	// sanitizeWANMarks/markHostsChainRules ORDENAM: a assimetria é real, está
	// congelada aqui, e um NewZone que resolvesse "ordenar por conveniência"
	// reordenaria a chain mss_clamp da produção sem que nada mais acusasse.
	wans     []string
	wanMarks []WANMark
	lanNets  []string
	// hairpin diz que entra e sai pela MESMA interface. É o que faz a Zone
	// renderizar por CIDR em vez de por interface. Falso nos três cenários
	// originais, que são caixas on-prem — e é justamente por isso que os
	// goldens deles não podem mudar quando a zona passa a existir.
	hairpin   bool
	acesso    AdminAccess
	grupos    []StoredGroup
	ntpRedes  []string
	ntpServir bool
}

// cenarios são as três topologias congeladas. A primeira é a máquina do dono; é
// a que não pode regredir. A terceira é a caixa recém-instalada, que ainda não
// tem link cadastrado — e é a que o incremento das zonas vai mudar de propósito.
func cenarios() []cenario {
	acessoProducao := AdminAccess{
		SSHPorts:    []int{22},
		PanelPort:   9997, // o default do .deb, não o do binário
		LANNetworks: []string{"192.168.3.0/24"},
		WANIsDHCP:   true,
	}
	gruposProducao := []StoredGroup{{
		ID:        "6f1c2d3e4a5b",
		Name:      "Acesso ao painel",
		ChainName: "grp_6f1c2d3e4a5b",
		Position:  10,
		Enabled:   true,
		Scope:     ScopeInput,
		CondSaddr: "192.168.3.0/24",
	}}
	return []cenario{
		{
			nome: "onprem_2wan",
			descricao: "a máquina de produção do dono: duas WANs (uma PPPoE, uma ethernet) " +
				"mais uma LAN em 192.168.3.0/24. É esta saída que não pode mudar.",
			wans: []string{"ppp0", "enp2s0"},
			wanMarks: []WANMark{
				{Interface: "ppp0", Mark: 0x64},
				{Interface: "enp2s0", Mark: 0xc8},
			},
			lanNets:   []string{"192.168.3.0/24"},
			acesso:    acessoProducao,
			grupos:    gruposProducao,
			ntpRedes:  []string{"192.168.3.0/24"},
			ntpServir: true,
		},
		{
			nome:      "onprem_1wan",
			descricao: "uma WAN só mais a LAN: o link redundante caiu do cadastro, ou nunca houve.",
			wans:      []string{"enp2s0"},
			wanMarks:  []WANMark{{Interface: "enp2s0", Mark: 0xc8}},
			lanNets:   []string{"192.168.3.0/24"},
			acesso:    acessoProducao,
			grupos:    gruposProducao,
			ntpRedes:  []string{"192.168.3.0/24"},
			ntpServir: true,
		},
		{
			nome: "hairpin_1nic",
			descricao: "uma VM de nuvem com UMA placa de rede: entra e sai pela mesma " +
				"interface, e o eixo das regras passa a ser o CIDR de dentro. É o " +
				"comportamento NOVO, e o contraste com onprem_1wan é o ponto.",
			wans:     []string{"ens3"},
			wanMarks: []WANMark{{Interface: "ens3", Mark: 0x64}},
			lanNets:  []string{"10.0.0.0/24"},
			hairpin:  true,
			acesso: AdminAccess{
				SSHPorts:    []int{22},
				PanelPort:   9997,
				LANNetworks: []string{"10.0.0.0/24"},
				WANIsDHCP:   true,
			},
			grupos: []StoredGroup{{
				ID:        "6f1c2d3e4a5b",
				Name:      "Acesso ao painel",
				ChainName: "grp_6f1c2d3e4a5b",
				Position:  10,
				Enabled:   true,
				Scope:     ScopeInput,
				CondSaddr: "10.0.0.0/24",
			}},
			ntpRedes:  []string{"10.0.0.0/24"},
			ntpServir: true,
		},
		{
			nome: "sem_wan",
			descricao: "caixa recém-instalada: a LAN já está configurada, nenhum link WAN foi " +
				"cadastrado ainda. Hoje vários Ensure* desistem ANTES de criar a chain, e é " +
				"esse fato — a chain não nascer — que este cenário prende.",
			wans:      nil,
			wanMarks:  nil,
			lanNets:   []string{"192.168.3.0/24"},
			acesso:    acessoProducao,
			grupos:    gruposProducao,
			ntpRedes:  []string{"192.168.3.0/24"},
			ntpServir: true,
		},
	}
}

// zona monta a Zone deste cenário para uma lista de interfaces.
//
// AS REDES LOCAIS VÃO PREENCHIDAS MESMO NOS CENÁRIOS ON-PREM, e isso é de
// propósito: é a prova mais barata e mais forte desta entrega. Fora do hairpin
// nenhum renderizador olha para os CIDRs, então os goldens de produção têm de
// continuar byte a byte os mesmos com a zona LIGADA e alimentada. Se ligar a
// zona mudasse um byte na topologia do dono, seria aqui que apareceria.
func (c cenario) zona(ifaces []string) Zone {
	return NewZone(ifaces, c.lanNets, c.hairpin)
}

// zonaDasMarcas é a zona das chains que derivam das WANMark. A lista de
// interfaces sai ORDENADA, que é a forma que conn_mark e mark_hosts têm em
// produção — e não a ordem do cadastro, que é a da acct e da mss_clamp. Os
// goldens congelam as DUAS ordens lado a lado de propósito.
func (c cenario) zonaDasMarcas() Zone {
	return c.zona(wanMarkIfaces(sanitizeWANMarks(c.wanMarks)))
}

// fatos é o que o Service leria da plataforma neste cenário.
func (c cenario) fatos() ZoneFacts {
	return ZoneFacts{Hairpin: c.hairpin, LocalNets: c.lanNets}
}

// ligarZona pluga os fatos da plataforma no Service, como main.go faz.
func ligarZona(s *Service, c cenario) {
	s.SetZoneFactsSource(func() (ZoneFacts, error) { return c.fatos(), nil })
}

// flowsDoCenario é a configuração de registro de conversa usada em todos os
// cenários. Literal, nunca lida do banco: um valor que mudasse por fora mudaria
// a spec do set e o golden junto, sem nada a ver com zona.
var flowsDoCenario = FlowsConfig{Ligado: true, JanelaMinutos: 15, Teto: 32768}

// portaWireGuard é fixa pelo mesmo motivo.
const portaWireGuard = 51820

// ─── Camada A: os tokens de cada gerador ─────────────────────────────────────

func TestOsGeradoresEmitemOsMesmosTokensDeSempreNaTopologiaDeProducaoDeDuasWANs(t *testing.T) {
	conferirGeradores(t, cenarioChamado(t, "onprem_2wan"))
}

func TestOsGeradoresEmitemOsMesmosTokensDeSempreComUmaWANSo(t *testing.T) {
	conferirGeradores(t, cenarioChamado(t, "onprem_1wan"))
}

func TestOsGeradoresNaoEmitemRegraNenhumaQuandoNaoHaWANCadastrada(t *testing.T) {
	conferirGeradores(t, cenarioChamado(t, "sem_wan"))
}

// TestOsGeradoresCasamPorCIDRNaMaquinaDeUmaPlacaSo congela o comportamento
// NOVO. O contraste a ler é com onprem_1wan: mesma quantidade de links, mesma
// forma de chain, eixo diferente — `ip saddr { 10.0.0.0/24 }` no lugar de
// `iifname != { "enp2s0" }`.
//
// E as chains que ficam VAZIAS aqui são parte do congelamento, não uma falta:
// mss_clamp, conn_mark e conn_mark_out não têm o que decidir com um link só.
func TestOsGeradoresCasamPorCIDRNaMaquinaDeUmaPlacaSo(t *testing.T) {
	conferirGeradores(t, cenarioChamado(t, "hairpin_1nic"))
}

// conferirGeradores congela a saída de TODO gerador que hoje deriva do eixo
// WAN/LAN, um arquivo por gerador.
func conferirGeradores(t *testing.T, c cenario) {
	t.Helper()

	type caso struct {
		arquivo string
		entrada string
		regras  [][]string
	}

	// Uma regra só, embrulhada, para os dois geradores que devolvem []string.
	uma := func(r []string) [][]string {
		if r == nil {
			return nil
		}
		return [][]string{r}
	}

	casos := []caso{
		{
			arquivo: "acctChainRules",
			entrada: fmt.Sprintf("wanIfaces = %q", sanitizeInterfaces(c.wans)),
			regras:  acctChainRules(c.zona(sanitizeInterfaces(c.wans))),
		},
		{
			arquivo: "mssClampRules",
			entrada: fmt.Sprintf("wanIfaces = %q", sanitizeInterfaces(c.wans)),
			regras:  mssClampRules(c.zona(sanitizeInterfaces(c.wans))),
		},
		{
			arquivo: "flowsChainRules",
			entrada: fmt.Sprintf("wanIfaces = %q", sanitizeInterfaces(c.wans)),
			regras:  flowsChainRules(c.zona(sanitizeInterfaces(c.wans))),
		},
		{
			arquivo: "connMarkChainRules",
			entrada: fmt.Sprintf("wans = %s", descreverMarcas(sanitizeWANMarks(c.wanMarks))),
			regras:  connMarkChainRules(c.zonaDasMarcas(), sanitizeWANMarks(c.wanMarks)),
		},
		{
			arquivo: "connMarkOutChainRules",
			entrada: fmt.Sprintf("wans = %s", descreverMarcas(sanitizeWANMarks(c.wanMarks))),
			regras:  connMarkOutChainRules(c.zonaDasMarcas(), sanitizeWANMarks(c.wanMarks)),
		},
		{
			arquivo: "restoreReplyMarkRule",
			entrada: fmt.Sprintf("wans = %s", descreverMarcas(sanitizeWANMarks(c.wanMarks))),
			regras:  uma(restoreReplyMarkRule(c.zonaDasMarcas())),
		},
		{
			arquivo: "restoreOutboundMarkRule",
			entrada: fmt.Sprintf("wans = %s", descreverMarcas(sanitizeWANMarks(c.wanMarks))),
			regras:  uma(restoreOutboundMarkRule(c.zonaDasMarcas())),
		},
		{
			arquivo: "markHostsChainRules",
			entrada: fmt.Sprintf("wans = %s", descreverMarcas(c.wanMarks)),
			regras:  markHostsChainRules(c.zona(wanMarkIfaces(c.wanMarks))),
		},
		{
			arquivo: "abuseRules",
			entrada: fmt.Sprintf("wanIfaces = %q, portas = %q", c.wans, portasDeGerencia(c.acesso)),
			regras:  abuseRules(c.zona(c.wans), portasDeGerencia(c.acesso)),
		},
		{
			// A configuração REAL da produção: gerência aberta na WAN,
			// contenção desligada (é opt-in, e ligada por padrão já trancou a
			// VM de validação uma vez), WireGuard escutando.
			arquivo: "WANInputRules",
			entrada: fmt.Sprintf("wanIfaces = %q, access = %s, gerenciaFechada = false, contencaoLigada = false, wireGuardPorts = [%d]",
				c.wans, descreverAcesso(c.acesso), portaWireGuard),
			regras: WANInputRules(c.zona(c.wans), c.acesso, false, false, portaWireGuard),
		},
		{
			// A ordem é a decisão (#127): as duas linhas de contenção têm de
			// vir ANTES do accept das portas de gerência, senão o accept
			// curto-circuita e a contenção não vale nada.
			arquivo: "WANInputRules_contencao_ligada",
			entrada: fmt.Sprintf("wanIfaces = %q, access = %s, gerenciaFechada = false, contencaoLigada = true, wireGuardPorts = [%d]",
				c.wans, descreverAcesso(c.acesso), portaWireGuard),
			regras: WANInputRules(c.zona(c.wans), c.acesso, false, true, portaWireGuard),
		},
		{
			// Com a gerência fechada não pode sobrar NENHUMA linha de `tcp
			// dport` na chain — nem a da contenção, que sem o accept a proteger
			// seria um set que nada alimenta.
			arquivo: "WANInputRules_gerencia_fechada",
			entrada: fmt.Sprintf("wanIfaces = %q, access = %s, gerenciaFechada = true, contencaoLigada = true, wireGuardPorts = [%d]",
				c.wans, descreverAcesso(c.acesso), portaWireGuard),
			regras: WANInputRules(c.zona(c.wans), c.acesso, true, true, portaWireGuard),
		},
		{
			// A chain input inteira, montada como a reconciliação a monta: é
			// aqui que se vê a proteção da WAN vindo DEPOIS dos jumps dos
			// grupos, que é a posição que a #119 decidiu.
			arquivo: "inputChainRules",
			entrada: fmt.Sprintf("groups = %d grupo(s) de escopo input, ntpNetworks = %q, ntpServing = %t, policy = %q, access = %s, wanIfaces = %q, gerenciaFechada = false, contencao = false, wireGuardPorts = [%d]",
				len(c.grupos), c.ntpRedes, c.ntpServir, PolicyAccept, descreverAcesso(c.acesso), c.wans, portaWireGuard),
			// O acesso administrativo vai preenchido MESMO com política
			// permissiva, e isso não é descuido: reconcileInputChain lê o acesso
			// DUAS vezes — uma para as regras de sobrevivência (só com `drop`) e
			// outra, logo abaixo, sempre que há WAN cadastrada, porque as portas
			// de gerência precisam ser conhecidas antes de o descarte da WAN ser
			// emitido. Passar AdminAccess{} aqui faria este golden divergir do
			// golden de comandos de ReconcileInputProtection, que percorre o
			// caminho de verdade.
			regras: inputChainRules(c.grupos, c.ntpRedes, c.ntpServir, PolicyAccept, c.acesso, c.zona(c.wans), false, false, portaWireGuard),
		},
		{
			arquivo: "inputChainRules_politica_drop",
			entrada: fmt.Sprintf("groups = %d grupo(s) de escopo input, ntpNetworks = %q, ntpServing = %t, policy = %q, access = %s, wanIfaces = %q, gerenciaFechada = false, contencao = false, wireGuardPorts = [%d]",
				len(c.grupos), c.ntpRedes, c.ntpServir, PolicyDrop, descreverAcesso(c.acesso), c.wans, portaWireGuard),
			regras: inputChainRules(c.grupos, c.ntpRedes, c.ntpServir, PolicyDrop, c.acesso, c.zona(c.wans), false, false, portaWireGuard),
		},
	}

	for _, caso := range casos {
		t.Run(caso.arquivo, func(t *testing.T) {
			corpo := renderizarRegras(caso.arquivo, c, caso.entrada, caso.regras)
			conferirArquivo(t, filepath.Join(dirGolden, "geradores", c.nome, caso.arquivo+".txt"), corpo)
		})
	}

	// buildBootstrapRuleset não devolve tokens: devolve o texto que vai inteiro
	// para o `nft -f`. Entra na camada A assim mesmo porque ele EMBUTE
	// markHostsChainRules como texto, e é ele que decide com que forma uma
	// instalação nova nasce. Se o bootstrap e a primeira reconciliação
	// discordarem, a caixa diverge no primeiro boot.
	t.Run("buildBootstrapRuleset", func(t *testing.T) {
		var b strings.Builder
		b.WriteString(cabecalho("buildBootstrapRuleset", c,
			fmt.Sprintf("wanInterfaces = %q", c.wans),
			"O texto literal entregue ao `nft -f` numa instalação nova. Não são tokens:",
			"é o arquivo inteiro, e a indentação faz parte dele."))
		b.WriteString("\n")
		for _, linha := range strings.Split(strings.TrimRight(buildBootstrapRuleset(c.wans, c.fatos()), "\n"), "\n") {
			b.WriteString("| " + linha + "\n")
		}
		conferirArquivo(t, filepath.Join(dirGolden, "geradores", c.nome, "buildBootstrapRuleset.txt"), b.String())
	})
}

// ─── Camada B: os comandos de cada método público ────────────────────────────

func TestOsMetodosPublicosEmitemOsMesmosComandosDeSempreNaTopologiaDeProducaoDeDuasWANs(t *testing.T) {
	conferirComandos(t, cenarioChamado(t, "onprem_2wan"))
}

func TestOsMetodosPublicosEmitemOsMesmosComandosDeSempreComUmaWANSo(t *testing.T) {
	conferirComandos(t, cenarioChamado(t, "onprem_1wan"))
}

// TestAsChainsNascemVaziasQuandoNaoHaWANCadastrada é a virada deste incremento,
// e o golden deste cenário é o ÚNICO diff intencional dele.
//
// O QUE ERA. EnsureAccounting, EnsureMSSClamp e EnsureConnMark desistiam ANTES
// do `add chain`, então numa caixa sem link cadastrado as chains acct,
// mss_clamp, conn_mark, conn_mark_out e output_mark não existiam — nem vazias.
// O golden gravava "(nenhum comando)". Numa VM de nuvem recém-criada era esse o
// estado: quem fosse conferir o ruleset não achava a chain e não tinha como
// distinguir "desligado" de "quebrado".
//
// O QUE É. As chains nascem, e nascem VAZIAS quando não há como discriminar.
// Estrutura montada, zero regra, aviso no log dizendo por quê. A output_mark é
// ganho líquido: a regra dela nunca dependeu de WAN nenhuma e agora existe.
//
// O QUE NÃO MUDOU, e os goldens deste mesmo cenário provam: EnsureFlows
// continua devolvendo ErrSemWAN com ZERO comando (chain vazia ali MENTIRIA —
// ver EnsureFlows), e ReconcileMasquerade continua se recusando a agir com
// fonte vazia, intocado.
func TestAsChainsNascemVaziasQuandoNaoHaWANCadastrada(t *testing.T) {
	conferirComandos(t, cenarioChamado(t, "sem_wan"))
}

func TestOsMetodosPublicosEmitemOEixoDeCIDRNaMaquinaDeUmaPlacaSo(t *testing.T) {
	conferirComandos(t, cenarioChamado(t, "hairpin_1nic"))
}

func conferirComandos(t *testing.T, c cenario) {
	t.Helper()

	type caso struct {
		arquivo string
		entrada string
		// rodar dirige o método público contra o gravador.
		rodar func(context.Context, *Service) string
	}

	casos := []caso{
		{
			arquivo: "EnsureAccounting",
			entrada: fmt.Sprintf("wanInterfaces = %q", c.wans),
			rodar: func(ctx context.Context, s *Service) string {
				return retornoDe(s.EnsureAccounting(ctx, c.wans))
			},
		},
		{
			arquivo: "EnsureMSSClamp",
			entrada: fmt.Sprintf("wanInterfaces = %q", c.wans),
			rodar: func(ctx context.Context, s *Service) string {
				return retornoDe(s.EnsureMSSClamp(ctx, c.wans))
			},
		},
		{
			arquivo: "EnsureConnMark",
			entrada: fmt.Sprintf("wans = %s", descreverMarcas(c.wanMarks)),
			rodar: func(ctx context.Context, s *Service) string {
				return retornoDe(s.EnsureConnMark(ctx, c.wanMarks))
			},
		},
		{
			// ErrSemWAN é CONTRATO DE API: internal/hostflows o distingue de
			// erro genérico e o handler o traduz em recado de tela. O cenário
			// sem_wan tem de continuar devolvendo a sentinela e ZERO comando.
			arquivo: "EnsureFlows",
			entrada: fmt.Sprintf("wanInterfaces = %q, cfg = {janela %d min, teto %d}",
				c.wans, flowsDoCenario.JanelaMinutos, flowsDoCenario.Teto),
			rodar: func(ctx context.Context, s *Service) string {
				return retornoDe(s.EnsureFlows(ctx, c.wans, flowsDoCenario))
			},
		},
		{
			arquivo: "ReconcileStructuralChains",
			entrada: fmt.Sprintf("wans = %s", descreverMarcas(c.wanMarks)),
			rodar: func(ctx context.Context, s *Service) string {
				return retornoDe(s.ReconcileStructuralChains(ctx, c.wanMarks...))
			},
		},
		{
			// FORA DO ESCOPO DO INCREMENTO, e congelado justamente por isso: a
			// recusa de agir com fonte vazia é deliberada, e o golden do
			// cenário sem_wan existe para provar que ela continuou intocada.
			arquivo: "ReconcileMasquerade",
			entrada: fmt.Sprintf("wanInterfaces = %q", c.wans),
			rodar: func(ctx context.Context, s *Service) string {
				return retornoDe(s.ReconcileMasquerade(ctx, c.wans))
			},
		},
		{
			arquivo: "ReconcileInputProtection",
			entrada: fmt.Sprintf("fontes ligadas: grupos = %d, ntp = %q/servindo=%t, política = %q, wans = %q, gerência fechada = false, contenção = false, wireguard = %d",
				len(c.grupos), c.ntpRedes, c.ntpServir, PolicyAccept, c.wans, portaWireGuard),
			rodar: func(ctx context.Context, s *Service) string {
				ligarFontesDeInput(s, c, PolicyAccept)
				return retornoDe(s.ReconcileInputProtection(ctx))
			},
		},
		{
			arquivo: "ReconcileInputProtection_politica_drop",
			entrada: fmt.Sprintf("fontes ligadas: grupos = %d, ntp = %q/servindo=%t, política = %q, wans = %q, gerência fechada = false, contenção = false, wireguard = %d",
				len(c.grupos), c.ntpRedes, c.ntpServir, PolicyDrop, c.wans, portaWireGuard),
			rodar: func(ctx context.Context, s *Service) string {
				ligarFontesDeInput(s, c, PolicyDrop)
				return retornoDe(s.ReconcileInputProtection(ctx))
			},
		},
		{
			// A instalação do zero. O gravador embute o corpo do arquivo
			// temporário no golden: sem isso o ruleset inteiro do bootstrap
			// escaparia para dentro de um nome de arquivo aleatório.
			arquivo: "EnsureTable",
			entrada: fmt.Sprintf("wanInterfaces = %q (a tabela ainda NÃO existe na máquina)", c.wans),
			rodar: func(ctx context.Context, s *Service) string {
				return fmt.Sprintf("criou a tabela = %t", s.EnsureTable(ctx, c.wans))
			},
		},
	}

	for _, caso := range casos {
		t.Run(caso.arquivo, func(t *testing.T) {
			ex := &gravadorDeGolden{}
			if caso.arquivo == "EnsureTable" {
				// A primeira leitura de `list table` falha porque a tabela não
				// existe — é a condição que faz o EnsureTable agir. As demais
				// (a do Persist, depois do `nft -f`) devolvem vazio: nesse
				// ponto a tabela já foi criada.
				ex.respostas = []respostaRoteirizada{{
					contem: "list table",
					err:    errors.New("Error: No such file or directory"),
					vezes:  1,
				}}
			}
			s := &Service{exec: ex}
			s.SetConfPath(filepath.Join(t.TempDir(), "nftables.conf"))
			// A fonte da plataforma vai LIGADA nos três cenários on-prem, e é
			// aí que está a prova: com hairpin falso ela tem de produzir
			// exatamente os comandos de sempre. Um Service com a fonte ligada
			// e um sem ela não podem divergir numa caixa de várias interfaces.
			ligarZona(s, c)

			ret := caso.rodar(context.Background(), s)

			corpo := renderizarComandos(caso.arquivo, c, caso.entrada, ret, ex.linhas)
			conferirArquivo(t, filepath.Join(dirGolden, "comandos", c.nome, caso.arquivo+".txt"), corpo)
		})
	}
}

// ligarFontesDeInput pluga no Service as fontes que a chain input consulta.
// Todas devolvem literal: nada aqui pode depender do banco, do relógio ou da
// máquina que roda a suíte.
func ligarFontesDeInput(s *Service, c cenario, politica Policy) {
	s.SetInputChainSources(
		func() ([]StoredGroup, error) { return c.grupos, nil },
		func() ([]string, bool, error) { return c.ntpRedes, c.ntpServir, nil },
	)
	s.SetInputPolicySource(func() (Policy, error) { return politica, nil })
	s.SetAdminAccessSource(func() (AdminAccess, error) { return c.acesso, nil })
	s.SetWANInterfacesSource(func() ([]string, error) { return c.wans, nil })
	s.SetWANMgmtClosedSource(func() (bool, error) { return false, nil })
	s.SetEdgeContainmentSource(func() (bool, error) { return false, nil })
	s.SetWireGuardInputSource(func() (bool, int, error) { return true, portaWireGuard, nil })
}

// ─── Determinismo ────────────────────────────────────────────────────────────

// TestAMesmaEntradaProduzAMesmaSaidaEmCinquentaExecucoesSeguidas é o teste que
// dá sentido aos dois goldens acima.
//
// Um golden só vale se a saída for função da entrada. Iteração de mapa em Go é
// ALEATÓRIA por construção: um gerador que montasse a lista de interfaces
// varrendo um map passaria no golden na primeira corrida e falharia na décima,
// e o sintoma seria "teste instável", não "regra de firewall instável" — quando
// o defeito de verdade é uma chain que muda de forma a cada boot.
//
// Cinquenta repetições não provam ausência de aleatoriedade, mas o runtime de
// Go embaralha a ordem de mapa a cada percurso: um map de dois elementos
// atravessa cinquenta corridas na mesma ordem com probabilidade desprezível.
func TestAMesmaEntradaProduzAMesmaSaidaEmCinquentaExecucoesSeguidas(t *testing.T) {
	for _, c := range cenarios() {
		t.Run(c.nome, func(t *testing.T) {
			geradores := map[string]func() [][]string{
				"acctChainRules":        func() [][]string { return acctChainRules(c.zona(sanitizeInterfaces(c.wans))) },
				"mssClampRules":         func() [][]string { return mssClampRules(c.zona(sanitizeInterfaces(c.wans))) },
				"flowsChainRules":       func() [][]string { return flowsChainRules(c.zona(sanitizeInterfaces(c.wans))) },
				"connMarkChainRules":    func() [][]string { return connMarkChainRules(c.zonaDasMarcas(), sanitizeWANMarks(c.wanMarks)) },
				"connMarkOutChainRules": func() [][]string { return connMarkOutChainRules(c.zonaDasMarcas(), sanitizeWANMarks(c.wanMarks)) },
				"markHostsChainRules":   func() [][]string { return markHostsChainRules(c.zona(wanMarkIfaces(c.wanMarks))) },
				"abuseRules":            func() [][]string { return abuseRules(c.zona(c.wans), portasDeGerencia(c.acesso)) },
				"WANInputRules":         func() [][]string { return WANInputRules(c.zona(c.wans), c.acesso, false, true, portaWireGuard) },
				"inputChainRules": func() [][]string {
					return inputChainRules(c.grupos, c.ntpRedes, c.ntpServir, PolicyDrop, c.acesso, c.zona(c.wans), false, true, portaWireGuard)
				},
			}
			for nome, gerar := range geradores {
				primeira := textoDasRegras(gerar())
				for i := 2; i <= 50; i++ {
					if agora := textoDasRegras(gerar()); agora != primeira {
						t.Fatalf("%s não é determinístico: a corrida %d divergiu da primeira.\nprimeira:\n%s\ncorrida %d:\n%s",
							nome, i, primeira, i, agora)
					}
				}
			}

			// O mesmo para o texto do bootstrap, que embute markHostsChainRules.
			primeiro := buildBootstrapRuleset(c.wans, c.fatos())
			for i := 2; i <= 50; i++ {
				if buildBootstrapRuleset(c.wans, c.fatos()) != primeiro {
					t.Fatalf("buildBootstrapRuleset não é determinístico: a corrida %d divergiu da primeira", i)
				}
			}
		})
	}
}

// ─── O executor gravador ─────────────────────────────────────────────────────

// respostaRoteirizada é uma resposta combinada para um comando. É um ELEMENTO
// DE SLICE, e não entrada de mapa, de propósito: o execFalso de
// accounting_test.go varre um map[string]error dentro do Execute, e com duas
// chaves casando o mesmo comando a resposta escolhida muda a cada corrida. Num
// teste de asserção isso quase nunca aparece; num golden apareceria como
// instabilidade sem causa visível.
type respostaRoteirizada struct {
	contem string
	saida  string
	err    error
	// vezes limita quantas vezes esta resposta vale. Zero = sempre.
	vezes int
	usos  int
}

// gravadorDeGolden grava a sequência exata de chamadas ao Executor.
//
// Não reusa o execFalso deste pacote por duas razões concretas: o map de
// respostas dele é o não-determinismo acima, e ele grava `cmd + " " + join(args)`
// — que é justamente a forma cega à fronteira de token que este arquivo existe
// para não ter.
type gravadorDeGolden struct {
	linhas    []comandoGravado
	respostas []respostaRoteirizada
	dryRun    bool
}

type comandoGravado struct {
	tipo string // "exec", "read" ou "write-file"
	cmd  string
	args []string
	// conteudo é o corpo de um arquivo temporário que apareceu no argv (o
	// `nft -f` do bootstrap e do caminho atômico). Sem inlinear isto, o golden
	// gravaria um nome de arquivo aleatório e perderia o ruleset inteiro.
	conteudo string
}

// reArquivoTemporario casa os arquivos que este pacote entrega ao nft por
// caminho. Casa pelo NOME BASE, e não pelo prefixo /tmp: o TMPDIR da máquina
// que roda a suíte não é garantido.
var reArquivoTemporario = regexp.MustCompile(`^linkguard-[A-Za-z0-9_-]+\.conf$`)

func (e *gravadorDeGolden) registrar(tipo, cmd string, args []string) {
	entrada := comandoGravado{tipo: tipo, cmd: cmd, args: append([]string(nil), args...)}
	for i, a := range entrada.args {
		if !reArquivoTemporario.MatchString(filepath.Base(a)) {
			continue
		}
		// O arquivo ainda existe neste instante: quem o criou só o remove no
		// defer, depois que o Executor devolve.
		if b, err := os.ReadFile(a); err == nil {
			entrada.conteudo = string(b)
		} else {
			entrada.conteudo = fmt.Sprintf("<não foi possível ler o arquivo temporário: %v>", err)
		}
		entrada.args[i] = "<tmp>"
	}
	e.linhas = append(e.linhas, entrada)
}

func (e *gravadorDeGolden) responder(cmd string, args []string) (string, error) {
	full := cmd + " " + strings.Join(args, " ")
	for i := range e.respostas {
		r := &e.respostas[i]
		if !strings.Contains(full, r.contem) {
			continue
		}
		if r.vezes > 0 && r.usos >= r.vezes {
			continue
		}
		r.usos++
		return r.saida, r.err
	}
	return "", nil
}

func (e *gravadorDeGolden) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	e.registrar("exec", cmd, args)
	return e.responder(cmd, args)
}

func (e *gravadorDeGolden) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	e.registrar("read", cmd, args)
	return e.responder(cmd, args)
}

func (e *gravadorDeGolden) IsDryRun() bool { return e.dryRun }

func (e *gravadorDeGolden) WriteFile(path string, data []byte, _ os.FileMode) error {
	e.linhas = append(e.linhas, comandoGravado{
		tipo:     "write-file",
		cmd:      "<arquivo>",
		args:     []string{filepath.Base(path)},
		conteudo: string(data),
	})
	return nil
}

// ─── Renderização dos arquivos golden ────────────────────────────────────────

func cabecalho(alvo string, c cenario, entrada string, notas ...string) string {
	var b strings.Builder
	b.WriteString("# alvo:    " + alvo + "\n")
	b.WriteString("# cenário: " + c.nome + "\n")
	escreverCampo(&b, "# sobre:   ", c.descricao)
	escreverCampo(&b, "# entrada: ", entrada)
	for _, n := range notas {
		b.WriteString("# " + n + "\n")
	}
	b.WriteString("#\n")
	b.WriteString("# GERADO POR zonas_golden_test.go. Um diff aqui é uma mudança no que o\n")
	b.WriteString("# firewall manda ao kernel — nunca edite este arquivo para fazer um teste passar.\n")
	return b.String()
}

// renderizarRegras escreve cada regra em DUAS linhas, e as duas são
// necessárias: `argv` é o contrato (um token por argumento do nft, cada um
// entre aspas — é ela que pega fusão de token) e `nft` é a leitura humana, os
// mesmos tokens juntados por espaço, como o nft os vê.
func renderizarRegras(alvo string, c cenario, entrada string, regras [][]string) string {
	var b strings.Builder
	b.WriteString(cabecalho(alvo, c, entrada,
		"formato: `argv` é o CONTRATO (um token por argumento, entre aspas);",
		"         `nft ` é a mesma regra como o nft a lê."))
	b.WriteString("\n")
	if len(regras) == 0 {
		b.WriteString("(nenhuma regra)\n")
		return b.String()
	}
	for i, r := range regras {
		fmt.Fprintf(&b, "%2d. argv  %s\n", i+1, tokensCitados(r))
		fmt.Fprintf(&b, "    nft   %s\n", strings.Join(r, " "))
	}
	return b.String()
}

func renderizarComandos(alvo string, c cenario, entrada, retorno string, linhas []comandoGravado) string {
	var b strings.Builder
	b.WriteString(cabecalho(alvo, c, entrada,
		"formato: `argv` é o CONTRATO (um token por argumento, entre aspas);",
		"         `cmd ` é o mesmo comando como se lê no shell.",
		"         exec = Execute, read = ExecuteRead (o `nft list table` do Persist",
		"         aparece aqui: é a prova de que o Persist rodou).",
		"retorno: "+retorno))
	b.WriteString("\n")
	if len(linhas) == 0 {
		b.WriteString("(nenhum comando)\n")
		return b.String()
	}
	for i, l := range linhas {
		fmt.Fprintf(&b, "%2d. %-5s argv  %s\n", i+1, l.tipo, tokensCitados(append([]string{l.cmd}, l.args...)))
		fmt.Fprintf(&b, "          cmd   %s %s\n", l.cmd, strings.Join(l.args, " "))
		if l.conteudo != "" {
			b.WriteString("          conteúdo:\n")
			for _, linha := range strings.Split(strings.TrimRight(l.conteudo, "\n"), "\n") {
				b.WriteString("          | " + linha + "\n")
			}
		}
	}
	return b.String()
}

func tokensCitados(tokens []string) string {
	out := make([]string, len(tokens))
	for i, t := range tokens {
		out[i] = fmt.Sprintf("%q", t)
	}
	return strings.Join(out, " ")
}

func textoDasRegras(regras [][]string) string {
	var b strings.Builder
	for _, r := range regras {
		b.WriteString(tokensCitados(r) + "\n")
	}
	return b.String()
}

func descreverMarcas(wans []WANMark) string {
	if len(wans) == 0 {
		return "[]"
	}
	partes := make([]string, len(wans))
	for i, w := range wans {
		partes[i] = fmt.Sprintf("{%q 0x%x}", w.Interface, w.Mark)
	}
	return "[" + strings.Join(partes, " ") + "]"
}

func descreverAcesso(a AdminAccess) string {
	return fmt.Sprintf("{ssh %v, painel %d, lan %q, wan por dhcp %t}",
		a.SSHPorts, a.PanelPort, a.LANNetworks, a.WANIsDHCP)
}

func retornoDe(err error) string {
	if err == nil {
		return "nil"
	}
	return fmt.Sprintf("%v", err)
}

func cenarioChamado(t *testing.T, nome string) cenario {
	t.Helper()
	for _, c := range cenarios() {
		if c.nome == nome {
			return c
		}
	}
	t.Fatalf("cenário %q não existe", nome)
	return cenario{}
}

// escreverCampo escreve um campo do cabeçalho dobrado em várias linhas, todas
// alinhadas embaixo da primeira: o diff costuma ser lido numa tela estreita.
func escreverCampo(b *strings.Builder, rotulo, valor string) {
	// As continuações também começam com "#": o arquivo inteiro tem de continuar
	// legível como comentário, sem uma linha solta parecendo conteúdo.
	recuo := "#" + strings.Repeat(" ", len(rotulo)-1)
	for i, linha := range quebrar(valor, 92-len(rotulo)) {
		if i == 0 {
			b.WriteString(rotulo + linha + "\n")
			continue
		}
		b.WriteString(recuo + linha + "\n")
	}
}

// quebrar dobra um texto longo para que o arquivo golden continue legível numa
// tela estreita, que é onde um diff costuma ser lido.
func quebrar(s string, largura int) []string {
	palavras := strings.Fields(s)
	if len(palavras) == 0 {
		return []string{s}
	}
	var linhas []string
	atual := palavras[0]
	for _, p := range palavras[1:] {
		if len(atual)+1+len(p) > largura {
			linhas = append(linhas, atual)
			atual = p
			continue
		}
		atual += " " + p
	}
	return append(linhas, atual)
}

// ─── A comparação ────────────────────────────────────────────────────────────

// conferirArquivo compara o corpo gerado com o arquivo golden.
//
// SEM -update, um arquivo AUSENTE é falha, não convite para criar. Um golden que
// se cria sozinho some junto com o teste que foi renomeado por engano, e a
// suíte fica verde protegendo nada.
//
// COM -update, o arquivo é reescrito E A CORRIDA FALHA quando o conteúdo muda.
// Ver o bloco no topo do arquivo: um golden que fica verde depois de se
// regravar é um botão de "faz passar".
func conferirArquivo(t *testing.T, caminho, corpo string) {
	t.Helper()

	anterior, err := os.ReadFile(caminho)
	existia := err == nil

	if *atualizarGolden {
		if existia && string(anterior) == corpo {
			return
		}
		if err := os.MkdirAll(filepath.Dir(caminho), 0o755); err != nil {
			t.Fatalf("criar o diretório do golden %s: %v", caminho, err)
		}
		if err := os.WriteFile(caminho, []byte(corpo), 0o644); err != nil {
			t.Fatalf("gravar o golden %s: %v", caminho, err)
		}
		if !existia {
			t.Errorf("golden %s CRIADO. A corrida falha de propósito: confira o arquivo novo "+
				"antes de commitá-lo.", caminho)
			return
		}
		t.Errorf("golden %s REESCRITO, e a saída do produto mudou. A corrida falha de propósito.\n"+
			"Leia o diff no git e explique por que a mudança é correta ANTES de commitar — "+
			"para a topologia de duas WANs mais LAN, mudança nenhuma é esperada.\n%s",
			caminho, diferenca(string(anterior), corpo))
		return
	}

	if !existia {
		t.Fatalf("o golden %s não existe. Rode `go test ./internal/nftables -run <este teste> -update` "+
			"e confira o arquivo criado; nunca o crie à mão.", caminho)
	}
	if string(anterior) == corpo {
		return
	}
	t.Errorf("a saída do produto não bate com o golden %s.\n"+
		"Isto é regressão até prova em contrário: para a topologia de produção o produto tem de "+
		"emitir os mesmos comandos de sempre, byte a byte.\n"+
		"Se a mudança for intencional, regrave com -update e justifique o diff.\n%s",
		caminho, diferenca(string(anterior), corpo))
}

// diferenca devolve um diff de linhas legível. Implementado aqui, com LCS
// simples, porque os arquivos são pequenos e porque este pacote não tem — nem
// vai ganhar — dependência de teste.
func diferenca(querido, obtido string) string {
	a := strings.Split(strings.TrimRight(querido, "\n"), "\n")
	b := strings.Split(strings.TrimRight(obtido, "\n"), "\n")

	// lcs[i][j] = tamanho da maior subsequência comum entre a[i:] e b[j:].
	lcs := make([][]int, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
				continue
			}
			if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}

	var out strings.Builder
	out.WriteString("  (- = o golden guardado, + = o que o produto emite agora)\n")
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			i, j = i+1, j+1
		case lcs[i+1][j] >= lcs[i][j+1]:
			fmt.Fprintf(&out, "  - %s\n", a[i])
			i++
		default:
			fmt.Fprintf(&out, "  + %s\n", b[j])
			j++
		}
	}
	for ; i < len(a); i++ {
		fmt.Fprintf(&out, "  - %s\n", a[i])
	}
	for ; j < len(b); j++ {
		fmt.Fprintf(&out, "  + %s\n", b[j])
	}
	return out.String()
}

// ─── O que os goldens de sem_wan revelaram, e o que virou disso ──────────────

// TestSemWANOsGeradoresOmitemARegraEmVezDeEmitirUmSetVazio é a versão VIRADA
// de um teste que existia aqui antes com o nome oposto.
//
// O QUE ELE DIZIA. Chamados com a lista de WANs vazia, cinco geradores montavam
// `{  }` — o set anônimo VAZIO, que o nft RECUSA. Isso nunca chegava ao kernel
// por um motivo só: EnsureAccounting, EnsureConnMark, EnsureFlows e
// EnsureMSSClamp desistiam ANTES de chamá-los. Ou seja, o early-return que este
// incremento removeu era exatamente o que impedia a regra inválida de ser
// emitida, e removê-lo sozinho teria trocado "chain que não existe" por "chain
// que existe e não reconcilia".
//
// O QUE ELE DIZ AGORA. O guarda entrou onde tinha de entrar: cada gerador
// pergunta Zone.Discriminates() e OMITE a regra quando não há como separar
// local de externo. A chain nasce vazia — que é o estado honesto — em vez de
// nascer com uma regra que o kernel recusa.
//
// O teste continua existindo, e continua apontando para o mesmo lugar, porque
// a armadilha é fácil de rearmar: basta alguém achar que a chain "devia ao
// menos ter a regra de restauração" e tirar um dos guardas.
func TestSemWANOsGeradoresOmitemARegraEmVezDeEmitirUmSetVazio(t *testing.T) {
	semZona := Zone{} // zero-value: sem WAN, sem CIDR, eixo de interface
	if semZona.Discriminates() {
		t.Fatal("a zona zero não pode discriminar: é o estado de uma caixa sem link cadastrado")
	}

	vazios := map[string][][]string{
		"acctChainRules":          acctChainRules(semZona),
		"flowsChainRules":         flowsChainRules(semZona),
		"connMarkChainRules":      connMarkChainRules(semZona, nil),
		"connMarkOutChainRules":   connMarkOutChainRules(semZona, nil),
		"mssClampRules":           mssClampRules(semZona),
		"abuseRules":              abuseRules(semZona, "{ 22 }"),
		"restoreReplyMarkRule":    {restoreReplyMarkRule(semZona)},
		"restoreOutboundMarkRule": {restoreOutboundMarkRule(semZona)},
	}
	for nome, regras := range vazios {
		for _, r := range regras {
			for _, token := range r {
				if token == "{  }" {
					t.Errorf("%s voltou a emitir o set anônimo vazio `{  }`, que o nft recusa. "+
						"Quem emite a regra tem de perguntar Zone.Discriminates() antes.\nregra: %v", nome, r)
				}
			}
		}
	}

	// As duas de restauração são o caso delicado: elas NÃO podem ser emitidas
	// sem o `iifname !=`, porque emiti-las desguarnecidas é ressuscitar a
	// armadilha da #120 (ver connmark.go). Quem as embrulha é
	// connMarkChainRules, e é lá que o guarda tem de estar.
	if regras := connMarkChainRules(semZona, nil); len(regras) != 0 {
		t.Errorf("sem WAN cadastrada a conn_mark tem de nascer VAZIA, vieram %d regras: %v", len(regras), regras)
	}

	// E o contraexemplo que já estava certo desde sempre: sem WAN, a mark_hosts
	// não some — sobra a linha do @host_wan, que não depende de eixo nenhum.
	semWAN := markHostsChainRules(semZona)
	if len(semWAN) != 1 {
		t.Fatalf("markHostsChainRules sem WAN tinha que emitir uma regra só, veio %d: %v", len(semWAN), semWAN)
	}
	if got := strings.Join(semWAN[0], " "); got != "counter meta mark set ip saddr map @host_wan" {
		t.Errorf("markHostsChainRules sem WAN: %q", got)
	}
}

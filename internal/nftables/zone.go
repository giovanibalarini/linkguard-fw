package nftables

import (
	"fmt"
	"strings"
)

// Zone é o eixo "local vs. externo" de uma regra, renderizado conforme a
// plataforma.
//
// ─── O DEFEITO QUE ISTO CORRIGE ──────────────────────────────────────────────
//
// O idioma deste pacote sempre foi "a LAN é tudo que não é WAN", escrito como
// `iifname != { as WANs }`. Numa caixa com várias interfaces isso diz a coisa
// certa: o pacote que entrou por onde não é WAN veio de dentro.
//
// Numa VM de VNIC única a frase é VAZIA. Entra e sai pela MESMA interface — o
// que a plataforma chama de hairpin, e o que platform.Capabilities.RoutedTransit
// == false marca —, então `iifname != { ens3 }` não casa NADA e `iifname
// { ens3 }` casa TUDO. As duas formas continuam sendo aceitas pelo nft e
// continuam sendo escritas na chain; o que some é o significado. Foi apurado:
//
//   - a contabilidade por host para de contar e devolve zero em silêncio, que é
//     indistinguível de "ninguém trafegou" — a confusão que a #112 existe para
//     acabar;
//   - o registro de conversa grava a ida com os campos INVERTIDOS (o endereço
//     da internet no lugar do host) mais a volta correta: cada conversa vira
//     duas linhas, uma certa e um fantasma espelhado, comendo metade do teto;
//   - o descarte de entrada da WAN corta DNS, NTP e painel vindos das outras
//     máquinas da própria rede, porque elas chegam pela mesma interface.
//
// ─── POR QUE UM RENDERIZADOR, E NÃO UMA TROCA DE `iifname` POR `ip saddr` ────
//
// A máquina do dono está em PRODUÇÃO 24/7 com duas WANs e uma LAN. Para essa
// topologia o produto tem de continuar emitindo exatamente os mesmos comandos
// de sempre, byte a byte — não "equivalentes", os MESMOS. Trocar o eixo para
// CIDR em todo lugar mudaria a chain de uma caixa que está funcionando, para
// resolver um problema que ela não tem.
//
// Então a zona não substitui `iifname`: ela RENDERIZA o prefixo da regra
// conforme a plataforma. Cada gerador pergunta "como se diz 'veio de dentro'
// aqui?" e recebe tokens. Com hairpin == false, cada método devolve
// LITERALMENTE a sequência que o código de antes construía — inclusive o
// espaçamento do set anônimo, que era montado em seis lugares diferentes e
// agora é montado num só.
//
// ─── VALOR, E ZERO-VALUE PERMISSIVO ──────────────────────────────────────────
//
// Valor e não ponteiro, e zero-value permissivo pela mesma razão de
// platform.Snapshot (ver Capable): um caminho que esqueça de preencher a zona
// se comporta como o produto se comporta hoje — eixo de interface, sem
// discriminar quando não há WAN cadastrada. O modo novo é o que exige ser
// pedido; o modo antigo é o que acontece por omissão.
type Zone struct {
	// wanIfaces são as interfaces de saída para a internet, JÁ higienizadas e
	// NA ORDEM DE ENTRADA. A ordem é contrato: mssClampRules emite uma regra
	// por WAN nessa ordem, e ordenar aqui por conveniência reescreveria a
	// chain mss_clamp da produção sem que nada mais acusasse.
	wanIfaces []string
	// localNets são os CIDRs de dentro, já higienizados por sanitizeNetworks.
	// Só são consultados em hairpin — fora dele o eixo é a interface, e uma
	// zona com CIDR preenchido renderiza igualzinho a uma sem.
	localNets []string
	// hairpin == !platform.Capabilities.RoutedTransit.
	hairpin bool
	// pathMTU é o que o CAMINHO para fora suporta, em bytes, JÁ higienizado
	// por sanitizePathMTU — 0 quando desconhecido. Ver ZoneFacts.PathMTU.
	pathMTU int
}

// ZoneFacts é o que este pacote precisa saber da plataforma — e SÓ isso.
//
// Struct estreita em vez de importar internal/platform: quem escreve regra de
// firewall não pode depender de quem detecta nuvem, e dois campos não
// justificam o acoplamento. É a mesma disciplina de hostflows.Banco e de
// platform.SettingsStore.
type ZoneFacts struct {
	// Hairpin diz que entra e sai pela mesma interface. Falso é o valor
	// permissivo: é a caixa on-prem, e é toda máquina anterior a esta entrega.
	Hairpin bool
	// LocalNets são os CIDRs que contam como "dentro" quando Hairpin é true.
	LocalNets []string

	// PathMTU é o que o CAMINHO para fora suporta, em bytes. 0 = desconhecido,
	// e desconhecido é o valor PERMISSIVO: o ajuste de MSS segue por `rt mtu`,
	// byte a byte o que a produção emite hoje.
	//
	// NÃO É A MTU DA INTERFACE. Numa VM da OCI a ens3 ANUNCIA 9000 e o caminho
	// externo aceita 1500 (medido, `ping -M do`). Uma regra que clampasse para
	// 8960 é pior do que nenhuma — ver mssclamp.go. platform.NetFacts grafa a
	// distinção em dois campos separados (LinkMTU vs. PathMTU) pela mesma razão.
	PathMTU int
}

// NewZone monta a zona.
//
// Higieniza aqui dentro, e não confia em quem chama: os dois valores vão para
// dentro de um argv do nft, e a lista de interfaces já chegou de seis lugares
// diferentes neste pacote. sanitizeInterfaces e sanitizeNetworks são
// idempotentes, então higienizar de novo o que já veio limpo não muda nada —
// e higienizar o que veio sujo é a diferença entre uma regra recusada e uma
// injeção de comando.
func NewZone(wanIfaces, localNets []string, hairpin bool, pathMTU int) Zone {
	return Zone{
		wanIfaces: sanitizeInterfaces(wanIfaces),
		localNets: sanitizeNetworks(localNets),
		hairpin:   hairpin,
		pathMTU:   sanitizePathMTU(pathMTU),
	}
}

// sanitizePathMTU transforma em 0 — isto é, em "não sei" — todo número que não
// pode ser MTU de caminho nenhum.
//
// O PISO É 576, o mínimo de remontagem do IPv4: abaixo dele o valor é lixo, e
// um clamp derivado de lixo TRAVA conexão em vez de corrigi-la — o oposto
// exato do que o ajuste de MSS existe para fazer. O teto é 65535, o maior
// datagrama IPv4 que existe; acima disso é campo de JSON corrompido, não MTU.
//
// Higienizar aqui, e não no gerador, é o mesmo motivo de sanitizeInterfaces
// estar em NewZone: o número vai para dentro de um argv do nft, e a fonte dele
// é um instantâneo lido de disco.
func sanitizePathMTU(mtu int) int {
	if mtu < mssClampMinPathMTU || mtu > 65535 {
		return 0
	}
	return mtu
}

// Hairpin diz se entra e sai pela mesma interface.
func (z Zone) Hairpin() bool { return z.hairpin }

// PathMTU é o que o caminho para fora suporta, em bytes; 0 quando desconhecido
// ou fora de faixa.
//
// O NOME CARREGA A DISTINÇÃO, e ela é o incremento inteiro: não é MTU(), porque
// não é a MTU que a interface anuncia. Quem quiser a segunda está pedindo a
// pergunta errada — ver o campo em ZoneFacts.
func (z Zone) PathMTU() int { return z.pathMTU }

// PerLink diz se casar por interface INDIVIDUAL decide alguma coisa aqui.
//
// Falso em hairpin, e a consequência é o que os geradores por-WAN fazem com
// isso: com uma VNIC só, "por qual link isto passou" tem uma resposta só.
// Marcar conexão por link e ajustar MSS por link passam a escrever estado que
// nenhuma `ip rule` consome — e platform.DeriveCapabilities já desligou
// MultiWAN, LinkFailover, LoadBalancing e PerLinkPolicyRouting no mesmo lugar
// em que ligou o hairpin. Ver connmark.go e mssclamp.go.
func (z Zone) PerLink() bool { return !z.hairpin }

// Discriminates diz se a zona sabe separar local de externo.
//
// SEM WAN CADASTRADA NÃO DISCRIMINA, EM PLATAFORMA NENHUMA, e isso é
// deliberado. É o comportamento de toda máquina anterior a esta entrega, e
// manter a condição idêntica é o que garante que uma caixa recém-instalada não
// ganhe, de surpresa, regras de descarte que ela nunca teve. Ligar a medição e
// a proteção numa VM de nuvem continua dependendo de o link ser cadastrado —
// que é matéria do incremento do uplink, não deste.
//
// Em hairpin exige TAMBÉM conhecer pelo menos um CIDR local: sem ele não há
// como dizer o que é de dentro, e o gerador tem de OMITIR a regra guardada em
// vez de emitir `ip saddr { }` — o set anônimo vazio, que o nft recusa.
func (z Zone) Discriminates() bool {
	if len(z.wanIfaces) == 0 {
		return false
	}
	if z.hairpin {
		return len(z.localNets) > 0
	}
	return true
}

// WANIfaces devolve uma cópia da lista, na ordem de entrada, para os geradores
// que emitem uma regra POR WAN. Cópia, e não a slice interna: um gerador que
// ordenasse o resultado no lugar reescreveria a chain de todo mundo.
func (z Zone) WANIfaces() []string {
	return append([]string(nil), z.wanIfaces...)
}

// ─── Os renderizadores ───────────────────────────────────────────────────────
//
// Cada um devolve o PREFIXO de tokens de uma regra. Quem chama concatena o
// resto — é por isso que devolvem []string e não texto: cada token vira um
// argv separado do nft, e nada aqui passa por um shell.

// FromLocal: "o pacote veio de dentro".
//
//	multi-NIC: {"iifname", "!=", `{ "wan1", "wan2" }`}
//	hairpin:   {"ip", "saddr", "{ 10.0.0.0/24 }"}
func (z Zone) FromLocal() []string {
	if z.hairpin {
		return []string{"ip", "saddr", z.netSet()}
	}
	return []string{"iifname", "!=", z.ifaceSet()}
}

// ToLocal: "o pacote vai para dentro".
//
// Existe separada de FromLocal porque a regra de DOWNLOAD da contabilidade casa
// `oifname !=`, e forçá-la no eixo de entrada mudaria a chain on-prem — o
// colapso do eixo de saída é exatamente o tipo de regressão calada que o
// golden desta entrega existe para pegar.
//
//	multi-NIC: {"oifname", "!=", `{ "wan1", "wan2" }`}
//	hairpin:   {"ip", "daddr", "{ 10.0.0.0/24 }"}
func (z Zone) ToLocal() []string {
	if z.hairpin {
		return []string{"ip", "daddr", z.netSet()}
	}
	return []string{"oifname", "!=", z.ifaceSet()}
}

// FromExternal: "o pacote veio de fora" — o complemento exato de FromLocal.
//
//	multi-NIC: {"iifname", `{ "wan1", "wan2" }`}
//	hairpin:   {"ip", "saddr", "!=", "{ 10.0.0.0/24 }"}
func (z Zone) FromExternal() []string {
	if z.hairpin {
		// `iifname != "lo"` NÃO É ENFEITE, É O CONSERTO DE UM INCIDENTE REAL.
		//
		// A forma multi-placa casa `iifname { wan1, wan2 }`, e daí decorre de
		// graça uma propriedade que ninguém tinha escrito: o loopback NUNCA
		// casa, porque "lo" não é uma WAN. A forma de CIDR perdeu isso —
		// `ip saddr != { 10.0.0.0/24 }` casa 127.0.0.1, que de fato não está na
		// rede local.
		//
		// Consequência medida num bastion de verdade: o descarte final de
		// WANInputRules passou a derrubar conexão NOVA de 127.0.0.1 para
		// 127.0.0.53, que é por onde todo processo da máquina fala com o
		// systemd-resolved. O sintoma foi DNS parar de resolver enquanto TCP
		// direto por IP continuava funcionando — e nenhum teste de mesa pega
		// isso, porque nenhum deles tem um resolver local.
		return []string{"iifname", "!=", `"lo"`, "ip", "saddr", "!=", z.netSet()}
	}
	return []string{"iifname", z.ifaceSet()}
}

// ToExternal: "o pacote SAI por uma das WANs". Casa por interface em QUALQUER
// plataforma, e é por isso que não é o espelho de ToLocal.
//
// NÃO COLAPSA PARA CIDR EM HAIRPIN, de propósito. Quem consome isto é o
// masquerade, e masquerade é uma decisão sobre a PLACA por onde o pacote
// efetivamente sai: trocada por `ip daddr != { locais }`, a regra mascararia
// também o que sai para lugar nenhum e deixaria de dizer o que quer dizer.
//
//	sempre: {"oifname", `{ "wan1", "wan2" }`}
func (z Zone) ToExternal() []string {
	return []string{"oifname", z.ifaceSet()}
}

// FromExternalByIface casa SEMPRE por interface, em qualquer plataforma.
//
// EXISTE POR UMA RAZÃO SÓ, E ELA É UMA LACUNA CONHECIDA. Na família `inet`,
// `ip saddr` casa apenas IPv4 — é o que sanitizeNetworks documenta e o motivo
// de ele recusar CIDR v6. Então as linhas de WANInputRules que são
// exclusivamente IPv6 (vizinhança, erros de ICMPv6, cliente DHCPv6, echo) NÃO
// PODEM ser renderizadas pelo eixo de CIDR: casadas por `ip saddr` elas deixam
// de casar qualquer pacote e o IPv6 perde as liberações de que depende.
//
// Elas ficam no eixo de interface, com os tokens intactos. Em hairpin isso casa
// mais do que devia — casa tudo —, e ISSO NÃO É REGRESSÃO DE SEGURANÇA porque
// as quatro são `accept` de protocolo de infraestrutura. O que É uma lacuna, e
// está registrada em WANInputRules, é o outro lado: o descarte final não tem
// equivalente v6 em hairpin. Ver o slog.Warn de lá.
//
// A saída honesta é `ip6 saddr { prefixo local }`, e ela precisa do prefixo
// IPv6 de dentro, que fonte nenhuma deste produto conhece hoje.
func (z Zone) FromExternalByIface() []string {
	return []string{"iifname", z.ifaceSet()}
}

// FromExternalIface: "veio POR ESTA WAN". Só faz sentido com PerLink().
//
//	{"iifname", `"wan1"`}
func (z Zone) FromExternalIface(iface string) []string {
	return []string{"iifname", fmt.Sprintf("%q", iface)}
}

// ToExternalIface: "vai POR ESTA WAN". Só faz sentido com PerLink().
//
//	{"oifname", `"wan1"`}
//
// Não colapsa para FromExternal em hairpin, de propósito: todo chamador destes
// dois já tem de perguntar PerLink() antes, porque o que eles escrevem — a
// marca daquele link — é que perde o sentido, não o casamento. Um colapso aqui
// seria um ramo que nenhum caminho alcança, isto é, código não exercitado
// fingindo ser tratamento de caso.
func (z Zone) ToExternalIface(iface string) []string {
	return []string{"oifname", fmt.Sprintf("%q", iface)}
}

// ─── Os dois literais ────────────────────────────────────────────────────────

// ifaceSet monta `{ "wanA", "wanB" }` como UM token.
//
// Esta função é a fusão de seis construtores idênticos que viviam em
// accounting.go, flows.go, connmark.go, reconcile.go, abusers.go e waninput.go.
// O espaçamento — chave, espaço, itens separados por vírgula e espaço, espaço,
// chave — é o contrato: ele está gravado nos goldens da topologia de produção,
// e trocá-lo por `{"a","b"}` mudaria toda regra de toda chain da caixa do dono.
func (z Zone) ifaceSet() string {
	quoted := make([]string, len(z.wanIfaces))
	for i, iface := range z.wanIfaces {
		quoted[i] = fmt.Sprintf("%q", iface)
	}
	return "{ " + strings.Join(quoted, ", ") + " }"
}

// netSet monta `{ 10.0.0.0/24 }` como UM token, na forma que survival.go e a
// proteção do NTP já usam — set ANÔNIMO, e não um `@local_nets` nomeado.
//
// POR QUE ANÔNIMO. Um set nomeado acrescenta um ciclo de vida inteiro: criar no
// bootstrap e no EnsureTable, sincronizar elementos, sobreviver ao Persist e ao
// Restore, aparecer em classifyRule e na higienização do snapshot. Isso por
// zero benefício com um a três CIDRs. E como estes renderizadores devolvem
// tokens, trocar por {"ip","saddr","@local_nets"} depois é uma linha aqui.
func (z Zone) netSet() string {
	return networkSet(z.localNets)
}

// ─── A ligação com a plataforma ──────────────────────────────────────────────

// SetZoneFactsSource liga a fonte que diz em que tipo de máquina este firewall
// está. Ver o campo zoneFactsSource em service.go para o contrato de ausência
// e de erro.
//
// Fonte, e não parâmetro: nenhum método público deste pacote muda de
// assinatura por causa das zonas. É o mesmo seam de SetWANInterfacesSource e
// SetInputPolicySource, e existe pelo mesmo motivo — a leitura tem de
// acontecer DENTRO da reconciliação, sob o mesmo lock da sequência
// "ler → flush → readicionar" (#81).
func (s *Service) SetZoneFactsSource(src func() (ZoneFacts, error)) {
	s.zoneFactsSource = src
}

func (s *Service) zoneFacts() (ZoneFacts, error) {
	if s.zoneFactsSource == nil {
		return ZoneFacts{}, nil
	}
	f, err := s.zoneFactsSource()
	if err != nil {
		return ZoneFacts{}, fmt.Errorf("ler a plataforma para decidir o eixo das regras: %w", err)
	}
	return f, nil
}

// zone resolve a zona desta reconciliação a partir da lista de WANs que o
// chamador já tem em mãos.
//
// A lista chega por PARÂMETRO, e não da fonte de WANs, porque cada Ensure*
// recebe a sua — e porque a ORDEM importa: mssClampRules emite uma regra por
// WAN na ordem do link, enquanto markHostsChainRules trabalha com a lista
// ORDENADA. Passar a lista que o chamador já usa hoje é o que mantém as duas
// chains byte a byte como estão.
func (s *Service) zone(wanIfaces []string) (Zone, error) {
	f, err := s.zoneFacts()
	if err != nil {
		return Zone{}, err
	}
	return NewZone(wanIfaces, f.LocalNets, f.Hairpin, f.PathMTU), nil
}

// zoneRule concatena o prefixo devolvido por um renderizador com o resto da
// regra, numa slice NOVA.
//
// Existe para que nenhum gerador escreva `append(z.FromLocal(), …)`: os
// renderizadores devolvem literais, e um `append` sobre um literal que um dia
// ganhe folga de capacidade passaria a escrever por cima do prefixo de outra
// regra. É o tipo de aliasing que não aparece em teste de unidade e aparece na
// chain de uma caixa em produção.
func zoneRule(prefixo []string, resto ...string) []string {
	r := make([]string, 0, len(prefixo)+len(resto))
	r = append(r, prefixo...)
	return append(r, resto...)
}

// motivoDeChainVazia devolve, em uma frase, POR QUE uma chain nasceu sem
// regra. Vai para o slog de quem cria a chain vazia.
//
// Um aviso que diz só "a chain está vazia" manda o operador ler código para
// descobrir se falta cadastrar um link, se a plataforma não suporta o recurso
// ou se alguma coisa quebrou. Estes três motivos são os únicos possíveis, e
// dizê-los é a diferença entre um alerta e um enigma.
//
// O QUE NÃO ENTRA AQUI: motivo que valha para UMA chain só. A frase desta
// função vai para o aviso de cinco chamadores diferentes, e um motivo
// específico posto aqui faz os outros quatro MENTIREM — a conn_mark de uma VM
// de nuvem nasce vazia porque há um link só para marcar, nunca porque falta uma
// MTU. Quem tem motivo próprio escreve a própria função e cai nesta como
// último caso: ver motivoDeMSSClampVazia, em mssclamp.go.
func motivoDeChainVazia(z Zone) string {
	switch {
	case len(z.wanIfaces) == 0:
		return "nenhuma interface WAN cadastrada"
	case z.hairpin && len(z.localNets) == 0:
		return "máquina de interface única e nenhuma rede local conhecida; sem CIDR de dentro não há como separar local de externo"
	case z.hairpin:
		return "máquina de interface única: não há vários links para distinguir"
	default:
		return "sem regra a emitir"
	}
}

package nftables

// As regras de sobrevivência: o que precisa continuar passando quando a chain
// input deixar de ser `policy accept` (issue #78).
//
// NADA AQUI ESTÁ LIGADO AO RENDERIZADOR AINDA, E ISSO É DE PROPÓSITO.
//
// Escrever estas linhas na chain hoje, com a política ainda em `accept`, não
// seria inócuo: elas entram ACIMA dos jumps dos grupos. Um admin que tenha um
// grupo de escopo input bloqueando DNS de uma VLAN passaria a ter esse bloqueio
// anulado em silêncio por uma linha de `accept` daqui — o produto afrouxando o
// firewall de quem já o usa, para preparar um recurso que ainda não existe.
//
// Elas entram em vigor JUNTO com a política restritiva, nunca antes. O que este
// arquivo entrega agora é a lista existindo, revisável e coberta por teste, em
// vez de nascer no meio da mudança arriscada.
//
// POR QUE A LISTA É ESTA. Ela saiu de uma investigação do que hoje mantém o
// admin dentro da máquina, e a resposta foi desconfortável: **a política, e só
// ela**. Não existe uma única regra de sobrevivência no ruleset atual — o acesso
// administrativo é inteiramente subproduto de `policy accept`. Duas das linhas
// abaixo (`udp dport 68` e o ICMPv6 de vizinhança) só apareceram na revisão
// adversarial do desenho, e são as duas que quebram DIAS depois, sem relação
// visível com a mudança:
//
//   - sem `udp dport 68`, a WAN que pega endereço por DHCP nunca mais renova
//     depois de um flap de link. O REBIND sai de 0.0.0.0:68 para broadcast e
//     não casa a tupla de retorno do conntrack. Sintoma: "a internet caiu
//     sozinha na quarta";
//   - sem o ICMPv6 de vizinhança, o IPv6 morre INTEIRO — a tabela é `inet`, e
//     Neighbor Solicitation/Advertisement são NEW, sem `related`. O IPv4 segue
//     funcionando, que é justamente o que faz ninguém relacionar o sintoma com
//     o firewall. ARP não é atingido (família `arp`, fora do `inet`), e é essa
//     assimetria que esconde o erro.
//
// O QUE NÃO ESTÁ AQUI, E É A DECISÃO MAIS IMPORTANTE DESTE ARQUIVO.
//
// Não há `ct state established accept`. A chain hoje aceita `related` e SÓ
// `related`, por uma razão registrada em reconcile.go:483-491: com
// `established`, a sessão SSH do operador sobrevive ao próprio bloqueio. Ele
// testa, vê tudo funcionando, confirma — e descobre na próxima reconexão, já
// sem rede embaixo. O teste dos 90 segundos passaria a mentir.
//
// Só que sem `established` morre todo retorno de conexão de saída: o apt, o
// http.Client do updater, a recursão do unbound, o chrony contra o pool. Não
// existe valor dessa flag em que as duas propriedades valham ao mesmo tempo.
//
// Isso é um problema de DESENHO, não de implementação, e está aberto na #78
// (item D). A saída apontada pela revisão é tornar a confirmação impossível
// pela conexão antiga — o handler alcança o net.Conn via ConnContext. Enquanto
// isso não existir, esta lista NÃO deve ser ligada com uma política restritiva.

// AdminAccess é o que precisa continuar alcançando o próprio firewall.
//
// Os campos são o que o chamador sabe e este pacote não pode descobrir sozinho
// (internal/nftables não importa internal/storage — ver o comentário em
// groups.go:219-230).
type AdminAccess struct {
	// SSHPorts são as portas em que o sshd está escutando. VAZIO cai em 22.
	//
	// É uma lista, e não um número, porque sshd com mais de um `Port` é
	// configuração comum em quem está migrando de porta: liberar só uma das
	// duas tranca metade das sessões — e a metade que fica de fora é
	// exatamente a que o admin ainda não terminou de migrar.
	SSHPorts []int
	// PanelPort é a porta do painel. Vem da config, e NÃO é fixa: o default do
	// binário é 8080 e o do pacote .deb é 9997. Zero deixa o painel de fora.
	PanelPort int
	// LANNetworks são as redes que servem DHCP e DNS a partir desta máquina.
	// Vazio omite as linhas correspondentes.
	LANNetworks []string
	// WANIsDHCP diz se alguma interface pega endereço por DHCP. Só então a
	// linha da porta 68 é emitida.
	WANIsDHCP bool
}

// SurvivalRules devolve as linhas que precedem tudo numa chain input com
// política restritiva.
//
// A ordem é a de avaliação, e ela importa: o que é mais barato e mais universal
// vem primeiro. `related` continua sendo a primeira linha, como já é hoje.
//
// Devolve tokens (e não texto) pelo mesmo motivo do resto deste pacote: cada
// elemento vira um argv separado, e nada aqui passa por um shell.
func SurvivalRules(a AdminAccess) [][]string {
	rules := [][]string{
		// Já é a primeira linha da chain hoje (reconcile.go:520). Repetida aqui
		// para que esta lista descreva a chain inteira, e não um apêndice.
		{"ct", "state", "related", "counter", "accept"},

		// O loopback. Sem isto, a própria máquina deixa de falar consigo: o
		// painel escutando em 127.0.0.1 (o default de listen_addr) fica
		// inalcançável até por um túnel SSH.
		{"iif", "lo", "counter", "accept"},
	}

	// Vizinhança IPv6. Vem cedo porque, sem ela, NADA de IPv6 funciona depois —
	// inclusive as linhas de acesso administrativo abaixo, que seriam aceitas
	// e nunca alcançadas, porque a resolução de vizinhança falhou antes.
	rules = append(rules, []string{
		"icmpv6", "type",
		"{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert }",
		"counter", "accept",
	})

	// Acesso administrativo. Sem restrição de interface DE PROPÓSITO: casar por
	// `iifname` aqui é o que a issue #83 mostra que não sobrevive a um rename de
	// NIC — e um anti-lockout que fica mudo depois de um reshuffle de PCI é pior
	// do que nenhum, porque dá a impressão de que existe.
	if set := portasDeGerencia(a); set != "" {
		rules = append(rules, []string{"tcp", "dport", set, "counter", "accept"})
	}

	// DHCP e DNS servidos à LAN. Sem estas, os aparelhos param de pegar IP e de
	// resolver nomes — e o admin culpa a internet, não o firewall.
	if nets := sanitizeNetworks(a.LANNetworks); len(nets) > 0 {
		set := networkSet(nets)
		rules = append(rules,
			[]string{"udp", "dport", "67", "ip", "saddr", set, "counter", "accept"},
			[]string{"udp", "dport", "53", "ip", "saddr", set, "counter", "accept"},
			[]string{"tcp", "dport", "53", "ip", "saddr", set, "counter", "accept"},
		)
	}

	// A própria caixa como CLIENTE de DHCP. Só quando alguma WAN é por DHCP:
	// numa máquina com endereçamento estático a linha não teria o que aceitar.
	if a.WANIsDHCP {
		rules = append(rules, []string{"udp", "dport", "68", "counter", "accept"})
	}

	return rules
}

// networkSet formata uma lista de redes como set do nft. Uma rede só continua
// virando set: `{ 192.168.3.0/24 }` é válido, e uma forma só evita que quem lê
// a chain tenha de reconhecer duas.
func networkSet(nets []string) string {
	out := "{ "
	for i, n := range nets {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out + " }"
}

// ForwardSurvivalRules é o equivalente da lista acima para a chain FORWARD —
// o tráfego que ATRAVESSA o firewall (issue #92).
//
// A lista é curta porque a pergunta é outra. A input protege o acesso À
// máquina; a forward protege as conexões que a rede já tem. Nada de SSH, painel
// ou DHCP servido aqui: nenhum deles atravessa o firewall.
//
// E `established` ENTRA, ao contrário da input.
//
// Isso não contradiz a issue #86 — contradiria se fosse a mesma chain. O
// problema de lá é a sessão SSH do OPERADOR sobrevivendo ao próprio bloqueio e
// fazendo o teste dos 90 segundos mentir; essa sessão vai para o firewall, ou
// seja, é `input`. Na forward, `established` é o que impede toda conexão de
// saída da LAN de morrer no meio: sem ela, "bloquear tudo" derruba cada
// download, cada chamada e cada página aberta no instante em que é aplicado,
// inclusive os que já estavam em curso.
func ForwardSurvivalRules() [][]string {
	return [][]string{
		// O retorno do que saiu. Sem esta linha, uma política restritiva na
		// forward não bloqueia "o que não foi liberado": bloqueia tudo, porque
		// nenhuma resposta de servidor casa com regra de saída.
		{"ct", "state", "established,related", "counter", "accept"},

		// Os encaminhamentos de porta. `ct status dnat` casa com o que a chain
		// de DNAT já traduziu — uma linha só, em vez de uma por encaminhamento,
		// porque a lista deles muda por um caminho que não passa por aqui.
		//
		// A #82 é o que faz esta linha bastar: sem ela, criar um encaminhamento
		// não reconciliava, e o DNAT ficava gravado com o pacote morrendo na
		// política. Com ela, o par (DNAT traduzido + esta liberação) existe
		// sempre junto.
		{"ct", "status", "dnat", "counter", "accept"},
	}
}

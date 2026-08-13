package nftables

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
)

// GroupChainPrefix identifies, in the live ruleset, the chains that belong
// to admin-defined rule groups — this is how reconciliation knows which
// chains are its own, so it can delete orphans without touching anything
// that belongs to a third party.
const GroupChainPrefix = "grp_"

// Values for StoredGroup.Fallthrough: what a group does with traffic that
// entered it (the entry condition matched) but matched none of the rules
// inside.
const (
	FallthroughContinue = "continue" // no final line: the jump returns and evaluation continues
	FallthroughAccept   = "accept"   // counter accept as the last line
	FallthroughDrop     = "drop"     // counter drop as the last line
)

// Kind separa os grupos que o admin criou dos dois que o próprio LinkGuard
// mantém para os named sets de bloqueio. Vazio conta como admin: é o valor
// que toda linha criada antes desta coluna existir carrega, e tratá-las como
// "do sistema" daria a elas proteções (não apagar, não renomear) que o admin
// nunca pediu.
const (
	GroupKindAdmin        = "admin"
	GroupKindBlockedHosts = "blocked_hosts"
	GroupKindBlocklist    = "blocklist"
)

// Scope diz para qual tráfego o grupo vale, e é o que decide em QUAL chain o
// `jump` dele é escrito (Fase C2):
//
//   - ScopeForward: tráfego ATRAVESSANDO o firewall (chain forward) — a LAN
//     saindo para a internet, uma VLAN falando com outra. É o único escopo
//     que existia até aqui.
//   - ScopeInput: tráfego DESTINADO ao próprio firewall (chain input) — SSH,
//     o painel, DNS, Samba.
//
// Vazio conta como ScopeForward: é o valor de toda linha criada antes desta
// coluna existir, e todo grupo que já existia é de tráfego atravessando.
// Tratar vazio como input moveria essas regras para outra chain, aplicando-as
// a um tráfego que o admin nunca pretendeu filtrar.
const (
	ScopeForward = "forward"
	ScopeInput   = "input"
)

// GroupScope normaliza o escopo gravado: vazio vira ScopeForward. Existe para
// que nenhum renderizador precise repetir a regra do vazio — os dois
// (forwardChainRules e inputChainRules) leem daqui, e não podem divergir
// sobre onde uma linha antiga cai.
func GroupScope(g StoredGroup) string {
	if g.Scope == ScopeInput {
		return ScopeInput
	}
	return ScopeForward
}

// GroupHostChain devolve o nome da chain onde o `jump` deste grupo é escrito —
// a chain "hospedeira" dele. É a mesma decisão que os dois renderizadores
// tomam (forwardChainRules pula quem é de input, inputChainRules pula quem
// não é), aqui em uma função só para que quem PROCURA o jump no firewall vivo
// não possa procurar na chain errada: um grupo de escopo input cujo jump fosse
// procurado na forward apareceria eternamente como "configurado, não
// aplicado" no painel, com o jump vivo o tempo todo na input — mentira na
// tela, que é o que este painel existe para não fazer.
//
// Grupo do sistema é sempre forward, qualquer que seja a coluna scope: o
// conteúdo dele é um named set de bloqueio de tráfego atravessando (as linhas
// dele nem são jumps).
func GroupHostChain(g StoredGroup) string {
	if !IsSystemGroup(g.Kind) && GroupScope(g) == ScopeInput {
		return InputChain
	}
	return ForwardChain
}

// Nomes de chain reservados dos dois grupos do sistema. Eles NÃO começam com
// GroupChainPrefix, e isso não é estética: a limpeza de chains órfãs de
// ReconcileGroups varre o ruleset vivo procurando exatamente o prefixo grp_ e
// apaga toda chain que não corresponda a um grupo do banco. Um grupo do
// sistema batizado de grp_… entraria nessa varredura, e a coluna chain_name é
// NOT NULL UNIQUE (não dá para deixar vazia).
//
// Grupo do sistema não tem chain própria — as linhas dele moram na própria
// forward, porque o conteúdo é um named set, não uma lista de regras. Estes
// nomes existem só para ocupar a coluna com um valor reservado, inequívoco e
// que nenhuma varredura de chain de grupo vai enxergar.
// TestSystemChainNamesAreNeverTakenForGroupChains guarda essa propriedade.
const (
	SystemChainBlockedHosts = "sys_blocked_hosts"
	SystemChainBlocklist    = "sys_blocklist"
)

// systemGroupForwardRules é a fonte única sobre "o que é um grupo do
// sistema": as chaves são os únicos kinds que este pacote reconhece como
// mantidos pelo LinkGuard, e o valor é exatamente a linha (ou par de linhas)
// que aquele kind emite na forward. IsSystemGroup e forwardChainRules leem
// as duas do mesmo mapa — não é mais possível um kind ser "do sistema" para
// um e cair no ramo do admin no outro, porque não existe um segundo lugar
// que tenha essa opinião.
//
// Antes desta mudança, IsSystemGroup era uma lista fechada de kinds e
// forwardChainRules era um switch com um `case` para cada um mais um
// `default` tratado como admin — coincidiam porque os dois foram escritos
// juntos, mas nada os mantinha em sincronia: um terceiro kind de sistema
// acrescentado só a um dos dois faria o outro divergir em silêncio (ver
// TestSystemGroupKindKnownToIsSystemGroupIsAlwaysRenderedAsSystem). Isto
// fecha essa divergência estruturalmente, não com uma checagem a mais.
var systemGroupForwardRules = map[string]func() [][]string{
	GroupKindBlockedHosts: func() [][]string {
		return [][]string{
			{"ip", "saddr", "@" + BlockedSet, "counter", "drop"},
			{"ip", "daddr", "@" + BlockedSet, "counter", "drop"},
		}
	},
	GroupKindBlocklist: func() [][]string {
		return [][]string{
			{"ip", "daddr", "@blocklist", "counter", "drop"},
			{"ip", "saddr", "@blocklist", "counter", "drop"},
		}
	},
}

// administrativeBlockRules é a forma canônica dos quatro bloqueios
// administrativos fixos — blocked_hosts primeiro, depois blocklist, a mesma
// ordem que a migração usa ao criar os dois grupos do sistema (posições 0 e
// 1) — lida direto de systemGroupForwardRules, a mesma fonte que
// forwardChainRules usa para os dois kinds de sistema.
//
// Existe para dar a buildBootstrapRuleset (bootstrap.go) as MESMAS quatro
// linhas sem uma segunda cópia literal: antes desta função, forwardChainRules
// e buildBootstrapRuleset tinham cada uma sua própria cópia das quatro
// strings, e bootstrap_test.go repetia as mesmas de novo — mudar a forma de
// uma linha de um lado e atualizar só os testes daquele lado deixava o outro
// divergindo em silêncio.
//
// Os dois consumidores querem formas diferentes do mesmo conteúdo:
// forwardChainRules quer token sets ([]string por linha, é o que ela mesma
// devolve), e buildBootstrapRuleset monta texto (um arquivo de ruleset para
// `nft -f`) — por isso esta função devolve token sets como forwardChainRules
// já devolve, e quem escreve texto (bootstrap.go) junta cada um com espaço,
// exatamente como já faz para as regras dos grupos do admin em outros
// lugares deste pacote.
func administrativeBlockRules() [][]string {
	var rules [][]string
	rules = append(rules, systemGroupForwardRules[GroupKindBlockedHosts]()...)
	rules = append(rules, systemGroupForwardRules[GroupKindBlocklist]()...)
	return rules
}

// IsSystemGroup reporta se o grupo é mantido pelo LinkGuard em vez de criado
// pelo admin. Deliberadamente uma lista fechada, não "!= admin": um kind
// desconhecido (banco de uma versão futura, linha editada à mão) é tratado
// como do admin, que é o lado seguro — o erro caro seria travar a edição de
// um grupo que o admin criou. A lista fechada é systemGroupForwardRules, não
// uma segunda cópia dos dois nomes.
func IsSystemGroup(kind string) bool {
	_, ok := systemGroupForwardRules[kind]
	return ok
}

// StoredGroup is this package's own view of a rule group, deliberately
// independent of internal/storage.FirewallGroup — internal/nftables must
// not import internal/storage (a cycle), exactly like StoredRule already
// does. The caller converts before calling.
//
// As tags json existem porque GroupView (merge_groups.go) embute este tipo e
// é o corpo que a API devolve: sem elas o painel receberia as chaves em
// PascalCase, divergindo de todo o resto da API — e `Rules` colidiria com o
// `rules` de GroupView, que é a visão honesta (banco + nft vivo) e a única
// que deve ir para a tela. Daí o `-`: a lista crua de dentro nunca é
// serializada, para não haver duas listas de regras na mesma resposta,
// dizendo coisas diferentes.
type StoredGroup struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	ChainName   string       `json:"chain_name"`
	Position    int          `json:"position"`
	Enabled     bool         `json:"enabled"`
	CondSaddr   string       `json:"cond_saddr"`
	CondDaddr   string       `json:"cond_daddr"`
	CondIif     string       `json:"cond_iif"`
	Fallthrough string       `json:"fallthrough"`
	Kind        string       `json:"kind"`
	Scope       string       `json:"scope"`
	Rules       []StoredRule `json:"-"`
}

// GroupChainName derives the chain name from the group's id, never from the
// name the admin typed: the name is editable (renaming would break the
// chain and leave the old one orphaned) and is free text (a name with a
// space, quote, or `;` would land in an nft argv). 12 hex digits of a UUID
// give ample headroom against collision, and the result matches [a-z0-9_],
// which nft accepts unquoted.
func GroupChainName(id string) string {
	hex := strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			return r
		case r >= 'A' && r <= 'F':
			return r + ('a' - 'A')
		}
		return -1
	}, id)
	if len(hex) > 12 {
		hex = hex[:12]
	}
	if hex == "" {
		hex = "0"
	}
	return GroupChainPrefix + hex
}

// ValidateGroup checks everything that ends up in an nft argv or on screen,
// with the same rigor ValidateRuleFields applies to a rule's fields: a
// group's entry condition is interpolated into an nft command exactly like
// any other.
func ValidateGroup(g StoredGroup) error {
	if strings.TrimSpace(g.Name) == "" {
		return fmt.Errorf("o grupo precisa de um nome")
	}
	if len(g.Name) > 80 {
		return fmt.Errorf("nome muito longo (máx. 80 caracteres)")
	}
	if g.CondIif != "" && !reIface.MatchString(g.CondIif) {
		return fmt.Errorf("interface de entrada inválida")
	}
	if g.CondSaddr != "" && !validIPv4OrCIDR(g.CondSaddr) {
		return fmt.Errorf("origem inválida: use um IP/CIDR IPv4 (IPv6 ainda não é suportado)")
	}
	if g.CondDaddr != "" && !validIPv4OrCIDR(g.CondDaddr) {
		return fmt.Errorf("destino inválido: use um IP/CIDR IPv4 (IPv6 ainda não é suportado)")
	}
	switch g.Fallthrough {
	case FallthroughContinue, FallthroughAccept, FallthroughDrop:
	default:
		return fmt.Errorf("valor inválido para \"e o que sobrar\" (use continue, accept ou drop)")
	}
	// Escopo desconhecido é recusado, e não normalizado para forward: um valor
	// que este código não entende (banco de uma versão futura, linha editada à
	// mão) tratado como forward colocaria na chain de tráfego atravessando um
	// grupo escrito para outra coisa. Vazio continua valendo — é toda linha
	// anterior à Fase C2 — e GroupScope o resolve como forward.
	switch g.Scope {
	case "", ScopeForward, ScopeInput:
	default:
		return fmt.Errorf("escopo inválido (use forward ou input)")
	}
	return nil
}

// groupJumpTokens builds the line that goes in the forward chain: the entry
// condition followed by `counter jump <group chain>`. The field order
// deliberately matches buildRuleTokens — both produce text that is compared
// against nft's own output, and diverging in order would make that
// comparison fail without anything actually being wrong.
//
// The `counter` here is what measures how much traffic actually ENTERED the
// group, and that's the number the panel shows next to the group — not the
// sum of the rules, which would overcount whatever matched more than one
// condition and undercount whatever entered and matched nothing.
func groupJumpTokens(g StoredGroup) ([]string, error) {
	if g.ChainName == "" {
		return nil, fmt.Errorf("grupo %q sem nome de chain", g.ID)
	}
	var t []string
	if g.CondIif != "" {
		if !reIface.MatchString(g.CondIif) {
			return nil, fmt.Errorf("interface de entrada inválida")
		}
		t = append(t, "iifname", g.CondIif)
	}
	if g.CondSaddr != "" {
		if !validIPv4OrCIDR(g.CondSaddr) {
			return nil, fmt.Errorf("origem inválida")
		}
		t = append(t, "ip", "saddr", g.CondSaddr)
	}
	if g.CondDaddr != "" {
		if !validIPv4OrCIDR(g.CondDaddr) {
			return nil, fmt.Errorf("destino inválido")
		}
		t = append(t, "ip", "daddr", g.CondDaddr)
	}
	return append(t, "counter", "jump", g.ChainName), nil
}

// renderGroupChain renders the group chain's content: the enabled rules in
// position order, followed by the "whatever's left over" line when there is
// one. It mirrors renderEnabledUserRules (same ordering, same enabled-only
// filter, same buildRuleTokens, same returning of the skipped ids) so
// validation and reconciliation can never render this differently from one
// another.
//
// "continue evaluating" emits no line at all: in nftables, a jump that
// reaches the end of a chain simply returns and evaluation continues where
// it left off. That's the native behavior, not a special case.
func renderGroupChain(g StoredGroup) (tokenSets [][]string, skipped []string) {
	sorted := make([]StoredRule, len(g.Rules))
	copy(sorted, g.Rules)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Position < sorted[j].Position })

	for _, r := range sorted {
		if !r.Enabled {
			continue
		}
		tokens, err := buildRuleTokens(r.Fields)
		if err != nil {
			skipped = append(skipped, r.ID)
			slog.Warn("regra ignorada ao renderizar a chain do grupo: campos inválidos",
				"grupo", g.ID, "regra", r.ID, "err", err)
			continue
		}
		tokenSets = append(tokenSets, tokens)
	}

	switch g.Fallthrough {
	case FallthroughAccept:
		tokenSets = append(tokenSets, []string{"counter", "accept"})
	case FallthroughDrop:
		tokenSets = append(tokenSets, []string{"counter", "drop"})
	}
	return tokenSets, skipped
}

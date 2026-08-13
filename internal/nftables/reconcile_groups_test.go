package nftables

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// liveTableWithOrphanGroup é saída REAL do `nft list table inet linkguard`
// (aspas em iifname, contadores expandidos em `packets N bytes N`, blocos de
// map/set no meio), não a renderização dos nossos próprios tokens — a
// Restrição Global 1 do plano existe porque em 2026-08-11 um bug crítico
// passou por cinco testes verdes justamente por usar a saída de
// buildRuleTokens como se fosse a do nft.
//
// grp_orfa é o cenário que importa: uma chain de grupo que o admin apagou do
// banco, ainda viva no kernel e ainda COM regras dentro.
const liveTableWithOrphanGroup = `table inet linkguard {
	map host_wan {
		type ipv4_addr : mark
		elements = { 192.168.3.10 : 0x00000064 }
	}

	set blocklist {
		type ipv4_addr
		flags interval
	}

	set blocked_hosts {
		type ipv4_addr
	}

	chain user_rules {
	}

	chain mark_hosts {
		type filter hook prerouting priority mangle; policy accept;
		counter packets 12 bytes 900 meta mark set ip saddr map @host_wan
	}

	chain forward {
		type filter hook forward priority filter; policy accept;
		ip saddr @blocked_hosts counter packets 0 bytes 0 drop
		ip daddr @blocked_hosts counter packets 0 bytes 0 drop
		ip daddr @blocklist counter packets 0 bytes 0 drop
		ip saddr @blocklist counter packets 0 bytes 0 drop
		ip saddr 192.168.50.0/24 counter packets 4 bytes 240 jump grp_aaa
		iifname "enp3s0" counter packets 1 bytes 60 jump grp_orfa
	}

	chain grp_aaa {
		tcp dport 443 counter packets 2 bytes 120 accept
	}

	chain grp_orfa {
		tcp dport 22 counter packets 3 bytes 180 accept
		counter packets 0 bytes 0 drop
	}

	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname { "enp2s0", "enp5s0" } masquerade
	}
}
`

// liveTableAfterReconcile é o mesmo ruleset DEPOIS de uma passada de
// ReconcileGroups com um único grupo (grp_aaa): a órfã não está mais lá e a
// forward já é a reconstruída. É o que a segunda passada de um teste de
// idempotência tem que enxergar — com o fixture estático, ela reveria a
// órfã e reemitiria o mesmo `delete`, e a igualdade entre as duas passadas
// seria satisfeita sem provar convergência nenhuma.
const liveTableAfterReconcile = `table inet linkguard {
	map host_wan {
		type ipv4_addr : mark
		elements = { 192.168.3.10 : 0x00000064 }
	}

	set blocklist {
		type ipv4_addr
		flags interval
	}

	set blocked_hosts {
		type ipv4_addr
	}

	chain user_rules {
	}

	chain mark_hosts {
		type filter hook prerouting priority mangle; policy accept;
		counter packets 12 bytes 900 meta mark set ip saddr map @host_wan
	}

	chain forward {
		type filter hook forward priority filter; policy accept;
		ip saddr @blocked_hosts counter packets 0 bytes 0 drop
		ip daddr @blocked_hosts counter packets 0 bytes 0 drop
		ip daddr @blocklist counter packets 0 bytes 0 drop
		ip saddr @blocklist counter packets 0 bytes 0 drop
		ip saddr 192.168.50.0/24 counter packets 0 bytes 0 jump grp_aaa
	}

	chain grp_aaa {
		tcp dport 443 counter packets 0 bytes 0 accept
		counter packets 0 bytes 0 drop
	}

	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname { "enp2s0", "enp5s0" } masquerade
	}
}
`

// liveTableWithForeignGroupChain: a tabela do LinkGuard com uma chain que
// COMEÇA com grp_ mas não é nossa — `grp_Legado` tem maiúsculas, coisa que
// o nft aceita e que GroupChainName nunca produz. É o que a reconciliação vê
// quando alguém criou uma chain à mão dentro da tabela, ou quando uma linha
// de banco corrompida gerou um nome fora do formato.
const liveTableWithForeignGroupChain = `table inet linkguard {
	chain forward {
		type filter hook forward priority filter; policy accept;
		ip saddr @blocked_hosts counter packets 0 bytes 0 drop
	}

	chain grp_aaa {
		tcp dport 443 counter packets 2 bytes 120 accept
	}

	chain grp_Legado {
		tcp dport 22 counter packets 7 bytes 420 accept
	}
}
`

func forwardLines(groups []StoredGroup) []string {
	var lines []string
	for _, toks := range forwardChainRules(groups) {
		lines = append(lines, strings.Join(toks, " "))
	}
	return lines
}

// forwardAdds extrai, da sequência de comandos executados, só os `add rule`
// da chain forward — na ordem em que foram emitidos, que é a ordem em que o
// nft os avalia.
func forwardAdds(executed []string) []string {
	var out []string
	for _, c := range executed {
		if strings.HasPrefix(c, "nft add rule inet linkguard forward ") {
			out = append(out, c)
		}
	}
	return out
}

func indexOfCommand(executed []string, pred func(string) bool) int {
	for i, c := range executed {
		if pred(c) {
			return i
		}
	}
	return -1
}

// ─── forwardChainRules: uma lista ordenada só ────────────────────────────

// A chain forward deixa de ter ordem fixa em código: ela é a lista do admin,
// na ordem dele. Um bloqueio movido para o fim aparece no fim.
func TestForwardChainFollowsTheSingleOrderedList(t *testing.T) {
	groups := []StoredGroup{
		{ID: "g", Kind: GroupKindAdmin, ChainName: "grp_aaa", Enabled: true, Position: 0,
			CondSaddr: "192.168.50.0/24"},
		{ID: "h", Kind: GroupKindBlockedHosts, Enabled: true, Position: 1},
		{ID: "b", Kind: GroupKindBlocklist, Enabled: true, Position: 2},
	}
	lines := forwardLines(groups)
	want := []string{
		"ip saddr 192.168.50.0/24 counter jump grp_aaa",
		"ip saddr @blocked_hosts counter drop",
		"ip daddr @blocked_hosts counter drop",
		"ip daddr @blocklist counter drop",
		"ip saddr @blocklist counter drop",
	}
	if len(lines) != len(want) {
		t.Fatalf("esperava %d linhas, obtive %d: %v", len(want), len(lines), lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("linha %d:\n  obtive %q\n  queria %q", i, lines[i], want[i])
		}
	}
}

// O padrão da migração: bloqueios primeiro. Continua sendo o que sai quando
// o admin não mexeu em nada.
func TestForwardChainDefaultOrderIsBlocksFirst(t *testing.T) {
	groups := []StoredGroup{
		{ID: "h", Kind: GroupKindBlockedHosts, Enabled: true, Position: 0},
		{ID: "b", Kind: GroupKindBlocklist, Enabled: true, Position: 1},
		{ID: "g", Kind: GroupKindAdmin, ChainName: "grp_aaa", Enabled: true, Position: 2},
	}
	s := renderChainScript(ForwardChain, forwardChainRules(groups))
	idxBlock := strings.Index(s, "@blocked_hosts")
	idxJump := strings.Index(s, "jump grp_aaa")
	if idxBlock < 0 || idxJump < 0 {
		// strings.Index devolve -1 para "não encontrado", e -1 > idx dá falso
		// para qualquer idx >= 0 — sem esta checagem o teste passaria vazio
		// (verde) numa forward sem nenhum @blocked_hosts, exatamente o
		// cenário que ele deveria pegar.
		t.Fatalf("esperava tanto o bloqueio quanto o jump na forward, faltou algum: block=%d jump=%d\n%s", idxBlock, idxJump, s)
	}
	if idxBlock > idxJump {
		t.Errorf("no padrão os bloqueios vêm primeiro:\n%s", s)
	}
}

// Desligar um grupo do sistema tira as linhas dele do firewall; os membros
// do set continuam guardados (o set não é tocado).
func TestForwardChainSkipsDisabledSystemGroup(t *testing.T) {
	groups := []StoredGroup{{ID: "h", Kind: GroupKindBlockedHosts, Enabled: false, Position: 0}}
	if len(forwardChainRules(groups)) != 0 {
		t.Error("grupo do sistema desligado não emite linha nenhuma")
	}
}

// Grupo do sistema não tem chain própria: as linhas dele moram na forward.
// Criar uma chain para ele deixaria uma chain vazia e órfã no ruleset.
func TestReconcileGroupsCreatesNoChainForSystemGroups(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	groups := []StoredGroup{{ID: "h", Kind: GroupKindBlockedHosts, Enabled: true}}
	if err := s.ReconcileGroups(context.Background(), groups); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	for _, cmd := range exec.executed {
		// A chain input é criada de forma idempotente em toda passada desde a
		// Fase C2 (ela pode não existir numa máquina provisionada antes de
		// 2026-08-11) — não é chain de grupo e não é o que este teste guarda.
		if strings.HasPrefix(cmd, "nft add chain") && !strings.Contains(cmd, "hook input") {
			t.Errorf("grupo do sistema não pode ganhar chain: %q", cmd)
		}
	}
}

// ─── forwardChainRules: a inversão da §3 ─────────────────────────────────

// m-6: renomeado de TestForwardChainPutsBlocksBeforeGroupJumps. Aquele nome
// prometia uma garantia estrutural que deixou de existir — desde que os
// bloqueios viraram itens de uma lista como qualquer outro, forwardChainRules
// não "põe" bloqueio antes de jump nenhum: ela segue a POSIÇÃO que a lista
// já trazia. O que este teste de fato prova é que, com a lista que a
// migração cria (grupos do sistema nas posições 0 e 1, antes dos grupos do
// admin), o resultado sai bloqueios-primeiro — é a lista sendo seguida, não
// uma proteção viva contra uma lista que viesse na ordem contrária. Ver
// TestForwardChainFollowsTheSingleOrderedList para a prova de que a ordem é
// mesmo arbitrária (bloqueio movido para o fim aparece no fim).
//
// Até a Fase B a garantia ERA estrutural — bloqueio administrativo avaliado
// antes dos grupos do admin, sempre, em código. A migração preserva esse
// COMPORTAMENTO por escolha de posição (§3 da spec), não por invariante de
// código; é essa distinção que o nome atual tenta deixar impossível de ler
// como proteção.
func TestForwardChainRendersMigrationDefaultOrderBlocksBeforeAdminJumps(t *testing.T) {
	groups := []StoredGroup{
		{ID: "h", Kind: GroupKindBlockedHosts, ChainName: SystemChainBlockedHosts, Enabled: true, Position: 0},
		{ID: "l", Kind: GroupKindBlocklist, ChainName: SystemChainBlocklist, Enabled: true, Position: 1},
		{ID: "a", Kind: GroupKindAdmin, ChainName: "grp_aaa", Enabled: true, Position: 2, CondSaddr: "192.168.50.0/24"},
		{ID: "b", Kind: GroupKindAdmin, ChainName: "grp_bbb", Enabled: true, Position: 3},
	}
	lines := forwardLines(groups)

	firstJump, lastBlock := -1, -1
	for i, l := range lines {
		if strings.Contains(l, "jump grp_") && firstJump < 0 {
			firstJump = i
		}
		if strings.Contains(l, "drop") {
			lastBlock = i
		}
	}
	if firstJump < 0 {
		t.Fatalf("nenhum jump para grupo foi emitido: %v", lines)
	}
	if lastBlock < 0 {
		t.Fatalf("nenhum bloqueio administrativo foi emitido: %v", lines)
	}
	if lastBlock > firstJump {
		t.Fatalf("bloqueio depois do primeiro jump — a ordem da §3 não vale:\n%v", lines)
	}
	if !strings.Contains(lines[firstJump], "ip saddr 192.168.50.0/24") {
		t.Errorf("o jump perdeu a condição do grupo: %q", lines[firstJump])
	}
}

// Os quatro bloqueios continuam existindo, byte a byte na mesma forma que a
// produção já tem desde junho de 2026 — o que mudou foi de onde eles vêm:
// dos dois itens da lista, não mais de um literal no código.
//
// ATUALIZADO: a entrada era `nil`, o que hoje descreveria o comportamento
// errado — sem os grupos do sistema na lista, a forward sai SEM bloqueio
// nenhum (por isso a reconciliação recusa esse caso antes de tocar no nft).
// A entrada passa a ser a lista com os dois grupos do sistema; a expectativa
// sobre as quatro linhas é idêntica.
func TestForwardChainKeepsTheFourAdministrativeBlocks(t *testing.T) {
	lines := forwardLines([]StoredGroup{
		{ID: "h", Kind: GroupKindBlockedHosts, ChainName: SystemChainBlockedHosts, Enabled: true, Position: 0},
		{ID: "l", Kind: GroupKindBlocklist, ChainName: SystemChainBlocklist, Enabled: true, Position: 1},
	})
	want := []string{
		"ip saddr @blocked_hosts counter drop",
		"ip daddr @blocked_hosts counter drop",
		"ip daddr @blocklist counter drop",
		"ip saddr @blocklist counter drop",
	}
	if len(lines) != len(want) {
		t.Fatalf("só com os grupos do sistema a forward deveria ter os 4 bloqueios, tem %d:\n%v", len(lines), lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("linha %d = %q, queria %q", i, lines[i], want[i])
		}
	}
}

// A afirmação central desta tarefa: SEM os grupos do sistema na lista, a
// forward não emite bloqueio administrativo nenhum. Não há mais fallback em
// código — quem impede essa lista de chegar aqui é
// internal/firewallrules.ensureSystemGroupsPresent, e é essa garantia que
// torna aceitável a chain forward ter deixado de ter bloqueio fixo. Sem este
// teste, um fallback fixo reintroduzido aqui (desfazendo o coração da
// mudança) passaria pela suíte inteira sem ser notado — foi exatamente o que
// aconteceu na revisão que pediu este teste (achado m-1).
func TestForwardChainWithoutSystemGroupsEmitsNoBlocks(t *testing.T) {
	groups := []StoredGroup{
		{ID: "a", Kind: GroupKindAdmin, ChainName: "grp_aaa", Enabled: true, Position: 0,
			CondSaddr: "192.168.50.0/24"},
	}
	lines := forwardLines(groups)
	for _, l := range lines {
		if strings.Contains(l, "drop") {
			t.Errorf("sem grupos de sistema na lista, a forward não pode emitir bloqueio nenhum; achei %q em %v", l, lines)
		}
	}
}

// Toda linha da forward carrega `counter`: reconciliar para uma definição
// sem counter zeraria, a cada boot, os contadores que o painel exibe (ver o
// doc-comment de ReconcileStructuralChains).
func TestForwardChainEveryRuleCarriesCounter(t *testing.T) {
	groups := []StoredGroup{{ID: "a", ChainName: "grp_aaa", Enabled: true, CondSaddr: "192.168.50.0/24"}}
	for _, l := range forwardLines(groups) {
		if !strings.Contains(l, "counter") {
			t.Errorf("linha da forward sem counter: %q", l)
		}
	}
}

func TestForwardChainSkipsDisabledGroups(t *testing.T) {
	groups := []StoredGroup{
		{ID: "a", ChainName: "grp_aaa", Enabled: false, Position: 0},
		{ID: "b", ChainName: "grp_bbb", Enabled: true, Position: 1},
	}
	joined := renderChainScript(ForwardChain, forwardChainRules(groups))
	if strings.Contains(joined, "grp_aaa") {
		t.Error("grupo desligado não pode ter jump na forward")
	}
	if !strings.Contains(joined, "grp_bbb") {
		t.Error("grupo ligado precisa ter jump na forward")
	}
}

func TestForwardChainRespectsGroupOrder(t *testing.T) {
	groups := []StoredGroup{
		{ID: "b", ChainName: "grp_bbb", Enabled: true, Position: 5},
		{ID: "a", ChainName: "grp_aaa", Enabled: true, Position: 1},
	}
	s := renderChainScript(ForwardChain, forwardChainRules(groups))
	if strings.Index(s, "grp_aaa") > strings.Index(s, "grp_bbb") {
		t.Errorf("ordem dos jumps não seguiu Position:\n%s", s)
	}
}

// Um grupo com condição inválida (linha de banco velha ou editada à mão) é
// pulado: ele não pode nem virar argv do nft nem derrubar os outros grupos.
func TestForwardChainSkipsGroupWithInvalidCondition(t *testing.T) {
	groups := []StoredGroup{
		{ID: "a", ChainName: "grp_aaa", Enabled: true, Position: 0, CondSaddr: "1.2.3.4; flush ruleset"},
		{ID: "b", ChainName: "grp_bbb", Enabled: true, Position: 1},
	}
	joined := renderChainScript(ForwardChain, forwardChainRules(groups))
	if strings.Contains(joined, "flush ruleset") || strings.Contains(joined, "grp_aaa") {
		t.Errorf("condição inválida chegou na forward:\n%s", joined)
	}
	if !strings.Contains(joined, "grp_bbb") {
		t.Errorf("o grupo válido tinha que continuar valendo:\n%s", joined)
	}
}

// O nome da chain vem do banco e é interpolado no argv do nft — que junta os
// argumentos e parseia o resultado. Um nome fora de grp_[a-z0-9_] nunca pode
// chegar lá (mesma disciplina de sanitizeInterfaces/ValidMark).
func TestForwardChainRejectsUnsafeChainName(t *testing.T) {
	groups := []StoredGroup{
		{ID: "a", ChainName: "grp_aaa; flush ruleset", Enabled: true, Position: 0},
		{ID: "b", ChainName: "", Enabled: true, Position: 1},
		{ID: "c", ChainName: "user_rules", Enabled: true, Position: 2},
		{ID: "d", ChainName: "grp_ddd", Enabled: true, Position: 3},
	}
	joined := renderChainScript(ForwardChain, forwardChainRules(groups))
	for _, forbidden := range []string{"flush ruleset", "jump user_rules"} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("nome de chain inseguro chegou na forward (%q):\n%s", forbidden, joined)
		}
	}
	if !strings.Contains(joined, "jump grp_ddd") {
		t.Errorf("o grupo com nome de chain válido tinha que continuar valendo:\n%s", joined)
	}
}

// ─── ReconcileGroups ─────────────────────────────────────────────────────

// A regra de segurança do projeto, replicada de ReconcileMasquerade: nunca
// dar flush em ruleset nem em tabela, só nos chains próprios.
func TestReconcileGroupsNeverFlushesRulesetOrTable(t *testing.T) {
	exec := &fakeReconcileExec{readOut: map[string]string{
		"nft list table inet linkguard": liveTableWithOrphanGroup,
	}}
	s := &Service{exec: exec}
	groups := []StoredGroup{{ID: "a", Name: "Wi-Fi", ChainName: "grp_aaa", Enabled: true,
		Fallthrough: FallthroughContinue,
		Rules: []StoredRule{{ID: "r", Enabled: true,
			Fields: RuleFields{Action: "accept", Proto: "tcp", Dport: "22"}}}}}

	if err := s.ReconcileGroups(context.Background(), groups); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	for _, joined := range exec.executed {
		if strings.Contains(joined, "flush ruleset") {
			t.Fatalf("deu flush no ruleset inteiro: %q", joined)
		}
		if strings.Contains(joined, "flush table") {
			t.Fatalf("deu flush na tabela: %q", joined)
		}
		if strings.HasPrefix(joined, "nft flush chain") &&
			!strings.Contains(joined, ForwardChain) && !strings.Contains(joined, GroupChainPrefix) &&
			!strings.HasSuffix(joined, " "+InputChain) {
			// A input entra na lista permitida desde a Fase C2: ela também é
			// reconstruída aqui, pelo renderizador único. Continua sendo flush
			// de CHAIN — nunca de tabela nem de ruleset.
			t.Fatalf("deu flush numa chain que não é dos grupos, nem a forward, nem a input: %q", joined)
		}
	}
}

// A chain do grupo tem que existir antes de a forward pular para ela, e a
// chain órfã só pode ser apagada depois de a forward parar de referenciá-la
// — o nft recusa apagar chain ainda referenciada.
func TestReconcileGroupsOrdersCreateBeforeJumpAndDeleteAfter(t *testing.T) {
	exec := &fakeReconcileExec{readOut: map[string]string{
		"nft list table inet linkguard": liveTableWithOrphanGroup,
	}}
	s := &Service{exec: exec}
	groups := []StoredGroup{{ID: "a", Name: "Wi-Fi", ChainName: "grp_aaa", Enabled: true,
		Fallthrough: FallthroughContinue}}

	if err := s.ReconcileGroups(context.Background(), groups); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}

	idxAdd := indexOfCommand(exec.executed, func(c string) bool {
		return strings.HasPrefix(c, "nft add chain") && strings.Contains(c, "grp_aaa")
	})
	idxJump := indexOfCommand(exec.executed, func(c string) bool {
		return strings.Contains(c, "jump grp_aaa")
	})
	idxDel := indexOfCommand(exec.executed, func(c string) bool {
		return strings.HasPrefix(c, "nft delete chain") && strings.Contains(c, "grp_orfa")
	})

	if idxAdd < 0 || idxJump < 0 {
		t.Fatalf("faltou criar a chain ou emitir o jump: %v", exec.executed)
	}
	if idxAdd > idxJump {
		t.Error("a chain do grupo precisa existir ANTES de a forward pular para ela")
	}
	if idxDel < 0 {
		t.Fatalf("chain órfã não foi removida: %v", exec.executed)
	}
	if idxDel < idxJump {
		t.Error("chain órfã removida antes de a forward ser reconstruída — o nft recusaria")
	}
}

// A chain órfã é apagada DIRETO, sem esvaziar antes.
//
// A premissa contrária ("o nft recusa apagar chain que ainda tem regra
// dentro") era falsa e estava virando invariante de teste: verificado ao
// vivo no nft da produção (Debian 13), `delete chain` numa chain COM regras
// funciona normalmente. A única restrição real é referência — um `jump`
// apontando para ela dá "Device or resource busy" —, e disso quem cuida é a
// ordem dos passos 3/4.
//
// O flush não era só inútil: ele criava um estado que o delete sozinho não
// cria. Se o delete falha (qualquer referência que a reconciliação não
// conheça), a chain sobrevive VAZIA — e um grupo que terminava em `drop`
// deixa de bloquear. Sem o flush, ou a chain some inteira ou nada muda; a
// pior consequência de um delete que falha vira uma chain órfã inalcançável
// no ruleset, não um bloqueio que sumiu.
func TestReconcileGroupsDeletesOrphanChainWithoutEmptyingItFirst(t *testing.T) {
	exec := &fakeReconcileExec{readOut: map[string]string{
		"nft list table inet linkguard": liveTableWithOrphanGroup,
	}}
	s := &Service{exec: exec}
	groups := []StoredGroup{{ID: "a", Name: "Wi-Fi", ChainName: "grp_aaa", Enabled: true,
		Fallthrough: FallthroughContinue}}

	if err := s.ReconcileGroups(context.Background(), groups); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if !ranCommand(exec.executed, "nft delete chain inet linkguard grp_orfa") {
		t.Fatalf("chain órfã não foi removida: %v", exec.executed)
	}
	if ranCommand(exec.executed, "nft flush chain inet linkguard grp_orfa") {
		t.Errorf("esvaziou a chain órfã antes de apagá-la: se o delete falhar, ela sobrevive vazia e o grupo para de bloquear: %v", exec.executed)
	}
}

// captureLogs troca o logger padrão por um que escreve num buffer, pelo
// tempo do teste. É o único jeito de assertar o nível de um slog — e aqui o
// NÍVEL é o comportamento sob teste: apagar todos os grupos do firewall de
// uma vez não pode passar como slog.Info no meio do boot.
func captureLogs(t *testing.T) *strings.Builder {
	t.Helper()
	var buf strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// ReconcileGroups(ctx, nil) esvazia a forward (desde que ela virou uma lista
// ordenada só, os bloqueios também são itens dela e vão junto) e apaga TODAS
// as chains de grupo. É o que uma lista vazia literalmente pede — e é
// indistinguível, aqui dentro, de um chamador que engoliu o
// erro de ListFirewallGroups e passou lista vazia. Enquanto o contrato do
// chamador é o que evita o segundo caso (ver o doc-comment de
// ReconcileGroups), apagar todos os grupos do firewall merece mais que um
// slog.Info perdido no boot.
func TestReconcileGroupsWarnsBeforeDeletingEveryGroupChain(t *testing.T) {
	logs := captureLogs(t)
	exec := &fakeReconcileExec{readOut: map[string]string{
		"nft list table inet linkguard": liveTableWithOrphanGroup,
	}}
	s := &Service{exec: exec}

	if err := s.ReconcileGroups(context.Background(), nil); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	warn := warnLineMentioning(logs.String(), GroupChainPrefix)
	if warn == "" {
		t.Fatalf("apagar TODAS as chains de grupo tem que ser um aviso, não um info:\n%s", logs.String())
	}
	for _, want := range []string{"grp_aaa", "grp_orfa"} {
		if !strings.Contains(warn, want) {
			t.Errorf("o aviso tem que nomear as chains que vão embora (%q): %s", want, warn)
		}
	}
}

// warnLineMentioning devolve a primeira linha de log em nível WARN que cita
// substr — olhar o buffer inteiro confundiria o aviso sob teste com o warn
// de Persist, que sai em todo teste deste pacote (sem permissão para
// escrever /etc/nftables.conf).
func warnLineMentioning(logs, substr string) string {
	for _, l := range strings.Split(logs, "\n") {
		if strings.Contains(l, "level=WARN") && strings.Contains(l, substr) {
			return l
		}
	}
	return ""
}

// errorLineMentioning é warnLineMentioning para nível ERROR — usado pelo
// alarme do m-5 (ReconcileGroups reclamando de uma forward sem bloqueio
// nenhum).
func errorLineMentioning(logs, substr string) string {
	for _, l := range strings.Split(logs, "\n") {
		if strings.Contains(l, "level=ERROR") && strings.Contains(l, substr) {
			return l
		}
	}
	return ""
}

// m-5: a invariante "a forward nunca fica sem bloqueio" mora uma camada
// acima (firewallrules.ensureSystemGroupsPresent) — ReconcileGroups não se
// defende sozinha, e hoje não há chamador que escape dessa defesa. Mas
// ReconcileGroups é exportada, e um chamador futuro que não passe por ali
// ficaria sem aviso nenhum: o único slog hoje ("nenhum grupo veio do banco")
// não cobre "veio uma lista, mas sem nenhum grupo de sistema dentro". Este
// teste chama ReconcileGroups diretamente — contornando a defesa de
// propósito, como faria esse chamador futuro — e confirma que o alarme
// dispara.
func TestReconcileGroupsLogsErrorWhenForwardEndsUpWithoutAnyBlock(t *testing.T) {
	logs := captureLogs(t)
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	groups := []StoredGroup{
		{ID: "a", Name: "Visitantes", ChainName: "grp_aaa", Kind: GroupKindAdmin, Enabled: true, Position: 0,
			Fallthrough: FallthroughContinue},
	}

	if err := s.ReconcileGroups(context.Background(), groups); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if errorLineMentioning(logs.String(), "nenhum bloqueio administrativo") == "" {
		t.Fatalf("esperava um slog.Error alertando que a forward ficou sem bloqueio nenhum:\n%s", logs.String())
	}
}

// E o alarme não pode disparar no caso normal — lista com os dois grupos do
// sistema —, senão vira ruído em todo boot de toda máquina em produção.
func TestReconcileGroupsDoesNotLogTheNoBlockAlarmWhenSystemGroupsArePresent(t *testing.T) {
	logs := captureLogs(t)
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	groups := []StoredGroup{
		{ID: "h", Name: "Hosts bloqueados", ChainName: SystemChainBlockedHosts,
			Kind: GroupKindBlockedHosts, Enabled: true, Position: 0, Fallthrough: FallthroughContinue},
		{ID: "l", Name: "Destinos bloqueados", ChainName: SystemChainBlocklist,
			Kind: GroupKindBlocklist, Enabled: true, Position: 1, Fallthrough: FallthroughContinue},
	}

	if err := s.ReconcileGroups(context.Background(), groups); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if warn := errorLineMentioning(logs.String(), "nenhum bloqueio administrativo"); warn != "" {
		t.Errorf("o caso normal (grupos do sistema presentes) não pode disparar o alarme: %s", warn)
	}
}

// M-6 da revisão final: desligar os dois bloqueios é uma decisão que a spec
// §2.1 permite — o botão existe, e desligar é como se testa uma regra sem
// perder a lista de membros. Um grupo desligado não emite linha nenhuma
// (forwardChainRules pula), então a forward fica sem drop nenhum e o alarme
// disparava um slog.Error a cada reconciliação numa máquina em perfeito
// estado, feita exatamente do jeito que o admin pediu. Alarme sem condição
// de erro é alarme que ninguém lê — e este alerta é sobre firewall sem
// bloqueio, que é a última coisa que pode virar ruído.
func TestReconcileGroupsDoesNotLogTheNoBlockAlarmWhenTheAdminTurnedBothBlocksOff(t *testing.T) {
	logs := captureLogs(t)
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	groups := []StoredGroup{
		{ID: "h", Name: "Hosts bloqueados", ChainName: SystemChainBlockedHosts,
			Kind: GroupKindBlockedHosts, Enabled: false, Position: 0, Fallthrough: FallthroughContinue},
		{ID: "l", Name: "Destinos bloqueados", ChainName: SystemChainBlocklist,
			Kind: GroupKindBlocklist, Enabled: false, Position: 1, Fallthrough: FallthroughContinue},
	}

	if err := s.ReconcileGroups(context.Background(), groups); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if warn := errorLineMentioning(logs.String(), "nenhum bloqueio administrativo"); warn != "" {
		t.Errorf("o admin desligou os dois bloqueios de propósito; isso não é erro: %s", warn)
	}
}

// E o alarme continua pegando o meio-termo: um grupo do sistema veio na
// lista e o outro não. É o contorno da defesa (ensureSystemGroupsPresent
// exige os dois), e não uma escolha que o painel permita fazer.
func TestReconcileGroupsLogsTheAlarmWhenOnlyOneSystemGroupIsInTheList(t *testing.T) {
	logs := captureLogs(t)
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	groups := []StoredGroup{
		{ID: "h", Name: "Hosts bloqueados", ChainName: SystemChainBlockedHosts,
			Kind: GroupKindBlockedHosts, Enabled: false, Position: 0, Fallthrough: FallthroughContinue},
	}

	if err := s.ReconcileGroups(context.Background(), groups); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	line := errorLineMentioning(logs.String(), "nenhum bloqueio administrativo")
	if line == "" {
		t.Fatalf("faltando um grupo do sistema, o alarme tem que disparar:\n%s", logs.String())
	}
	if !strings.Contains(line, GroupKindBlocklist) {
		t.Errorf("o alarme tem que nomear o kind ausente: %s", line)
	}
}

// E o aviso é só para o caso "zero grupos": uma remoção de órfã normal, com
// grupos vivos, não pode ficar avisando a cada apply — aviso que aparece
// sempre é aviso que ninguém lê.
func TestReconcileGroupsDoesNotWarnWhenThereAreStillGroups(t *testing.T) {
	logs := captureLogs(t)
	exec := &fakeReconcileExec{readOut: map[string]string{
		"nft list table inet linkguard": liveTableWithOrphanGroup,
	}}
	s := &Service{exec: exec}
	groups := []StoredGroup{{ID: "a", Name: "Wi-Fi", ChainName: "grp_aaa", Enabled: true,
		Fallthrough: FallthroughContinue}}

	if err := s.ReconcileGroups(context.Background(), groups); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if warn := warnLineMentioning(logs.String(), GroupChainPrefix); warn != "" {
		t.Errorf("remoção de órfã com grupos vivos não é motivo de aviso: %s", warn)
	}
}

// Chain que não é de grupo jamais é candidata a remoção, por mais que esteja
// sobrando: user_rules, forward, mark_hosts, postrouting e qualquer chain de
// terceiros continuam onde estão.
func TestReconcileGroupsOnlyEverDeletesGroupChains(t *testing.T) {
	exec := &fakeReconcileExec{readOut: map[string]string{
		"nft list table inet linkguard": liveTableWithOrphanGroup,
	}}
	s := &Service{exec: exec}

	if err := s.ReconcileGroups(context.Background(), nil); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	for _, c := range exec.executed {
		if !strings.HasPrefix(c, "nft delete chain") {
			continue
		}
		if !strings.Contains(c, " "+GroupChainPrefix) {
			t.Errorf("apagou uma chain que não é de grupo: %q", c)
		}
	}
	// Com zero grupos, as duas chains grp_ vivas viraram órfãs.
	for _, want := range []string{
		"nft delete chain inet linkguard grp_aaa",
		"nft delete chain inet linkguard grp_orfa",
	} {
		if !ranCommand(exec.executed, want) {
			t.Errorf("faltou %q; rodou: %v", want, exec.executed)
		}
	}
}

// Uma chain que começa com grp_ mas não tem o formato que GroupChainName
// produz não é nossa e não é apagada: o nome vem de texto parseado do nft e
// vira argv de um `nft delete chain` — a mesma disciplina que impede um nome
// de chain vindo do banco de chegar ao nft. Uma chain que alguém criou à mão
// dentro da tabela sobrevive; a órfã de verdade continua sendo removida.
func TestReconcileGroupsNeverDeletesAChainNameItCouldNotHaveCreated(t *testing.T) {
	exec := &fakeReconcileExec{readOut: map[string]string{
		"nft list table inet linkguard": liveTableWithForeignGroupChain,
	}}
	s := &Service{exec: exec}

	if err := s.ReconcileGroups(context.Background(), nil); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if ranCommand(exec.executed, "nft delete chain inet linkguard grp_Legado") {
		t.Errorf("apagou uma chain grp_ que este código nunca poderia ter criado: %v", exec.executed)
	}
	if !ranCommand(exec.executed, "nft delete chain inet linkguard grp_aaa") {
		t.Errorf("a órfã de verdade tinha que ter sido removida: %v", exec.executed)
	}
}

// Desligar um grupo tira o jump da forward mas mantém a chain e as regras
// dentro dela (spec §2.1/§10): religar não pode depender de nada ter sido
// preservado fora do nft, e a chain desligada não é órfã.
func TestReconcileGroupsKeepsDisabledGroupChainWithItsRules(t *testing.T) {
	exec := &fakeReconcileExec{readOut: map[string]string{
		"nft list table inet linkguard": liveTableWithOrphanGroup,
	}}
	s := &Service{exec: exec}
	groups := []StoredGroup{{ID: "a", Name: "Wi-Fi", ChainName: "grp_aaa", Enabled: false,
		Fallthrough: FallthroughDrop,
		Rules: []StoredRule{{ID: "r", Enabled: true,
			Fields: RuleFields{Action: "accept", Proto: "tcp", Dport: "443"}}}}}

	if err := s.ReconcileGroups(context.Background(), groups); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	want := "nft add rule inet linkguard grp_aaa tcp dport 443 counter accept"
	if !ranCommand(exec.executed, want) {
		t.Errorf("a regra do grupo desligado tinha que continuar na chain; faltou %q em %v", want, exec.executed)
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "jump grp_aaa") {
			t.Errorf("grupo desligado não pode ter jump na forward: %q", c)
		}
		if strings.HasPrefix(c, "nft delete chain") && strings.Contains(c, "grp_aaa") {
			t.Errorf("chain de grupo desligado não é órfã e não pode ser apagada: %q", c)
		}
	}
}

// A ordem de avaliação vista de ponta a ponta, na sequência real de comandos
// (não só na função pura): a lista do admin na ordem dele — aqui, a ordem
// padrão da migração, com os dois grupos do sistema antes dos jumps.
func TestReconcileGroupsForwardCommandOrder(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	// ATUALIZADO: os dois grupos do sistema entram na lista (posições 0 e 1,
	// como a migração os cria). Sem eles a forward sairia sem os quatro
	// bloqueios — não porque a reconciliação os perdeu, mas porque eles
	// deixaram de ser literais no código e passaram a ser itens desta lista.
	groups := []StoredGroup{
		{ID: "b", Name: "Servidores", ChainName: "grp_bbb", Kind: GroupKindAdmin, Enabled: true, Position: 5,
			CondSaddr: "192.168.3.10", Fallthrough: FallthroughContinue},
		{ID: "a", Name: "Visitantes", ChainName: "grp_aaa", Kind: GroupKindAdmin, Enabled: true, Position: 2,
			CondSaddr: "192.168.50.0/24", Fallthrough: FallthroughDrop},
		{ID: "h", Name: "Hosts bloqueados", ChainName: SystemChainBlockedHosts,
			Kind: GroupKindBlockedHosts, Enabled: true, Position: 0, Fallthrough: FallthroughContinue},
		{ID: "l", Name: "Destinos bloqueados", ChainName: SystemChainBlocklist,
			Kind: GroupKindBlocklist, Enabled: true, Position: 1, Fallthrough: FallthroughContinue},
	}

	if err := s.ReconcileGroups(context.Background(), groups); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	adds := forwardAdds(exec.executed)
	want := []string{
		"nft add rule inet linkguard forward ip saddr @blocked_hosts counter drop",
		"nft add rule inet linkguard forward ip daddr @blocked_hosts counter drop",
		"nft add rule inet linkguard forward ip daddr @blocklist counter drop",
		"nft add rule inet linkguard forward ip saddr @blocklist counter drop",
		"nft add rule inet linkguard forward ip saddr 192.168.50.0/24 counter jump grp_aaa",
		"nft add rule inet linkguard forward ip saddr 192.168.3.10 counter jump grp_bbb",
	}
	if len(adds) != len(want) {
		t.Fatalf("esperava %d regras na forward, vieram %d:\n%v", len(want), len(adds), adds)
	}
	for i := range want {
		if adds[i] != want[i] {
			t.Errorf("regra %d da forward = %q, queria %q", i, adds[i], want[i])
		}
	}
	// E o flush da forward vem antes de tudo isso, senão apagaria o que
	// acabou de ser escrito.
	idxFlush := indexOfCommand(exec.executed, func(c string) bool {
		return c == "nft flush chain inet linkguard forward"
	})
	idxFirstAdd := indexOfCommand(exec.executed, func(c string) bool {
		return strings.HasPrefix(c, "nft add rule inet linkguard forward ")
	})
	if idxFlush < 0 || idxFlush > idxFirstAdd {
		t.Errorf("a forward tem que ser esvaziada antes de receber as regras: %v", exec.executed)
	}
}

// O conteúdo do grupo: regras ativadas em ordem de posição, e o "e o que
// sobrar" como última linha.
func TestReconcileGroupsRendersGroupChainContent(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	groups := []StoredGroup{{ID: "a", Name: "Visitantes", ChainName: "grp_aaa", Enabled: true,
		Fallthrough: FallthroughDrop,
		Rules: []StoredRule{
			{ID: "r2", Position: 2, Enabled: true, Fields: RuleFields{Action: "accept", Proto: "udp", Dport: "53"}},
			{ID: "r1", Position: 1, Enabled: true, Fields: RuleFields{Action: "accept", Proto: "tcp", Dport: "443"}},
			{ID: "r3", Position: 3, Enabled: false, Fields: RuleFields{Action: "accept", Proto: "tcp", Dport: "8080"}},
		}}}

	if err := s.ReconcileGroups(context.Background(), groups); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	var adds []string
	for _, c := range exec.executed {
		if strings.HasPrefix(c, "nft add rule inet linkguard grp_aaa ") {
			adds = append(adds, c)
		}
	}
	want := []string{
		"nft add rule inet linkguard grp_aaa tcp dport 443 counter accept",
		"nft add rule inet linkguard grp_aaa udp dport 53 counter accept",
		"nft add rule inet linkguard grp_aaa counter drop",
	}
	if len(adds) != len(want) {
		t.Fatalf("esperava %d regras na chain do grupo, vieram %d:\n%v", len(want), len(adds), adds)
	}
	for i := range want {
		if adds[i] != want[i] {
			t.Errorf("regra %d do grupo = %q, queria %q", i, adds[i], want[i])
		}
	}
}

// Spec §8, "falha por regra é contida": o nft recusar UMA regra de UM grupo
// não pode impedir a forward de ser reconstruída — se impedisse, os jumps de
// todos os outros grupos sumiriam do firewall por causa de uma regra ruim, e
// o admin veria os grupos dele deixarem de valer sem nenhuma mudança sua.
// O erro tem que chegar ao chamador (apply não-ok), mas depois de o resto
// estar aplicado.
func TestReconcileGroupsStillRebuildsForwardWhenNftRejectsARule(t *testing.T) {
	exec := &fakeReconcileExec{
		failOn: func(cmd string) error {
			if strings.Contains(cmd, "grp_aaa tcp dport 443") {
				return errors.New("nft: Error: could not process rule")
			}
			return nil
		},
	}
	s := &Service{exec: exec}
	// ATUALIZADO: o grupo do sistema entra na lista, porque a linha
	// @blocked_hosts que este teste exige na forward agora vem dele.
	groups := []StoredGroup{
		{ID: "h", Name: "Hosts bloqueados", ChainName: SystemChainBlockedHosts,
			Kind: GroupKindBlockedHosts, Enabled: true, Position: 0, Fallthrough: FallthroughContinue},
		{ID: "a", Name: "Visitantes", ChainName: "grp_aaa", Kind: GroupKindAdmin, Enabled: true, Position: 1,
			Fallthrough: FallthroughContinue,
			Rules: []StoredRule{{ID: "r1", Enabled: true,
				Fields: RuleFields{Action: "accept", Proto: "tcp", Dport: "443"}}}},
		{ID: "b", Name: "Servidores", ChainName: "grp_bbb", Kind: GroupKindAdmin, Enabled: true, Position: 2,
			Fallthrough: FallthroughContinue,
			Rules: []StoredRule{{ID: "r2", Enabled: true,
				Fields: RuleFields{Action: "accept", Proto: "tcp", Dport: "22"}}}},
	}

	err := s.ReconcileGroups(context.Background(), groups)
	if err == nil {
		t.Fatal("uma regra recusada pelo nft tem que virar erro para o chamador (apply não-ok)")
	}
	if !strings.Contains(err.Error(), "could not process rule") {
		t.Errorf("o erro tinha que carregar a mensagem do próprio nft, veio %q", err.Error())
	}
	if !ranCommand(exec.executed, "nft add rule inet linkguard grp_bbb tcp dport 22 counter accept") {
		t.Errorf("o outro grupo parou de ser aplicado por causa da regra ruim: %v", exec.executed)
	}
	for _, want := range []string{
		"nft add rule inet linkguard forward ip saddr @blocked_hosts counter drop",
		"nft add rule inet linkguard forward counter jump grp_aaa",
		"nft add rule inet linkguard forward counter jump grp_bbb",
	} {
		if !ranCommand(exec.executed, want) {
			t.Errorf("a forward não foi reconstruída depois da regra recusada; faltou %q em %v", want, exec.executed)
		}
	}
}

// Uma regra ativada que nem chega a renderizar (linha de banco velha) sai do
// firewall em silêncio se ninguém contar: ReconcileGroups devolve
// SkippedRulesError nomeando as regras, como ReconcileUserRules já faz, para
// o painel poder dizer QUAL regra não está valendo (I-8).
func TestReconcileGroupsReportsRulesItCouldNotRender(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	groups := []StoredGroup{{ID: "a", Name: "Visitantes", ChainName: "grp_aaa", Enabled: true,
		Fallthrough: FallthroughContinue,
		Rules: []StoredRule{
			{ID: "boa", Position: 0, Enabled: true, Fields: RuleFields{Action: "accept", Proto: "tcp", Dport: "443"}},
			{ID: "ruim", Position: 1, Enabled: true, Fields: RuleFields{Action: "accept", Proto: "tcp", Dport: "80; flush ruleset"}},
		}}}

	err := s.ReconcileGroups(context.Background(), groups)
	var skipped *SkippedRulesError
	if !errors.As(err, &skipped) {
		t.Fatalf("esperava um SkippedRulesError nomeando a regra fora do firewall, obtive %v", err)
	}
	if len(skipped.IDs) != 1 || skipped.IDs[0] != "ruim" {
		t.Errorf("esperava a regra %q identificada, veio %v", "ruim", skipped.IDs)
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "flush ruleset") {
			t.Fatalf("a regra inválida chegou ao nft: %q", c)
		}
	}
	if !ranCommand(exec.executed, "nft add rule inet linkguard grp_aaa tcp dport 443 counter accept") {
		t.Errorf("a regra boa do mesmo grupo tinha que continuar valendo: %v", exec.executed)
	}
}

// Se a forward NÃO pôde ser reconstruída, a forward antiga continua viva —
// e ela ainda tem o `jump grp_orfa`. O `delete` da órfã falharia com EBUSY
// (o nft recusa apagar chain referenciada), mas o `flush` que vem antes
// FUNCIONA: o nft aceita esvaziar chain referenciada. O resultado seria uma
// forward antiga ainda pulando para uma grp_orfa recém-esvaziada — se aquele
// grupo terminava em `drop`, o tráfego que morria ali passa a passar. É
// fail-open num firewall, e por isso o passo 4 só roda se o passo 3 deu
// certo.
func TestReconcileGroupsDoesNotTouchOrphansWhenTheForwardRebuildFails(t *testing.T) {
	exec := &fakeReconcileExec{
		readOut: map[string]string{"nft list table inet linkguard": liveTableWithOrphanGroup},
		failOn: func(cmd string) error {
			if cmd == "nft flush chain inet linkguard forward" {
				return errors.New("nft: Error: Could not process rule: Device or resource busy")
			}
			return nil
		},
	}
	s := &Service{exec: exec}
	groups := []StoredGroup{{ID: "a", Name: "Visitantes", ChainName: "grp_aaa", Enabled: true,
		Fallthrough: FallthroughContinue}}

	err := s.ReconcileGroups(context.Background(), groups)
	if err == nil {
		t.Fatal("a forward não reconstruída tem que virar apply não-ok")
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "grp_orfa") {
			t.Errorf("mexeu na chain órfã com a forward antiga ainda pulando para ela (%q): %v", c, exec.executed)
		}
	}
}

// Os dois problemas podem acontecer na mesma passada: uma regra que nem
// renderiza (linha de banco velha) e outra que o nft recusa. O chamador
// precisa dos DOIS — internal/firewallrules.Service.Reconcile faz
// errors.As(applyErr, &skipped) justamente para nomear no banner as regras
// que ficaram de fora, e se o erro das failures mascarar o
// SkippedRulesError esses ids nunca chegam à tela, só ao journal.
func TestReconcileGroupsReportsSkippedRulesEvenWhenNftAlsoRejectedOne(t *testing.T) {
	exec := &fakeReconcileExec{failOn: func(cmd string) error {
		if strings.Contains(cmd, "grp_aaa tcp dport 443") {
			return errors.New("nft: Error: could not process rule")
		}
		return nil
	}}
	s := &Service{exec: exec}
	groups := []StoredGroup{{ID: "a", Name: "Visitantes", ChainName: "grp_aaa", Enabled: true,
		Fallthrough: FallthroughContinue,
		Rules: []StoredRule{
			{ID: "recusada-pelo-nft", Position: 0, Enabled: true,
				Fields: RuleFields{Action: "accept", Proto: "tcp", Dport: "443"}},
			{ID: "nao-renderiza", Position: 1, Enabled: true,
				Fields: RuleFields{Action: "accept", Proto: "tcp", Dport: "80; flush ruleset"}},
		}}}

	err := s.ReconcileGroups(context.Background(), groups)
	if err == nil {
		t.Fatal("esperava erro: o nft recusou uma regra e outra nem renderizou")
	}
	var skipped *SkippedRulesError
	if !errors.As(err, &skipped) {
		t.Fatalf("o erro das failures engoliu o SkippedRulesError; o banner nunca saberia QUAL regra ficou de fora: %v", err)
	}
	if len(skipped.IDs) != 1 || skipped.IDs[0] != "nao-renderiza" {
		t.Errorf("esperava a regra %q identificada, veio %v", "nao-renderiza", skipped.IDs)
	}
	if !strings.Contains(err.Error(), "could not process rule") {
		t.Errorf("a recusa do próprio nft tinha que continuar na mensagem, veio %q", err.Error())
	}
	if !strings.Contains(err.Error(), "nao-renderiza") {
		t.Errorf("a mensagem agregada tem que nomear a regra pulada, veio %q", err.Error())
	}
	if strings.Contains(err.Error(), "\n") {
		t.Errorf("a mensagem vai para um banner de uma linha, veio multilinha: %q", err.Error())
	}
}

// Não conseguir listar as chains vivas é motivo para não limpar órfã nenhuma
// — nunca para desfazer o que já foi aplicado, e nunca para chutar um
// `delete` às cegas.
func TestReconcileGroupsSurvivesAFailingChainListing(t *testing.T) {
	exec := &fakeReconcileExec{readErr: errors.New("nft: command not found")}
	s := &Service{exec: exec}
	groups := []StoredGroup{{ID: "a", Name: "Visitantes", ChainName: "grp_aaa", Enabled: true,
		Fallthrough: FallthroughContinue}}

	if err := s.ReconcileGroups(context.Background(), groups); err != nil {
		t.Fatalf("listagem falha não pode derrubar a reconciliação: %v", err)
	}
	for _, c := range exec.executed {
		if strings.HasPrefix(c, "nft delete chain") {
			t.Errorf("apagou chain sem saber o que está vivo: %q", c)
		}
	}
	if !ranCommand(exec.executed, "nft add rule inet linkguard forward counter jump grp_aaa") {
		t.Errorf("a forward tinha que ter sido reconstruída mesmo assim: %v", exec.executed)
	}
}

// Nome de chain inseguro vindo do banco não pode virar argv do nft — o nft
// junta os argumentos e parseia o resultado, então `grp_x; flush ruleset`
// seria injeção de comando, exatamente o que reIface/ValidMark já barram nos
// outros geradores deste pacote.
func TestReconcileGroupsRefusesUnsafeChainName(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	groups := []StoredGroup{
		{ID: "mau", Name: "Injetado", ChainName: "grp_x; flush ruleset", Enabled: true, Position: 0,
			Fallthrough: FallthroughContinue},
		{ID: "bom", Name: "Visitantes", ChainName: "grp_bbb", Enabled: true, Position: 1,
			Fallthrough: FallthroughContinue},
	}

	if err := s.ReconcileGroups(context.Background(), groups); err == nil {
		t.Error("um grupo que não pôde ser aplicado tem que virar apply não-ok")
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "flush ruleset") {
			t.Fatalf("nome de chain inseguro chegou ao nft: %q", c)
		}
	}
	if !ranCommand(exec.executed, "nft add rule inet linkguard forward counter jump grp_bbb") {
		t.Errorf("o grupo válido tinha que continuar valendo: %v", exec.executed)
	}
}

// Um grupo ATIVADO cuja condição de entrada não valida (linha de banco
// antiga ou editada à mão) não recebe jump: ele existe, aparece ativado no
// painel, a chain dele é criada e preenchida — e nenhum pacote passa por
// lá. Um "Wi-Fi visitantes" com "e o que sobrar: descartar" simplesmente
// para de bloquear. Isso não pode virar apply ok: é exatamente o mesmo peso
// do nome de chain inseguro, que já vira falha agregada
// (TestReconcileGroupsRefusesUnsafeChainName). E, como lá, os OUTROS grupos
// continuam sendo aplicados.
func TestReconcileGroupsReportsEnabledGroupWithoutAJump(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	groups := []StoredGroup{
		{ID: "a", Name: "Wi-Fi visitantes", ChainName: "grp_aaa", Enabled: true, Position: 0,
			CondSaddr: "192.168.50.0/33", Fallthrough: FallthroughDrop},
		{ID: "b", Name: "Servidores", ChainName: "grp_bbb", Enabled: true, Position: 1,
			Fallthrough: FallthroughContinue},
	}

	err := s.ReconcileGroups(context.Background(), groups)
	if err == nil {
		t.Fatal("grupo ativado que ficou fora da forward tem que virar apply não-ok, veio nil")
	}
	if !strings.Contains(err.Error(), "Wi-Fi visitantes") {
		t.Errorf("o erro tem que dizer QUAL grupo ficou de fora, veio %q", err.Error())
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "jump grp_aaa") {
			t.Fatalf("a condição inválida não podia ter chegado ao nft: %q", c)
		}
	}
	// Contenção de falha: o grupo bom continua valendo.
	if !ranCommand(exec.executed, "nft add rule inet linkguard forward counter jump grp_bbb") {
		t.Errorf("o outro grupo parou de ser aplicado por causa do grupo quebrado: %v", exec.executed)
	}
}

// O mesmo grupo, DESLIGADO, não é falha nenhuma: desligado já não tem jump
// por definição (spec §2.1), e marcar apply não-ok por causa dele deixaria o
// painel vermelho para sempre por um grupo que o admin não está usando.
func TestReconcileGroupsIgnoresInvalidConditionOnDisabledGroup(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	groups := []StoredGroup{
		{ID: "a", Name: "Wi-Fi visitantes", ChainName: "grp_aaa", Enabled: false, Position: 0,
			CondSaddr: "192.168.50.0/33", Fallthrough: FallthroughDrop},
	}

	if err := s.ReconcileGroups(context.Background(), groups); err != nil {
		t.Fatalf("grupo desligado com condição inválida não é falha de aplicação: %v", err)
	}
}

// Idempotência aqui é CONVERGÊNCIA: a segunda passada, sobre o ruleset que
// a primeira deixou, não pode ter mais nada para limpar e tem que reescrever
// exatamente o mesmo conteúdo.
//
// Com o `readOut` estático que este teste usava, a segunda passada revia a
// mesma chain órfã e reemitia o mesmo `delete` — a igualdade entre as duas
// listas era trivialmente satisfeita e não provava nada sobre convergir. O
// fake agora reflete a remoção: a leitura da segunda passada é o ruleset SEM
// a órfã.
func TestReconcileGroupsIsIdempotent(t *testing.T) {
	groups := []StoredGroup{{ID: "a", Name: "Visitantes", ChainName: "grp_aaa", Enabled: true,
		CondSaddr: "192.168.50.0/24", Fallthrough: FallthroughDrop,
		Rules: []StoredRule{{ID: "r", Position: 0, Enabled: true,
			Fields: RuleFields{Action: "accept", Proto: "tcp", Dport: "443"}}}}}

	exec := &fakeReconcileExec{readOut: map[string]string{
		"nft list table inet linkguard": liveTableWithOrphanGroup,
	}}
	s := &Service{exec: exec}
	if err := s.ReconcileGroups(context.Background(), groups); err != nil {
		t.Fatalf("primeira: %v", err)
	}
	first := append([]string(nil), exec.executed...)
	if !ranCommand(first, "nft delete chain inet linkguard grp_orfa") {
		t.Fatalf("a primeira passada tinha que remover a órfã: %v", first)
	}

	// O ruleset vivo agora é o que a primeira passada deixou.
	exec.readOut["nft list table inet linkguard"] = liveTableAfterReconcile
	exec.executed = nil
	if err := s.ReconcileGroups(context.Background(), groups); err != nil {
		t.Fatalf("segunda: %v", err)
	}
	second := append([]string(nil), exec.executed...)

	// 1. convergiu: não sobrou nada para remover.
	for _, c := range second {
		if strings.HasPrefix(c, "nft delete chain") {
			t.Errorf("a segunda passada ainda tinha o que apagar (não convergiu): %q", c)
		}
	}
	// 2. e o conteúdo reescrito é o mesmo — comparado contra a primeira
	// passada sem os comandos de limpeza, que só existiam por causa da órfã.
	var firstWithoutCleanup []string
	for _, c := range first {
		if strings.HasPrefix(c, "nft delete chain") {
			continue
		}
		firstWithoutCleanup = append(firstWithoutCleanup, c)
	}
	if len(firstWithoutCleanup) != len(second) {
		t.Fatalf("a segunda execução emitiu outro conjunto de comandos:\nprimeira=%v\nsegunda=%v", firstWithoutCleanup, second)
	}
	for i := range firstWithoutCleanup {
		if firstWithoutCleanup[i] != second[i] {
			t.Errorf("comando %d difere entre execuções:\nprimeira=%q\nsegunda=%q", i, firstWithoutCleanup[i], second[i])
		}
	}
}

// m-7: o log final de ReconcileGroups tinha que contar quantas CHAINS foram
// aplicadas — e os dois grupos do sistema não têm chain própria (o conteúdo
// deles é o named set). Com dois grupos do sistema e um do admin, o número
// certo é 1, não 3.
func TestReconcileGroupsLogsChainsAppliedExcludingSystemGroups(t *testing.T) {
	logs := captureLogs(t)
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	groups := []StoredGroup{
		{ID: "h", Name: "Hosts bloqueados", ChainName: SystemChainBlockedHosts,
			Kind: GroupKindBlockedHosts, Enabled: true, Position: 0, Fallthrough: FallthroughContinue},
		{ID: "l", Name: "Destinos bloqueados", ChainName: SystemChainBlocklist,
			Kind: GroupKindBlocklist, Enabled: true, Position: 1, Fallthrough: FallthroughContinue},
		{ID: "a", Name: "Visitantes", ChainName: "grp_aaa", Kind: GroupKindAdmin, Enabled: true, Position: 2,
			Fallthrough: FallthroughContinue},
	}

	if err := s.ReconcileGroups(context.Background(), groups); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if !strings.Contains(logs.String(), "chains_aplicadas=1") {
		t.Errorf("esperava chains_aplicadas=1 (só o grupo do admin tem chain própria), log:\n%s", logs.String())
	}
}

func TestReconcileGroupsNoopInDryRun(t *testing.T) {
	exec := &fakeReconcileExec{dryRun: true}
	s := &Service{exec: exec}
	groups := []StoredGroup{{ID: "a", Name: "Visitantes", ChainName: "grp_aaa", Enabled: true,
		Fallthrough: FallthroughContinue}}

	if err := s.ReconcileGroups(context.Background(), groups); err != nil {
		t.Fatalf("ReconcileGroups em dry-run: %v", err)
	}
	if len(exec.executed) != 0 {
		t.Errorf("esperava zero comandos em dry-run, rodou: %v", exec.executed)
	}
}

// ─── CheckGroups ─────────────────────────────────────────────────────────

// scriptFor devolve, dentre os scripts validados por `nft -c`, aquele que
// reconstrói a chain pedida — identificado pelo `flush chain` dela, que é a
// linha que só existe no script daquela chain. Pescar por posição no slice
// (`checkScripts[len-1]`) amarrava o teste à ORDEM em que CheckGroups valida
// as chains, e foi exatamente o que quebrou quando a input entrou como um
// terceiro script.
func scriptFor(t *testing.T, scripts []string, chain string) string {
	t.Helper()
	marker := "flush chain " + Family + " " + Table + " " + chain + "\n"
	for _, s := range scripts {
		if strings.Contains(s, marker) {
			return s
		}
	}
	t.Fatalf("nenhum script validado reconstrói a chain %s:\n%s", chain, strings.Join(scripts, "\n---\n"))
	return ""
}

// A validação prévia (`nft -c`) tem que passar exatamente pelo que a
// reconciliação de verdade vai emitir depois — mesma renderização, mesma
// ordem, chain do grupo E forward — senão ela aprova uma coisa e o firewall
// recebe outra.
func TestCheckGroupsValidatesEveryGroupChainAndTheForward(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	// ATUALIZADO: os dois grupos do sistema entram na lista — é deles que
	// saem, agora, as linhas de set que este teste exige no script validado.
	// Eles não acrescentam script nenhum (não têm chain própria). São 4
	// validações: as duas chains de grupo, a forward e a input (Fase C2).
	groups := []StoredGroup{
		{ID: "h", Name: "Hosts bloqueados", ChainName: SystemChainBlockedHosts,
			Kind: GroupKindBlockedHosts, Enabled: true, Position: 0, Fallthrough: FallthroughContinue},
		{ID: "l", Name: "Destinos bloqueados", ChainName: SystemChainBlocklist,
			Kind: GroupKindBlocklist, Enabled: true, Position: 1, Fallthrough: FallthroughContinue},
		{ID: "a", Name: "Visitantes", ChainName: "grp_aaa", Kind: GroupKindAdmin, Enabled: true, Position: 2,
			CondSaddr: "192.168.50.0/24", Fallthrough: FallthroughDrop,
			Rules: []StoredRule{{ID: "r", Position: 0, Enabled: true,
				Fields: RuleFields{Action: "accept", Proto: "tcp", Dport: "443"}}}},
		{ID: "b", Name: "Servidores", ChainName: "grp_bbb", Kind: GroupKindAdmin, Enabled: true, Position: 3,
			Fallthrough: FallthroughContinue},
	}

	if err := s.CheckGroups(context.Background(), groups); err != nil {
		t.Fatalf("CheckGroups: %v", err)
	}
	if len(exec.executed) != 0 {
		t.Fatalf("a validação prévia não pode mudar nada no firewall, rodou: %v", exec.executed)
	}
	if len(exec.checkScripts) != 4 {
		t.Fatalf("esperava 4 validações (duas chains de grupo + forward + input), vieram %d", len(exec.checkScripts))
	}
	all := strings.Join(exec.checkScripts, "\n")
	for _, want := range []string{
		"add rule inet linkguard grp_aaa tcp dport 443 counter accept",
		"add rule inet linkguard grp_aaa counter drop",
		"add rule inet linkguard forward ip saddr @blocked_hosts counter drop",
		"add rule inet linkguard forward ip saddr 192.168.50.0/24 counter jump grp_aaa",
		"add rule inet linkguard forward counter jump grp_bbb",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("a validação prévia não conferiu %q:\n%s", want, all)
		}
	}
	// A forward validada é a mesma que a reconciliação escreveria: bloqueios
	// antes dos jumps.
	fwd := scriptFor(t, exec.checkScripts, ForwardChain)
	if strings.Index(fwd, "@blocklist") > strings.Index(fwd, "jump grp_aaa") {
		t.Errorf("a forward validada não está na ordem da §3:\n%s", fwd)
	}
}

// O pre-flight roda ANTES do INSERT no banco (é o contrato: validar com a
// ferramenta real antes de gravar), então a chain do grupo NOVO ainda não
// existe no kernel. Um script que começa com `flush chain … grp_novo` ou que
// pula para ele é recusado pelo nft com "No such file or directory" — mesmo
// em `nft -c`, verificado ao vivo na produção — e o resultado seria criar
// QUALQUER grupo devolver 400. O script tem que garantir a chain (`add
// chain`, idempotente, e que o `-c` não materializa) antes de usá-la.
func TestCheckGroupsCreatesTheGroupChainBeforeUsingIt(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	groups := []StoredGroup{
		{ID: "novo", Name: "Wi-Fi visitantes", ChainName: "grp_novo", Enabled: true, Position: 0,
			CondSaddr: "192.168.50.0/24", Fallthrough: FallthroughDrop,
			Rules: []StoredRule{{ID: "r", Position: 0, Enabled: true,
				Fields: RuleFields{Action: "accept", Proto: "tcp", Dport: "443"}}}},
	}

	if err := s.CheckGroups(context.Background(), groups); err != nil {
		t.Fatalf("CheckGroups: %v", err)
	}
	if len(exec.checkScripts) != 3 {
		t.Fatalf("esperava 3 validações (chain do grupo + forward + input), vieram %d", len(exec.checkScripts))
	}

	// 1. no script da própria chain do grupo: add chain antes do flush.
	own := scriptFor(t, exec.checkScripts, "grp_novo")
	idxAdd := strings.Index(own, "add chain inet linkguard grp_novo\n")
	idxFlush := strings.Index(own, "flush chain inet linkguard grp_novo\n")
	if idxAdd < 0 {
		t.Fatalf("o script de validação não garante a chain do grupo novo:\n%s", own)
	}
	if idxFlush < 0 {
		t.Fatalf("o script de validação não dá flush na chain do grupo:\n%s", own)
	}
	if idxAdd > idxFlush {
		t.Errorf("o `add chain` veio depois do `flush` — o nft já teria recusado:\n%s", own)
	}

	// 2. no script da forward: add chain antes do jump correspondente.
	fwd := scriptFor(t, exec.checkScripts, ForwardChain)
	idxAddFwd := strings.Index(fwd, "add chain inet linkguard grp_novo\n")
	idxJump := strings.Index(fwd, "jump grp_novo")
	if idxAddFwd < 0 {
		t.Fatalf("o script da forward pula para uma chain que ainda não existe:\n%s", fwd)
	}
	if idxJump < 0 {
		t.Fatalf("o script da forward não tem o jump do grupo:\n%s", fwd)
	}
	if idxAddFwd > idxJump {
		t.Errorf("o `add chain` veio depois do jump — o nft já teria recusado:\n%s", fwd)
	}
}

// O `add chain` extra é só para as chains de GRUPO: CheckChain/CheckUserRules
// validam chains que existem desde o bootstrap, e emitir `add chain` para
// elas mudaria o script que hoje está em produção sem necessidade.
func TestCheckUserRulesScriptStaysExactlyAsItWas(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.CheckUserRules(context.Background(), []StoredRule{
		{ID: "r", Enabled: true, Fields: RuleFields{Action: "accept", Proto: "tcp", Dport: "22"}},
	}); err != nil {
		t.Fatalf("CheckUserRules: %v", err)
	}
	if len(exec.checkScripts) != 1 {
		t.Fatalf("esperava 1 validação, vieram %d", len(exec.checkScripts))
	}
	if strings.Contains(exec.checkScripts[0], "add chain") {
		t.Errorf("o script de user_rules não pode ganhar `add chain`:\n%s", exec.checkScripts[0])
	}
}

func TestCheckGroupsSurfacesNftsOwnRejection(t *testing.T) {
	exec := &fakeReconcileExec{readErr: errors.New("nft: Error: invalid port range: end before start")}
	s := &Service{exec: exec}
	groups := []StoredGroup{{ID: "a", Name: "Visitantes", ChainName: "grp_aaa", Enabled: true,
		Fallthrough: FallthroughContinue}}

	err := s.CheckGroups(context.Background(), groups)
	if err == nil {
		t.Fatal("esperava que a recusa do próprio nft chegasse ao chamador")
	}
	if !strings.Contains(err.Error(), "invalid port range") {
		t.Errorf("esperava a mensagem do nft no erro, veio %q", err.Error())
	}
	if !strings.Contains(err.Error(), "Visitantes") {
		t.Errorf("o erro tem que dizer QUAL grupo não passou, veio %q", err.Error())
	}
}

// ─── listGroupChains ─────────────────────────────────────────────────────

// Só as chains do próprio LinkGuard que pertencem a grupos (prefixo grp_)
// são candidatas a remoção. É isto que permite apagar a chain de um grupo
// que o admin removeu sem nunca tocar em chain de terceiros.
func TestListGroupChainsSeesOnlyGroupChains(t *testing.T) {
	exec := &fakeReconcileExec{readOut: map[string]string{
		"nft list table inet linkguard": liveTableWithOrphanGroup,
	}}
	s := &Service{exec: exec}

	got, err := s.listGroupChains(context.Background())
	if err != nil {
		t.Fatalf("listGroupChains: %v", err)
	}
	if fmt.Sprint(got) != fmt.Sprint([]string{"grp_aaa", "grp_orfa"}) {
		t.Fatalf("chains de grupo lidas do ruleset vivo = %v, queria [grp_aaa grp_orfa]", got)
	}
	// E a leitura é escopada na tabela do LinkGuard: `nft list chains
	// <família>` não aceita nome de tabela e devolveria chain de terceiro.
	if len(exec.reads) == 0 || !strings.HasPrefix(exec.reads[0], "nft list table inet linkguard") {
		t.Errorf("a listagem tem que ser escopada na tabela do LinkGuard, leu: %v", exec.reads)
	}
}

// ─── DeleteUnreferencedChain: a remoção da chain legada user_rules ───────

// A tentação é dar `flush` antes do `delete` "para garantir". Num firewall
// isso inverte o risco: o nft ACEITA esvaziar uma chain ainda referenciada e
// RECUSA apagá-la. Se a forward ainda tiver o jump (reconstrução falhou,
// ruleset restaurado de um boot antigo), o flush passa, o delete falha, e
// sobra uma chain viva e VAZIA — o tráfego que as regras do admin
// bloqueavam ali passa a passar. Sem o flush, ou a chain some inteira ou
// nada muda.
func TestDeleteUnreferencedChainNeverFlushesBeforeDeleting(t *testing.T) {
	exec := &fakeReconcileExec{readOut: map[string]string{
		"nft list chain inet linkguard user_rules": "table inet linkguard {\n\tchain user_rules {\n\t\ttcp dport 22 counter accept\n\t}\n}\n",
	}}
	s := &Service{exec: exec}

	if err := s.DeleteUnreferencedChain(context.Background(), UserChain); err != nil {
		t.Fatalf("DeleteUnreferencedChain: %v", err)
	}
	for _, c := range exec.executed {
		if strings.HasPrefix(c, "nft flush chain") && strings.Contains(c, UserChain) {
			t.Errorf("a chain legada não pode ser esvaziada antes de removida: %q", c)
		}
	}
	if !ranCommand(exec.executed, "nft delete chain inet linkguard user_rules") {
		t.Errorf("a chain legada não foi removida: %v", exec.executed)
	}
}

// Isto roda em todo boot depois da migração. Numa máquina onde a chain sumiu
// há semanas, ela não pode nem tentar apagar nem devolver erro — viraria
// ruído permanente no log e um apply não-ok eterno.
func TestDeleteUnreferencedChainIsQuietWhenTheChainIsAlreadyGone(t *testing.T) {
	exec := &fakeReconcileExec{readErr: errors.New("nft: Error: No such file or directory")}
	s := &Service{exec: exec}

	if err := s.DeleteUnreferencedChain(context.Background(), UserChain); err != nil {
		t.Fatalf("chain inexistente não é erro: %v", err)
	}
	for _, c := range exec.executed {
		if strings.HasPrefix(c, "nft delete chain") {
			t.Errorf("não se apaga uma chain que não está lá: %q", c)
		}
	}
}

// O nft recusando o delete (a forward ainda referencia a chain: "Device or
// resource busy") tem que chegar ao chamador — é ele que decide o que
// registrar. O que não pode é a chain ter sido mexida assim mesmo.
func TestDeleteUnreferencedChainSurfacesTheRefusal(t *testing.T) {
	exec := &fakeReconcileExec{
		readOut: map[string]string{"nft list chain inet linkguard user_rules": "table inet linkguard {\n\tchain user_rules {\n\t}\n}\n"},
		failOn: func(cmd string) error {
			if strings.HasPrefix(cmd, "nft delete chain") {
				return errors.New("Device or resource busy")
			}
			return nil
		},
	}
	s := &Service{exec: exec}

	err := s.DeleteUnreferencedChain(context.Background(), UserChain)
	if err == nil {
		t.Fatal("esperava a recusa do nft chegando ao chamador")
	}
	if !strings.Contains(err.Error(), "Device or resource busy") {
		t.Errorf("a mensagem do nft tem que ser preservada, obtive %q", err)
	}
}

func TestDeleteUnreferencedChainIsANoOpInDryRun(t *testing.T) {
	exec := &fakeReconcileExec{dryRun: true}
	s := &Service{exec: exec}
	if err := s.DeleteUnreferencedChain(context.Background(), UserChain); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if len(exec.executed) != 0 || len(exec.reads) != 0 {
		t.Errorf("dry-run não pode tocar no nft: %v %v", exec.executed, exec.reads)
	}
}

// ─── Grupo do sistema ────────────────────────────────────────────────────

// Um grupo do sistema não tem chain própria: o conteúdo dele é um named set
// (@blocked_hosts / @blocklist) e as linhas dele moram na própria forward. O
// chain_name reservado que a migração grava (sys_…) existe só para ocupar a
// coluna NOT NULL UNIQUE — mandá-lo para o nft criaria uma chain vazia e
// órfã, e validá-lo como se fosse chain de grupo do admin (que só aceita
// grp_…) marcaria os DOIS bloqueios como "não aplicados" em toda
// reconciliação: apply não-ok eterno no painel, e o pré-voo `nft -c` de
// CheckGroups recusando toda mutação de regra com 400.
func TestReconcileGroupsGivesSystemGroupsNoChainAndNoFailure(t *testing.T) {
	exec := &fakeReconcileExec{readOut: map[string]string{
		"nft list table inet linkguard": liveTableWithOrphanGroup,
	}}
	s := &Service{exec: exec}
	groups := []StoredGroup{
		{ID: "h", Name: "Hosts bloqueados", ChainName: SystemChainBlockedHosts,
			Kind: GroupKindBlockedHosts, Position: 0, Enabled: true, Fallthrough: FallthroughContinue},
		{ID: "b", Name: "Destinos bloqueados", ChainName: SystemChainBlocklist,
			Kind: GroupKindBlocklist, Position: 1, Enabled: true, Fallthrough: FallthroughContinue},
		{ID: "a", Name: "Wi-Fi", ChainName: "grp_aaa", Kind: GroupKindAdmin,
			Position: 2, Enabled: true, Fallthrough: FallthroughContinue},
	}

	if err := s.ReconcileGroups(context.Background(), groups); err != nil {
		t.Fatalf("grupo do sistema não pode virar falha de aplicação: %v", err)
	}
	for _, joined := range exec.executed {
		if strings.Contains(joined, SystemChainBlockedHosts) || strings.Contains(joined, SystemChainBlocklist) {
			t.Errorf("o nome de chain reservado do grupo do sistema foi para o nft: %q", joined)
		}
	}
}

// Mesma razão, no pré-voo: CheckGroups valida o que ReconcileGroups
// renderizaria. Recusar o grupo do sistema aqui faria criar/editar/mover
// QUALQUER regra devolver 400, porque o pré-voo enxerga o conjunto completo
// de grupos, não só o que está sendo mexido.
func TestCheckGroupsDoesNotRejectSystemGroups(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	groups := []StoredGroup{
		{ID: "h", Name: "Hosts bloqueados", ChainName: SystemChainBlockedHosts,
			Kind: GroupKindBlockedHosts, Enabled: true, Fallthrough: FallthroughContinue},
		{ID: "a", Name: "Wi-Fi", ChainName: "grp_aaa", Kind: GroupKindAdmin,
			Enabled: true, Fallthrough: FallthroughContinue},
	}

	if err := s.CheckGroups(context.Background(), groups); err != nil {
		t.Fatalf("o pré-voo recusou um grupo do sistema: %v", err)
	}
	for _, script := range exec.checkScripts {
		if strings.Contains(script, SystemChainBlockedHosts) {
			t.Errorf("o nome de chain reservado entrou no script validado pelo nft:\n%s", script)
		}
	}
}

// CheckGroups renderiza a forward do MESMO jeito que ReconcileGroups — é o
// motivo de o pré-voo existir. Com a forward virando uma lista ordenada só,
// isso passa a incluir a POSIÇÃO das linhas de set: se o pré-voo validasse os
// bloqueios sempre no topo enquanto a reconciliação os escreve no meio, o
// `nft -c` aprovaria uma chain diferente da que vai ser aplicada — exatamente
// a divergência que CheckChainEnsuring existe para eliminar.
func TestCheckGroupsValidatesTheForwardWithTheBlocksInListPosition(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	groups := []StoredGroup{
		{ID: "a", Name: "Visitantes", ChainName: "grp_aaa", Kind: GroupKindAdmin,
			Enabled: true, Position: 0, CondSaddr: "192.168.50.0/24",
			Fallthrough: FallthroughContinue},
		{ID: "h", Name: "Hosts bloqueados", ChainName: SystemChainBlockedHosts,
			Kind: GroupKindBlockedHosts, Enabled: true, Position: 1,
			Fallthrough: FallthroughContinue},
	}

	if err := s.CheckGroups(context.Background(), groups); err != nil {
		t.Fatalf("CheckGroups: %v", err)
	}
	if len(exec.checkScripts) == 0 {
		t.Fatal("nenhum script foi validado")
	}
	fwd := scriptFor(t, exec.checkScripts, ForwardChain)
	idxJump := strings.Index(fwd, "jump grp_aaa")
	idxBlock := strings.Index(fwd, "@blocked_hosts")
	if idxJump < 0 || idxBlock < 0 {
		t.Fatalf("a forward validada não tem o jump e o bloqueio:\n%s", fwd)
	}
	if idxBlock < idxJump {
		t.Errorf("o pré-voo validou os bloqueios no topo, mas a reconciliação os escreveria depois do jump — script validado ≠ script aplicado:\n%s", fwd)
	}
}

// ─── Fase C2: escopo do grupo e a chain input com um renderizador só ─────

// inputLines é o equivalente de forwardLines para a chain input: a lista
// ordenada que o renderizador único emite, uma linha por regra.
func inputLines(groups []StoredGroup, ntpNetworks []string, ntpServing bool) []string {
	var lines []string
	for _, toks := range inputChainRules(groups, ntpNetworks, ntpServing) {
		lines = append(lines, strings.Join(toks, " "))
	}
	return lines
}

// inputAdds extrai, da sequência de comandos executados, só os `add rule` da
// chain input — na ordem em que foram emitidos, que é a ordem em que o nft os
// avalia.
func inputAdds(executed []string) []string {
	var out []string
	for _, c := range executed {
		if strings.HasPrefix(c, "nft add rule inet linkguard input ") {
			out = append(out, c)
		}
	}
	return out
}

// A chain input tinha UM dono: ReconcileNTPInput dava flush nela e escrevia
// só as regras de NTP. Com grupos de escopo input escrevendo no mesmo lugar,
// os dois se apagavam mutuamente. Um renderizador só, como já foi feito para
// a forward.
func TestInputChainRendersNTPAndGroupJumpsTogether(t *testing.T) {
	groups := []StoredGroup{
		{ID: "a", Kind: GroupKindAdmin, Scope: ScopeInput, ChainName: "grp_aaa",
			Enabled: true, Position: 0, CondSaddr: "192.168.50.0/24"},
		{ID: "b", Kind: GroupKindAdmin, Scope: ScopeForward, ChainName: "grp_bbb",
			Enabled: true, Position: 1},
	}
	lines := inputLines(groups, []string{"192.168.3.0/24"}, true)
	want := []string{
		"udp dport 123 ip saddr { 192.168.3.0/24 } counter accept",
		"udp dport 123 counter drop",
		"ip saddr 192.168.50.0/24 counter jump grp_aaa",
	}
	if len(lines) != len(want) {
		t.Fatalf("esperava %d linhas, obtive %d: %v", len(want), len(lines), lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("linha %d:\n  obtive %q\n  queria %q", i, lines[i], want[i])
		}
	}
}

// Grupo de escopo forward NUNCA aparece na input, e vice-versa. Trocar de
// chain um grupo que o admin escreveu para atravessar seria aplicá-lo a um
// tráfego que ele não pretendia filtrar.
func TestGroupScopeDecidesWhichChainItLandsIn(t *testing.T) {
	groups := []StoredGroup{
		{ID: "i", Kind: GroupKindAdmin, Scope: ScopeInput, ChainName: "grp_iii", Enabled: true, Position: 0},
		{ID: "f", Kind: GroupKindAdmin, Scope: ScopeForward, ChainName: "grp_fff", Enabled: true, Position: 1},
	}
	inp := renderChainScript(InputChain, inputChainRules(groups, nil, false))
	fwd := renderChainScript(ForwardChain, forwardChainRules(groups))
	// Presença primeiro: só com as ausências, este teste passaria com os dois
	// renderizadores devolvendo lista vazia — nenhum grupo em chain nenhuma,
	// que é um firewall sem as regras do admin, e o teste diria verde.
	if !strings.Contains(inp, "jump grp_iii") {
		t.Errorf("o grupo de escopo input não entrou na chain input:\n%s", inp)
	}
	if !strings.Contains(fwd, "jump grp_fff") {
		t.Errorf("o grupo de escopo forward não entrou na chain forward:\n%s", fwd)
	}
	if strings.Contains(inp, "grp_fff") {
		t.Error("grupo de escopo forward vazou para a chain input")
	}
	if strings.Contains(fwd, "grp_iii") {
		t.Error("grupo de escopo input vazou para a chain forward")
	}
}

// Escopo vazio é o valor de toda linha criada antes da coluna existir, e todo
// grupo que existia era de tráfego atravessando: ele tem que continuar caindo
// na forward, nunca na input.
func TestEmptyScopeCountsAsForward(t *testing.T) {
	groups := []StoredGroup{
		{ID: "v", Kind: GroupKindAdmin, ChainName: "grp_velho", Enabled: true, Position: 0},
	}
	if lines := forwardLines(groups); len(lines) != 1 || !strings.Contains(lines[0], "jump grp_velho") {
		t.Errorf("grupo com escopo vazio tinha que entrar na forward, obtive %v", lines)
	}
	if lines := inputLines(groups, nil, false); len(lines) != 0 {
		t.Errorf("grupo com escopo vazio não pode entrar na input, obtive %v", lines)
	}
}

// Os dois grupos do sistema são bloqueio de tráfego ATRAVESSANDO o firewall
// (os named sets valem para a forward). Uma linha de banco com scope=input
// neles — edição à mão, corrupção — não pode transformar o bloqueio de hosts
// em regra de input: o admin perderia o bloqueio na forward, que é onde ele
// existe para valer.
func TestSystemGroupsStayInForwardEvenWithAnInputScopeRow(t *testing.T) {
	groups := []StoredGroup{
		{ID: "h", Kind: GroupKindBlockedHosts, Scope: ScopeInput, ChainName: SystemChainBlockedHosts,
			Enabled: true, Position: 0},
	}
	fwd := forwardLines(groups)
	if len(fwd) != 2 || !strings.Contains(fwd[0], "@blocked_hosts") {
		t.Fatalf("o bloqueio do sistema tem que continuar na forward, obtive %v", fwd)
	}
	if lines := inputLines(groups, nil, false); len(lines) != 0 {
		t.Errorf("grupo do sistema não pode emitir linha na chain input, obtive %v", lines)
	}
}

// A política da chain input é accept, sempre. Se algum dia alguém a mudar
// para drop, o operador perde SSH e painel no mesmo instante.
func TestInputChainPolicyIsAlwaysAccept(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	if err := s.ReconcileGroups(context.Background(), []StoredGroup{
		{ID: "i", Kind: GroupKindAdmin, Scope: ScopeInput, ChainName: "grp_iii", Enabled: true},
	}); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	for _, cmd := range exec.executed {
		if strings.Contains(cmd, "hook input") && !strings.Contains(cmd, "policy accept") {
			t.Fatalf("chain input criada sem policy accept: %q", cmd)
		}
		if strings.Contains(cmd, "policy drop") {
			t.Fatalf("policy drop em qualquer chain é proibido: %q", cmd)
		}
	}
}

// Direção 1 do problema central: salvar um grupo (qualquer um) reconstrói a
// chain input, e ela não pode sair sem a proteção do NTP. Antes do
// renderizador único, ReconcileGroups escrevendo na input apagaria as regras
// que ReconcileNTPInput tinha posto lá — o firewall passaria a responder NTP
// para a internet inteira sem nada na tela mudar.
func TestSavingAGroupDoesNotWipeTheNTPProtection(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	s.SetInputChainSources(
		func() ([]StoredGroup, error) { return nil, nil },
		func() ([]string, bool, error) { return []string{"192.168.3.0/24"}, true, nil },
	)

	if err := s.ReconcileGroups(context.Background(), []StoredGroup{
		{ID: "i", Kind: GroupKindAdmin, Scope: ScopeInput, ChainName: "grp_iii",
			Enabled: true, Position: 0},
	}); err != nil {
		t.Fatalf("ReconcileGroups: %v", err)
	}
	adds := inputAdds(exec.executed)
	want := []string{
		"nft add rule inet linkguard input udp dport 123 ip saddr { 192.168.3.0/24 } counter accept",
		"nft add rule inet linkguard input udp dport 123 counter drop",
		"nft add rule inet linkguard input counter jump grp_iii",
	}
	if len(adds) != len(want) {
		t.Fatalf("esperava %d regras na input, obtive %d: %v", len(want), len(adds), adds)
	}
	for i := range want {
		if adds[i] != want[i] {
			t.Errorf("regra %d da input:\n  obtive %q\n  queria %q", i, adds[i], want[i])
		}
	}
}

// Direção 2: ligar/desligar o NTP reconstrói a mesma chain input, e ela não
// pode sair sem os jumps dos grupos de escopo input — o admin veria o grupo
// dele ativado no painel e nenhum pacote passando por ele.
func TestReconcilingNTPDoesNotWipeTheInputGroupJumps(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	s.SetInputChainSources(
		func() ([]StoredGroup, error) {
			return []StoredGroup{
				{ID: "i", Kind: GroupKindAdmin, Scope: ScopeInput, ChainName: "grp_iii",
					Enabled: true, Position: 0, CondSaddr: "192.168.50.0/24"},
				{ID: "f", Kind: GroupKindAdmin, Scope: ScopeForward, ChainName: "grp_fff",
					Enabled: true, Position: 1},
			}, nil
		},
		func() ([]string, bool, error) { return nil, false, nil },
	)

	if err := s.ReconcileNTPInput(context.Background(), []string{"192.168.3.0/24"}, true); err != nil {
		t.Fatalf("ReconcileNTPInput: %v", err)
	}
	adds := inputAdds(exec.executed)
	want := []string{
		"nft add rule inet linkguard input udp dport 123 ip saddr { 192.168.3.0/24 } counter accept",
		"nft add rule inet linkguard input udp dport 123 counter drop",
		"nft add rule inet linkguard input ip saddr 192.168.50.0/24 counter jump grp_iii",
	}
	if len(adds) != len(want) {
		t.Fatalf("esperava %d regras na input, obtive %d: %v", len(want), len(adds), adds)
	}
	for i := range want {
		if adds[i] != want[i] {
			t.Errorf("regra %d da input:\n  obtive %q\n  queria %q", i, adds[i], want[i])
		}
	}
}

// Desligar o NTP não pode ser o que apaga os grupos de input: a chain é
// reconstruída inteira, só que sem as duas linhas de udp/123.
func TestTurningNTPOffKeepsTheInputGroupJumps(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	s.SetInputChainSources(
		func() ([]StoredGroup, error) {
			return []StoredGroup{
				{ID: "i", Kind: GroupKindAdmin, Scope: ScopeInput, ChainName: "grp_iii", Enabled: true},
			}, nil
		},
		func() ([]string, bool, error) { return nil, false, nil },
	)

	if err := s.ReconcileNTPInput(context.Background(), []string{"192.168.3.0/24"}, false); err != nil {
		t.Fatalf("ReconcileNTPInput: %v", err)
	}
	adds := inputAdds(exec.executed)
	if len(adds) != 1 || adds[0] != "nft add rule inet linkguard input counter jump grp_iii" {
		t.Fatalf("o jump do grupo de input tinha que sobreviver ao NTP desligado, obtive %v", adds)
	}
}

// Um SELECT que falhou não é "o admin não tem grupo nenhum": se os grupos não
// podem ser lidos, a chain input NÃO é tocada. Reconstruí-la com lista vazia
// apagaria todos os jumps de input por causa de um erro de leitura — o mesmo
// contrato que ReconcileGroups tem para a forward.
func TestReconcileNTPInputDoesNotTouchTheChainWhenGroupsCannotBeRead(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	s.SetInputChainSources(
		func() ([]StoredGroup, error) { return nil, errors.New("banco fora do ar") },
		func() ([]string, bool, error) { return nil, false, nil },
	)

	if err := s.ReconcileNTPInput(context.Background(), []string{"192.168.3.0/24"}, true); err == nil {
		t.Fatal("ler os grupos falhou e mesmo assim a reconciliação disse ok")
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "flush chain inet linkguard input") || strings.HasPrefix(c, "nft add rule inet linkguard input") {
			t.Errorf("a chain input foi mexida mesmo sem saber quais grupos existem: %q", c)
		}
	}
}

// A chain input é reconstruída ANTES da limpeza de chains órfãs, pela mesma
// razão que a forward: o nft recusa apagar chain ainda referenciada (EBUSY),
// e um grupo de input apagado do banco ainda tem o `jump` dele na input viva.
func TestInputChainIsRebuiltBeforeOrphanChainsAreDeleted(t *testing.T) {
	exec := &fakeReconcileExec{readOut: map[string]string{
		"nft list table inet linkguard": liveTableWithOrphanGroup,
	}}
	s := &Service{exec: exec}
	groups := []StoredGroup{
		{ID: "a", Kind: GroupKindAdmin, ChainName: "grp_aaa", Enabled: true, Position: 0,
			CondSaddr: "192.168.50.0/24"},
	}
	if err := s.ReconcileGroups(context.Background(), groups); err != nil {
		t.Fatalf("ReconcileGroups: %v", err)
	}
	flushInput := indexOfCommand(exec.executed, func(c string) bool {
		return c == "nft flush chain inet linkguard input"
	})
	deleteOrphan := indexOfCommand(exec.executed, func(c string) bool {
		return strings.HasPrefix(c, "nft delete chain") && strings.HasSuffix(c, "grp_orfa")
	})
	if flushInput == -1 || deleteOrphan == -1 {
		t.Fatalf("esperava flush da input e delete da órfã; executados: %v", exec.executed)
	}
	if flushInput > deleteOrphan {
		t.Errorf("a input foi reconstruída depois de apagar a órfã: um jump de input vivo faria o delete falhar com EBUSY; executados: %v", exec.executed)
	}
}

// ─── Correções da revisão da Fase C2 ─────────────────────────────────────

// I-1. A ponta do NTP é simétrica à dos grupos: um erro de LEITURA não pode
// virar "servir NTP está desligado". Se virasse, salvar um grupo qualquer com
// o banco travado daria flush na chain input e a reescreveria só com os jumps
// — as duas linhas de udp/123 sumiriam do firewall vivo, o painel continuaria
// mostrando o toggle ligado, e o apply seria reportado ok. Fail-open em
// silêncio, que é justamente o que o lado dos grupos já evita de propósito.
func TestReconcileGroupsDoesNotTouchTheInputChainWhenTheNTPStateCannotBeRead(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	s.SetInputChainSources(
		func() ([]StoredGroup, error) { return nil, nil },
		func() ([]string, bool, error) { return nil, false, errors.New("banco travado") },
	)

	err := s.ReconcileGroups(context.Background(), []StoredGroup{
		{ID: "a", Kind: GroupKindAdmin, ChainName: "grp_aaa", Enabled: true, Position: 0},
	})
	if err == nil {
		t.Fatal("ler o estado do NTP falhou e mesmo assim o apply foi reportado ok")
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "flush chain inet linkguard input") ||
			strings.HasPrefix(c, "nft add rule inet linkguard input") {
			t.Errorf("a chain input foi mexida sem saber o estado do NTP: %q", c)
		}
	}
	// A forward não é refém disso: a contenção de falha deste pacote é por
	// chain, e o grupo do admin continua sendo aplicado.
	if indexOfCommand(exec.executed, func(c string) bool {
		return c == "nft flush chain inet linkguard forward"
	}) == -1 {
		t.Errorf("a forward deixou de ser reconciliada por causa de um erro que é só da input: %v", exec.executed)
	}
}

// I-1, continuação: com a input intocada, a limpeza de chains órfãs não pode
// rodar — a input viva ainda pode ter o `jump` da órfã, e o nft recusa apagar
// chain referenciada (EBUSY); o `flush` que viria antes, não. É a mesma razão
// pela qual o passo 4 espera o passo 3.
func TestOrphanChainsAreNotDeletedWhenTheInputChainWasNotRebuilt(t *testing.T) {
	exec := &fakeReconcileExec{readOut: map[string]string{
		"nft list table inet linkguard": liveTableWithOrphanGroup,
	}}
	s := &Service{exec: exec}
	s.SetInputChainSources(
		func() ([]StoredGroup, error) { return nil, nil },
		func() ([]string, bool, error) { return nil, false, errors.New("banco travado") },
	)

	if err := s.ReconcileGroups(context.Background(), []StoredGroup{
		{ID: "a", Kind: GroupKindAdmin, ChainName: "grp_aaa", Enabled: true, Position: 0},
	}); err == nil {
		t.Fatal("esperava erro")
	}
	for _, c := range exec.executed {
		if strings.HasPrefix(c, "nft delete chain") {
			t.Errorf("chain apagada numa passada em que a input não foi reconstruída: %q", c)
		}
	}
}

// I-3. O pré-voo valida a chain input e o `jump` que vai para ela, não só a
// forward. Sem isto, no dia em que a API expuser o campo `scope`, uma
// condição de entrada que o nft recusa passaria pelo gate de 400, entraria no
// banco, e só falharia no apply — depois de o flush já ter esvaziado a chain
// input viva.
func TestCheckGroupsValidatesTheInputChainToo(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	s.SetInputChainSources(
		func() ([]StoredGroup, error) { return nil, nil },
		func() ([]string, bool, error) { return []string{"192.168.3.0/24"}, true, nil },
	)
	groups := []StoredGroup{
		{ID: "i", Name: "Acesso ao firewall", ChainName: "grp_iii", Kind: GroupKindAdmin,
			Scope: ScopeInput, Enabled: true, Position: 0, CondSaddr: "192.168.50.0/24",
			Fallthrough: FallthroughContinue},
	}

	if err := s.CheckGroups(context.Background(), groups); err != nil {
		t.Fatalf("CheckGroups: %v", err)
	}
	if len(exec.executed) != 0 {
		t.Fatalf("a validação prévia não pode mudar nada no firewall, rodou: %v", exec.executed)
	}

	inp := scriptFor(t, exec.checkScripts, InputChain)
	// O jump do grupo de escopo input tem que estar no script validado — é a
	// linha que só existe por causa do que o admin acabou de digitar.
	idxJump := strings.Index(inp, "add rule inet linkguard input ip saddr 192.168.50.0/24 counter jump grp_iii")
	if idxJump < 0 {
		t.Fatalf("o pré-voo não validou o jump do grupo de escopo input:\n%s", inp)
	}
	// E as duas linhas de NTP, na mesma renderização que a reconciliação
	// emitiria: validar uma forma diferente é validar outra coisa.
	if !strings.Contains(inp, "add rule inet linkguard input udp dport 123 ip saddr { 192.168.3.0/24 } counter accept") {
		t.Errorf("o script da input não é o que a reconciliação escreveria:\n%s", inp)
	}

	// A própria chain input entra no `ensure`: numa máquina anterior a
	// 2026-08-11 ela não existe, e `flush chain` de chain inexistente derruba
	// o script inteiro dentro de um `nft -c -f` (verificado ao vivo, nft
	// v1.1.3). Sem isto, criar QUALQUER grupo passaria a devolver 400.
	idxAddInput := strings.Index(inp, "add chain inet linkguard input\n")
	idxFlush := strings.Index(inp, "flush chain inet linkguard input\n")
	if idxAddInput < 0 {
		t.Fatalf("o script da input não garante a própria chain input:\n%s", inp)
	}
	if idxAddInput > idxFlush {
		t.Errorf("o `add chain` da input veio depois do flush — o nft já teria recusado:\n%s", inp)
	}
	// E a chain do grupo NOVO também, senão o jump não parseia.
	idxAddGroup := strings.Index(inp, "add chain inet linkguard grp_iii\n")
	if idxAddGroup < 0 || idxAddGroup > idxJump {
		t.Errorf("o script da input pula para uma chain que ainda não existe:\n%s", inp)
	}
}

// Não conseguir ler o estado do NTP não pode REPROVAR o grupo do admin: aqui
// não se escreve nada, e devolver 400 em toda mutação de grupo por causa de um
// SELECT de settings que falhou trancaria o admin fora do painel. Os jumps —
// a parte que vem do que ele digitou — continuam sendo validados.
func TestCheckGroupsStillValidatesTheJumpsWhenTheNTPStateCannotBeRead(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	s.SetInputChainSources(
		func() ([]StoredGroup, error) { return nil, nil },
		func() ([]string, bool, error) { return nil, false, errors.New("banco travado") },
	)
	groups := []StoredGroup{
		{ID: "i", Name: "Acesso ao firewall", ChainName: "grp_iii", Kind: GroupKindAdmin,
			Scope: ScopeInput, Enabled: true, Position: 0, CondSaddr: "192.168.50.0/24",
			Fallthrough: FallthroughContinue},
	}

	if err := s.CheckGroups(context.Background(), groups); err != nil {
		t.Fatalf("um erro de leitura do NTP reprovou o grupo do admin: %v", err)
	}
	inp := scriptFor(t, exec.checkScripts, InputChain)
	if !strings.Contains(inp, "jump grp_iii") {
		t.Errorf("o jump do grupo deixou de ser validado:\n%s", inp)
	}
	if strings.Contains(inp, "dport 123") {
		t.Errorf("o estado do NTP não pôde ser lido, então nenhuma linha de NTP podia ser inventada:\n%s", inp)
	}
}

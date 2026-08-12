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

// ─── forwardChainRules: a inversão da §3 ─────────────────────────────────

// A inversão da spec §3: bloqueio administrativo é avaliado ANTES dos
// grupos do admin e sempre vence. Até a Fase B era o contrário — um
// "permitir" do usuário anulava a lista de bloqueio — e ninguém percebia.
func TestForwardChainPutsBlocksBeforeGroupJumps(t *testing.T) {
	groups := []StoredGroup{
		{ID: "a", ChainName: "grp_aaa", Enabled: true, Position: 0, CondSaddr: "192.168.50.0/24"},
		{ID: "b", ChainName: "grp_bbb", Enabled: true, Position: 1},
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

// Os quatro bloqueios continuam existindo, na mesma forma que a produção já
// tem desde junho de 2026 — a inversão muda a POSIÇÃO deles, não o conteúdo.
func TestForwardChainKeepsTheFourAdministrativeBlocks(t *testing.T) {
	lines := forwardLines(nil)
	want := []string{
		"ip saddr @blocked_hosts counter drop",
		"ip daddr @blocked_hosts counter drop",
		"ip daddr @blocklist counter drop",
		"ip saddr @blocklist counter drop",
	}
	if len(lines) != len(want) {
		t.Fatalf("sem grupos a forward deveria ter só os 4 bloqueios, tem %d:\n%v", len(lines), lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("linha %d = %q, queria %q", i, lines[i], want[i])
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
			!strings.Contains(joined, ForwardChain) && !strings.Contains(joined, GroupChainPrefix) {
			t.Fatalf("deu flush numa chain que não é dos grupos nem a forward: %q", joined)
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

// ReconcileGroups(ctx, nil) reduz a forward aos 4 bloqueios e apaga TODAS as
// chains de grupo. É o comportamento correto para "o admin não tem nenhum
// grupo" — e é indistinguível, aqui dentro, de um chamador que engoliu o
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
// (não só na função pura): bloqueios primeiro, depois os jumps na ordem que o
// admin configurou.
func TestReconcileGroupsForwardCommandOrder(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	groups := []StoredGroup{
		{ID: "b", Name: "Servidores", ChainName: "grp_bbb", Enabled: true, Position: 5,
			CondSaddr: "192.168.3.10", Fallthrough: FallthroughContinue},
		{ID: "a", Name: "Visitantes", ChainName: "grp_aaa", Enabled: true, Position: 1,
			CondSaddr: "192.168.50.0/24", Fallthrough: FallthroughDrop},
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
	groups := []StoredGroup{
		{ID: "a", Name: "Visitantes", ChainName: "grp_aaa", Enabled: true, Position: 0,
			Fallthrough: FallthroughContinue,
			Rules: []StoredRule{{ID: "r1", Enabled: true,
				Fields: RuleFields{Action: "accept", Proto: "tcp", Dport: "443"}}}},
		{ID: "b", Name: "Servidores", ChainName: "grp_bbb", Enabled: true, Position: 1,
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

// A validação prévia (`nft -c`) tem que passar exatamente pelo que a
// reconciliação de verdade vai emitir depois — mesma renderização, mesma
// ordem, chain do grupo E forward — senão ela aprova uma coisa e o firewall
// recebe outra.
func TestCheckGroupsValidatesEveryGroupChainAndTheForward(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	groups := []StoredGroup{
		{ID: "a", Name: "Visitantes", ChainName: "grp_aaa", Enabled: true, Position: 0,
			CondSaddr: "192.168.50.0/24", Fallthrough: FallthroughDrop,
			Rules: []StoredRule{{ID: "r", Position: 0, Enabled: true,
				Fields: RuleFields{Action: "accept", Proto: "tcp", Dport: "443"}}}},
		{ID: "b", Name: "Servidores", ChainName: "grp_bbb", Enabled: true, Position: 1,
			Fallthrough: FallthroughContinue},
	}

	if err := s.CheckGroups(context.Background(), groups); err != nil {
		t.Fatalf("CheckGroups: %v", err)
	}
	if len(exec.executed) != 0 {
		t.Fatalf("a validação prévia não pode mudar nada no firewall, rodou: %v", exec.executed)
	}
	if len(exec.checkScripts) != 3 {
		t.Fatalf("esperava 3 validações (duas chains de grupo + forward), vieram %d", len(exec.checkScripts))
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
	fwd := exec.checkScripts[len(exec.checkScripts)-1]
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
	if len(exec.checkScripts) != 2 {
		t.Fatalf("esperava 2 validações (chain do grupo + forward), vieram %d", len(exec.checkScripts))
	}

	// 1. no script da própria chain do grupo: add chain antes do flush.
	own := exec.checkScripts[0]
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
	fwd := exec.checkScripts[1]
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

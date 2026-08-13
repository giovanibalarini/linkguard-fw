package firewallrules

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// inputGroup é a mudança perigosa destes testes: um grupo que age no tráfego
// DESTINADO ao firewall. É exatamente a classe de mudança que pode tirar o
// SSH e o painel do operador de uma máquina remota — e por isso a única que
// passa pelo confirmar-ou-reverte.
func inputGroup(t *testing.T, db *storage.DB, id, name string) storage.FirewallGroup {
	t.Helper()
	existing, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatalf("ListFirewallGroups: %v", err)
	}
	g := storage.FirewallGroup{
		ID:          id,
		Name:        name,
		ChainName:   nftables.GroupChainName(id),
		Position:    len(existing),
		Enabled:     true,
		Fallthrough: nftables.FallthroughContinue,
		Kind:        nftables.GroupKindAdmin,
		Scope:       nftables.ScopeInput,
	}
	if err := db.CreateFirewallGroup(&g); err != nil {
		t.Fatalf("CreateFirewallGroup: %v", err)
	}
	return g
}

func groupNames(t *testing.T, db *storage.DB) []string {
	t.Helper()
	groups, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatalf("ListFirewallGroups: %v", err)
	}
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		out = append(out, g.Name)
	}
	return out
}

// mutatingCommands devolve os comandos de MUTAÇÃO que o nft recebeu, já
// formatados para o texto do erro. Leitura (ExecuteRead) não entra: o
// migrateExec só registra Execute, que é o caminho que muda o firewall vivo.
func mutatingCommands(exec *migrateExec) []string {
	out := make([]string, 0, len(exec.executed))
	for _, args := range exec.executed {
		out = append(out, strings.Join(args, " "))
	}
	return out
}

// O pendente mora no banco, não num timer em memória. Sem isso, um reboot
// dentro da janela deixaria valendo para sempre uma regra não confirmada que
// pode ter trancado o operador — e aí não há volta remota.
func TestPendingChangeSurvivesRestart(t *testing.T) {
	db := newTestDB(t)
	svc := newTestService(t, db)
	ctx := context.Background()

	if err := svc.OpenConfirmWindow(ctx, `{"groups":[]}`, "admin", "grupo X aplicado"); err != nil {
		t.Fatalf("abrir janela: %v", err)
	}
	// simula o processo morrendo e voltando: novo serviço, mesmo banco
	svc2 := newTestService(t, db)
	p := svc2.PendingChange()
	if p == nil {
		t.Fatal("o pendente tem que sobreviver ao restart do processo")
	}
	if p.Snapshot == "" {
		t.Error("sem o snapshot não há para onde reverter")
	}
}

// Confirmar limpa o pendente e NÃO mexe no firewall — o que está valendo já
// é o estado desejado. Assere sobre o executor: zero comandos de mutação
// saíram. Uma reconciliação "por garantia" no confirmar seria um flush e uma
// reescrita da chain input no exato instante em que o operador acabou de
// provar que ainda tem acesso — uma janela de risco criada do nada, pela
// linha que existia para não fazer nada.
func TestConfirmClearsWithoutTouchingTheFirewall(t *testing.T) {
	db := newTestDB(t)
	svc, exec := newBootedService(t, db)
	ctx := context.Background()

	before, err := svc.SnapshotState()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	inputGroup(t, db, "aaaaaaaa-0000-4000-8000-000000000001", "Trava SSH")
	if err := svc.OpenConfirmWindow(ctx, before, "admin", "grupo Trava SSH aplicado"); err != nil {
		t.Fatalf("abrir janela: %v", err)
	}

	if err := svc.ConfirmPending(ctx); err != nil {
		t.Fatalf("confirmar: %v", err)
	}

	if p := svc.PendingChange(); p != nil {
		t.Errorf("confirmar tem que apagar o pendente, ainda há um: %+v", p)
	}
	if cmds := mutatingCommands(exec); len(cmds) != 0 {
		t.Errorf("confirmar não pode emitir comando de mutação no nft, emitiu: %v", cmds)
	}
	// E o grupo aplicado continua valendo: confirmar é aceitar, não desfazer.
	if names := groupNames(t, db); !contains(names, "Trava SSH") {
		t.Errorf("o grupo confirmado sumiu do banco: %v", names)
	}
}

// Reverter restaura o estado anterior dos grupos e reconcilia. Não é
// flush ruleset nem restauração de snapshot inteiro: `flush ruleset` destrói
// as tabelas de terceiros que dividem o kernel com a nossa (é a dívida que
// Service.Restore ainda carrega, e que este caminho não pode repetir).
func TestRevertRestoresTheGroupsAndReconciles(t *testing.T) {
	db := newTestDB(t)
	svc, exec := newBootedService(t, db)
	ctx := context.Background()

	antes := groupNames(t, db)
	before, err := svc.SnapshotState()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	// o admin aplica a mudança arriscada
	g := inputGroup(t, db, "aaaaaaaa-0000-4000-8000-000000000002", "Trava painel")
	if err := db.CreateFirewallRule(&storage.FirewallRule{
		GroupID: g.ID, Action: "drop", Proto: "tcp", Dport: "9997",
	}); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}
	if err := svc.OpenConfirmWindow(ctx, before, "admin", "grupo Trava painel aplicado"); err != nil {
		t.Fatalf("abrir janela: %v", err)
	}
	exec.executed = nil

	if err := svc.RevertPending(ctx); err != nil {
		t.Fatalf("reverter: %v", err)
	}

	if got := groupNames(t, db); strings.Join(got, "|") != strings.Join(antes, "|") {
		t.Errorf("os grupos não voltaram ao estado anterior:\n  obtive %v\n  queria %v", got, antes)
	}
	rules, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("a regra aplicada dentro da janela tinha que ter voltado junto, sobraram %d: %+v", len(rules), rules)
	}
	if p := svc.PendingChange(); p != nil {
		t.Errorf("reverter tem que apagar o pendente, ainda há um: %+v", p)
	}

	// Reconciliou — e SÓ nas nossas chains. A verificação é uma lista branca
	// de verbos, não uma busca por "flush ruleset": o caminho proibido de
	// verdade é nftables.Service.Restore, e ele nem escreve `flush ruleset`
	// no argv — escreve num arquivo temporário e chama `nft -f <arquivo>`.
	// Procurar só pelo texto deixaria passar justamente a dívida que este
	// mecanismo não pode repetir (`flush ruleset` destrói as tabelas de
	// terceiros que dividem o kernel com a nossa).
	flushedChain := false
	for _, args := range exec.executed {
		if len(args) == 0 {
			continue
		}
		switch args[0] {
		case "flush":
			if len(args) < 2 || args[1] != "chain" {
				t.Fatalf("PROIBIDO: reverter só pode dar flush em chain nossa, emitiu: %v", args)
			}
			flushedChain = true
		case "add", "delete":
			// as chains e regras do LinkGuard: é o que reconciliar significa
		default:
			t.Fatalf("PROIBIDO: comando inesperado na reversão (`nft -f` carrega o ruleset inteiro e é o caminho que este mecanismo não pode tomar): %v", args)
		}
	}
	if !flushedChain {
		t.Errorf("reverter tem que reconciliar (flush chain + regras); comandos emitidos: %v", mutatingCommands(exec))
	}
}

// Expirada, a janela reverte sozinha na próxima verificação — inclusive a
// que roda no boot. O relógio é injetado: um teste que dorme 90 segundos é um
// teste que ninguém roda, e a expiração deixaria de ter cobertura.
func TestExpiredWindowRevertsOnCheck(t *testing.T) {
	db := newTestDB(t)
	svc, exec := newBootedService(t, db)
	ctx := context.Background()

	base := time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return base }

	antes := groupNames(t, db)
	before, err := svc.SnapshotState()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	inputGroup(t, db, "aaaaaaaa-0000-4000-8000-000000000003", "Trava SSH")
	if err := svc.OpenConfirmWindow(ctx, before, "admin", "grupo Trava SSH aplicado"); err != nil {
		t.Fatalf("abrir janela: %v", err)
	}

	// dentro da janela: a verificação não pode reverter nada
	svc.now = func() time.Time { return base.Add(ConfirmWindow - time.Second) }
	if err := svc.CheckPendingExpired(ctx); err != nil {
		t.Fatalf("verificação dentro da janela: %v", err)
	}
	if svc.PendingChange() == nil {
		t.Fatal("a janela ainda não expirou; reverter aqui tiraria do operador o tempo que ele tem para confirmar")
	}
	if names := groupNames(t, db); !contains(names, "Trava SSH") {
		t.Fatalf("o grupo foi revertido antes da hora: %v", names)
	}
	exec.executed = nil

	// um segundo depois do prazo: reverte sozinha
	svc.now = func() time.Time { return base.Add(ConfirmWindow + time.Second) }
	if err := svc.CheckPendingExpired(ctx); err != nil {
		t.Fatalf("verificação depois do prazo: %v", err)
	}
	if p := svc.PendingChange(); p != nil {
		t.Errorf("a janela expirada tem que sumir do banco depois de revertida, ainda há: %+v", p)
	}
	if got := groupNames(t, db); strings.Join(got, "|") != strings.Join(antes, "|") {
		t.Errorf("a janela expirou e os grupos não voltaram:\n  obtive %v\n  queria %v", got, antes)
	}
	if len(exec.executed) == 0 {
		t.Error("a reversão automática tem que reconciliar o nft, nenhum comando foi emitido")
	}
}

// No boot, um pendente é revertido MESMO que ainda não tenha expirado. O
// operador não estava lá para confirmar, e um reboot dentro da janela
// normalmente significa que a máquina caiu POR CAUSA da mudança (decisão
// registrada na spec §5.1). Tratar "ainda não expirou" como "deixa valer"
// seria deixar de pé, para sempre, a regra que pode ter trancado o operador.
func TestBootRevertsAnUnconfirmedChangeEvenBeforeItExpires(t *testing.T) {
	db := newTestDB(t)
	svc, exec := newBootedService(t, db)
	ctx := context.Background()

	base := time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return base }

	antes := groupNames(t, db)
	before, err := svc.SnapshotState()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	inputGroup(t, db, "aaaaaaaa-0000-4000-8000-000000000004", "Trava SSH")
	if err := svc.OpenConfirmWindow(ctx, before, "admin", "grupo Trava SSH aplicado"); err != nil {
		t.Fatalf("abrir janela: %v", err)
	}
	exec.executed = nil

	// a máquina reiniciou 10 segundos depois: a janela ainda estaria correndo
	alerter := &recordingAlerter{}
	svc.SetAlerter(alerter)
	svc.now = func() time.Time { return base.Add(10 * time.Second) }
	if err := svc.RevertPendingOnBoot(ctx); err != nil {
		t.Fatalf("verificação de boot: %v", err)
	}

	if p := svc.PendingChange(); p != nil {
		t.Errorf("o pendente tinha que ter sido resolvido no boot, ainda há: %+v", p)
	}
	if got := groupNames(t, db); strings.Join(got, "|") != strings.Join(antes, "|") {
		t.Errorf("o boot não reverteu a mudança não confirmada:\n  obtive %v\n  queria %v", got, antes)
	}
	if len(alerter.reverted) != 1 {
		t.Errorf("o operador tem que encontrar um alerta explicando o que foi revertido e por quê, obtive %v", alerter.reverted)
	} else if !strings.Contains(alerter.reverted[0], "Trava SSH aplicado") {
		t.Errorf("o alerta tem que dizer O QUE foi revertido, obtive %q", alerter.reverted[0])
	}
	if len(exec.executed) == 0 {
		t.Error("a reversão no boot tem que reconciliar o nft, nenhum comando foi emitido")
	}
}

// Sem pendente, a verificação de boot é um no-op silencioso: nenhum comando
// no nft, nenhum alerta. É o caso de todo boot normal, e um alerta aqui
// treinaria o operador a ignorar os alertas de verdade.
func TestBootCheckIsANoopWithoutAPendingChange(t *testing.T) {
	db := newTestDB(t)
	svc, exec := newBootedService(t, db)
	alerter := &recordingAlerter{}
	svc.SetAlerter(alerter)

	if err := svc.RevertPendingOnBoot(context.Background()); err != nil {
		t.Fatalf("verificação de boot sem pendente: %v", err)
	}
	if cmds := mutatingCommands(exec); len(cmds) != 0 {
		t.Errorf("boot sem pendente não pode tocar no nft, emitiu: %v", cmds)
	}
	if len(alerter.reverted) != 0 {
		t.Errorf("boot sem pendente não pode alertar, alertou: %v", alerter.reverted)
	}
}

// Abrir uma janela com outra já aberta é ERRO, não empilhamento: com dois
// pendentes, "reverter ao estado anterior" não tem resposta — anterior a qual
// das duas mudanças? A trava é do próprio banco (uma linha no máximo).
func TestOpeningASecondWindowIsRefused(t *testing.T) {
	db := newTestDB(t)
	svc := newTestService(t, db)
	ctx := context.Background()

	if err := svc.OpenConfirmWindow(ctx, `{"groups":[]}`, "admin", "primeira"); err != nil {
		t.Fatalf("abrir a primeira janela: %v", err)
	}
	if err := svc.OpenConfirmWindow(ctx, `{"groups":[]}`, "admin", "segunda"); err == nil {
		t.Fatal("abrir uma segunda janela tinha que falhar; empilhar pendentes torna a reversão ambígua")
	}
	p := svc.PendingChange()
	if p == nil || p.Summary != "primeira" {
		t.Errorf("a janela em aberto tem que continuar sendo a primeira, obtive %+v", p)
	}
}

// A contagem regressiva do painel sai daqui: expires_at é do servidor e vale
// 90 segundos (spec §5). Um relógio local reiniciaria a cada F5 e mentiria
// sobre quanto tempo ainda resta para confirmar.
func TestOpenConfirmWindowUsesTheServerClockAndNinetySeconds(t *testing.T) {
	db := newTestDB(t)
	svc := newTestService(t, db)

	base := time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return base }

	if err := svc.OpenConfirmWindow(context.Background(), `{"groups":[]}`, "gov", "grupo X"); err != nil {
		t.Fatalf("abrir janela: %v", err)
	}
	p := svc.PendingChange()
	if p == nil {
		t.Fatal("sem pendente depois de abrir a janela")
	}
	if got := p.ExpiresAt.Unix(); got != base.Add(90*time.Second).Unix() {
		t.Errorf("expires_at = %v, queria %v (90 s a partir do relógio do servidor)",
			p.ExpiresAt.UTC(), base.Add(90*time.Second).UTC())
	}
	if p.AppliedBy != "gov" {
		t.Errorf("quem aplicou = %q, queria %q", p.AppliedBy, "gov")
	}
}

// Reverter para um snapshot sem nenhum grupo é recusado: obedecê-lo esvaziaria
// a chain forward por completo — inclusive os bloqueios administrativos, que
// desde a Fase C1 também são itens da lista — e apagaria todas as chains grp_.
// Nenhum snapshot legítimo é assim; um que seja é corrupção, e derrubar o
// firewall inteiro em nome de uma reversão de segurança é o oposto do que este
// mecanismo existe para fazer.
func TestRevertRefusesAnEmptySnapshotInsteadOfWipingTheFirewall(t *testing.T) {
	db := newTestDB(t)
	svc, exec := newBootedService(t, db)
	ctx := context.Background()

	antes := groupNames(t, db)
	if err := svc.OpenConfirmWindow(ctx, `{"groups":[]}`, "admin", "snapshot corrompido"); err != nil {
		t.Fatalf("abrir janela: %v", err)
	}
	exec.executed = nil

	if err := svc.RevertPending(ctx); err == nil {
		t.Fatal("reverter para um snapshot vazio tinha que falhar, não apagar o firewall")
	}
	if got := groupNames(t, db); strings.Join(got, "|") != strings.Join(antes, "|") {
		t.Errorf("os grupos foram apagados por um snapshot vazio:\n  obtive %v\n  queria %v", got, antes)
	}
	if cmds := mutatingCommands(exec); len(cmds) != 0 {
		t.Errorf("uma reversão recusada não pode ter tocado no nft, emitiu: %v", cmds)
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

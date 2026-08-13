package firewallrules

import (
	"context"
	"errors"
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

// pending lê a janela em aberto. Só existe PendingChangeOrError (I-4): a
// forma que engolia o erro de leitura e devolvia nil foi apagada, porque
// "não sei" mostrado como "não há" some com a faixa de confirmação da tela do
// operador e libera a mutação que ela existe para travar.
func pending(t *testing.T, svc *Service) *storage.PendingChange {
	t.Helper()
	p, err := svc.PendingChangeOrError()
	if err != nil {
		t.Fatalf("PendingChangeOrError: %v", err)
	}
	return p
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
	svc, _ := newBootedService(t, db)
	ctx := context.Background()

	snapshot, err := svc.SnapshotState()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if err := svc.OpenConfirmWindow(ctx, snapshot, "admin", "grupo X aplicado"); err != nil {
		t.Fatalf("abrir janela: %v", err)
	}
	// simula o processo morrendo e voltando: novo serviço, mesmo banco
	svc2 := newTestService(t, db)
	p := pending(t, svc2)
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

	if p := pending(t, svc); p != nil {
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
	if p := pending(t, svc); p != nil {
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

	// m-5: e o EFEITO que importa para o operador — o `jump` do grupo
	// perigoso tem que ter sumido da chain input reconstruída. Tudo o mais
	// que este teste olha (grupos no banco, pendente apagado, houve flush)
	// pode estar certo com a chain input viva ainda mandando todo o tráfego
	// destinado ao firewall para dentro do grupo que trancou o operador: a
	// chain input é reconstruída a partir da lista de grupos, e é justamente
	// aí que uma reversão pela metade não aparece em nenhuma outra asserção.
	if !rebuiltChain(exec, nftables.InputChain) {
		t.Fatalf("a chain input tinha que ter sido reconstruída na reversão (é ela que carrega os jumps dos grupos de escopo input); comandos: %v",
			mutatingCommands(exec))
	}
	for _, args := range exec.executed {
		if !isAddRuleTo(args, nftables.InputChain) {
			continue
		}
		for _, tok := range args {
			if tok == g.ChainName {
				t.Errorf("a chain input reconstruída ainda pula para o grupo revertido (%s): a reversão não desfez o que trancaria o operador -- comando: %v",
					g.ChainName, strings.Join(args, " "))
			}
		}
	}
}

// rebuiltChain diz se a chain nomeada foi reconstruída nesta passada (o
// `flush chain` que abre a reconstrução).
func rebuiltChain(exec *migrateExec, chain string) bool {
	for _, args := range exec.executed {
		if len(args) >= 5 && args[0] == "flush" && args[1] == "chain" && args[4] == chain {
			return true
		}
	}
	return false
}

// isAddRuleTo diz se o comando é `add rule <family> <table> <chain> …`.
func isAddRuleTo(args []string, chain string) bool {
	return len(args) >= 5 && args[0] == "add" && args[1] == "rule" && args[4] == chain
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
	if pending(t, svc) == nil {
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
	if p := pending(t, svc); p != nil {
		t.Errorf("a janela expirada tem que sumir do banco depois de revertida, ainda há: %+v", p)
	}
	if got := groupNames(t, db); strings.Join(got, "|") != strings.Join(antes, "|") {
		t.Errorf("a janela expirou e os grupos não voltaram:\n  obtive %v\n  queria %v", got, antes)
	}
	if len(exec.executed) == 0 {
		t.Error("a reversão automática tem que reconciliar o nft, nenhum comando foi emitido")
	}
}

// I-3. A expiração não pode depender SÓ do relógio de parede, porque esta
// máquina É o servidor NTP da rede e o chrony do Debian vem com `makestep`
// ligado: um passo do relógio PARA TRÁS maior que a janela (RTC ruim depois de
// troca de disco, `timedatectl set-time`, o primeiro sync depois de subir)
// empurra o expires_at gravado para o futuro. Sem um prazo monotônico, o
// auto-revert simplesmente não dispara — e o operador fica trancado fora sem
// poder confirmar (não tem acesso) nem esperar (o prazo fugiu).
func TestTheWindowExpiresEvenWhenTheClockJumpsBackwards(t *testing.T) {
	db := newTestDB(t)
	svc, _ := newBootedService(t, db)
	ctx := context.Background()

	wall := time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC)
	mono := time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return wall }
	svc.monoNow = func() time.Time { return mono }

	antes := groupNames(t, db)
	before, err := svc.SnapshotState()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	inputGroup(t, db, "aaaaaaaa-0000-4000-8000-000000000009", "Trava SSH")
	if err := svc.OpenConfirmWindow(ctx, before, "admin", "grupo Trava SSH aplicado"); err != nil {
		t.Fatalf("abrir janela: %v", err)
	}

	// o chrony dá um passo de 10 minutos PARA TRÁS enquanto a janela corre; o
	// expires_at gravado (wall + 90 s) passa a estar 11min30 no futuro
	wall = wall.Add(-10 * time.Minute)
	// e o tempo real segue andando: 91 segundos desde que a janela abriu
	mono = mono.Add(ConfirmWindow + time.Second)

	if err := svc.CheckPendingExpired(ctx); err != nil {
		t.Fatalf("verificação depois do salto de relógio: %v", err)
	}
	if p := pending(t, svc); p != nil {
		t.Fatalf("a janela tinha que ter expirado pelo relógio monotônico: um passo do NTP para trás não pode adiar para sempre a reversão que devolve o acesso ao operador; pendente ainda em aberto: %+v", p)
	}
	if got := groupNames(t, db); strings.Join(got, "|") != strings.Join(antes, "|") {
		t.Errorf("a janela expirou e os grupos não voltaram:\n  obtive %v\n  queria %v", got, antes)
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

	if p := pending(t, svc); p != nil {
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
	svc, _ := newBootedService(t, db)
	ctx := context.Background()

	snapshot, err := svc.SnapshotState()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if err := svc.OpenConfirmWindow(ctx, snapshot, "admin", "primeira"); err != nil {
		t.Fatalf("abrir a primeira janela: %v", err)
	}
	if err := svc.OpenConfirmWindow(ctx, snapshot, "admin", "segunda"); err == nil {
		t.Fatal("abrir uma segunda janela tinha que falhar; empilhar pendentes torna a reversão ambígua")
	}
	p := pending(t, svc)
	if p == nil || p.Summary != "primeira" {
		t.Errorf("a janela em aberto tem que continuar sendo a primeira, obtive %+v", p)
	}
}

// A contagem regressiva do painel sai daqui: expires_at é do servidor e vale
// 90 segundos (spec §5). Um relógio local reiniciaria a cada F5 e mentiria
// sobre quanto tempo ainda resta para confirmar.
func TestOpenConfirmWindowUsesTheServerClockAndNinetySeconds(t *testing.T) {
	db := newTestDB(t)
	svc, _ := newBootedService(t, db)

	base := time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return base }

	snapshot, err := svc.SnapshotState()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if err := svc.OpenConfirmWindow(context.Background(), snapshot, "gov", "grupo X"); err != nil {
		t.Fatalf("abrir janela: %v", err)
	}
	p := pending(t, svc)
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
	// m-4: created_at sai do MESMO relógio injetado, não de um time.Now() cru
	// lá dentro do repositório. Dois relógios diferentes na mesma linha fazem
	// "aberta às 03:00, expira às 02:31" — e é esse par que o painel usa para
	// desenhar quanto já passou.
	if got := p.CreatedAt.UTC(); !got.Equal(base) {
		t.Errorf("created_at = %v, queria %v (o mesmo relógio de que sai o expires_at)", got, base)
	}
}

// I-1. Abrir janela com um snapshot que a REVERSÃO vai recusar é armar uma
// rede de proteção que nunca pode disparar: 90 segundos depois o watchdog
// tenta reverter, é recusado, e continua sendo recusado para sempre — com a
// regra perigosa valendo. A hora de falhar é antes de aplicar.
func TestOpenConfirmWindowRefusesASnapshotTheRevertWouldReject(t *testing.T) {
	db := newTestDB(t)
	svc, _ := newBootedService(t, db)
	ctx := context.Background()

	// (a) sem nenhum grupo — o formato que ReplaceFirewallGroupsAndRules
	// recusa, e que SnapshotState produz se ListFirewallGroups voltar vazio.
	if err := svc.OpenConfirmWindow(ctx, `{"groups":[],"rules":[]}`, "admin", "grupo X"); err == nil {
		t.Error("abrir janela com snapshot sem grupos tinha que falhar: a reversão dela seria recusada para sempre")
	}
	// (b) com grupo do admin mas SEM os dois do sistema — passa pela guarda
	// de "lista vazia" e ainda assim é irreversível (restaurá-lo apagaria os
	// bloqueios administrativos, e nada os recria).
	semSistema := `{"groups":[{"id":"g1","name":"Minhas regras","chain_name":"grp_g1","kind":"admin"}],"rules":[]}`
	if err := svc.OpenConfirmWindow(ctx, semSistema, "admin", "grupo X"); err == nil {
		t.Error("abrir janela com snapshot sem os grupos do sistema tinha que falhar: restaurá-lo apagaria os bloqueios administrativos e travaria toda reconciliação da máquina")
	}
	if p := pending(t, svc); p != nil {
		t.Errorf("nenhuma janela podia ter sido aberta, há uma: %+v", p)
	}
}

// Reverter para um snapshot sem nenhum grupo é recusado: obedecê-lo esvaziaria
// a chain forward por completo — inclusive os bloqueios administrativos, que
// desde a Fase C1 também são itens da lista — e apagaria todas as chains grp_.
// Nenhum snapshot legítimo é assim; um que seja é corrupção, e derrubar o
// firewall inteiro em nome de uma reversão de segurança é o oposto do que este
// mecanismo existe para fazer.
//
// O pendente é gravado DIRETO no banco de propósito: desde I-1 o
// OpenConfirmWindow recusa esse snapshot, e a única forma de ele chegar aqui é
// corrupção da linha (ou uma versão anterior que o gravou). É exatamente esse
// caso que esta guarda cobre — a de OpenConfirmWindow não a substitui.
func TestRevertRefusesAnEmptySnapshotInsteadOfWipingTheFirewall(t *testing.T) {
	db := newTestDB(t)
	svc, exec := newBootedService(t, db)
	ctx := context.Background()

	antes := groupNames(t, db)
	if err := db.SavePendingChange(storage.PendingChange{
		ID:        "corrompido",
		Snapshot:  `{"groups":[]}`,
		ExpiresAt: time.Now().Add(ConfirmWindow),
		AppliedBy: "admin",
		Summary:   "snapshot corrompido",
	}); err != nil {
		t.Fatalf("SavePendingChange: %v", err)
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
	if p := pending(t, svc); p == nil {
		t.Error("o pendente tem que FICAR quando a reversão é recusada: apagá-lo tiraria da tela a faixa que ainda deixa o operador confirmar")
	}
}

// ─── C-1: a reversão não pode apagar a própria rede de proteção ───────────

// TestARevertThatCannotReachNftKeepsThePendingAndHealsItself é o teste do
// furo mais grave desta fase.
//
// A reversão apagava o pendente ANTES de saber se o nft tinha aceitado. Quando
// o Reconcile falhava, o resultado era: banco revertido, pendente apagado,
// REGRA PERIGOSA AINDA VIVA no firewall, watchdog sem nada para observar
// (WatchPending só age quando há linha na tabela), faixa do painel sumindo da
// tela — e nada, em lugar nenhum do sistema, tentando de novo. O operador
// ficava trancado fora da máquina para sempre.
//
// E não é azar: RevertPendingOnBoot roda ANTES do EnsureTable, então numa
// máquina cuja tabela `inet linkguard` precisou ser recriada (recuperação de
// desastre, 2026-08-10) esse Reconcile falha de forma determinística. Falha
// também quando a leitura do estado do NTP falha — e nesse caso a chain input
// não é sequer tocada, isto é, justamente a chain que contém a regra que
// trancou o operador.
//
// O que este teste prova, na ordem: primeira passada com o nft recusando →
// erro E o pendente PERMANECE; segunda passada com o nft de volta → a reversão
// se completa sozinha, o jump do grupo perigoso sai da chain input, e só então
// o pendente é apagado.
func TestARevertThatCannotReachNftKeepsThePendingAndHealsItself(t *testing.T) {
	db := newTestDB(t)
	svc, exec := newBootedService(t, db)
	alerter := &recordingAlerter{}
	svc.SetAlerter(alerter)
	ctx := context.Background()

	base := time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return base }

	antes := groupNames(t, db)
	before, err := svc.SnapshotState()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	g := inputGroup(t, db, "aaaaaaaa-0000-4000-8000-000000000005", "Trava SSH")
	if err := db.CreateFirewallRule(&storage.FirewallRule{
		GroupID: g.ID, Action: "drop", Proto: "tcp", Dport: "22",
	}); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}
	if err := svc.OpenConfirmWindow(ctx, before, "admin", "grupo Trava SSH aplicado"); err != nil {
		t.Fatalf("abrir janela: %v", err)
	}

	// ── primeira passada: o nft recusa (tabela recém-recriada, EBUSY, …)
	busy := errors.New("Device or resource busy")
	exec.failOn = func(args []string) error {
		if len(args) > 0 && args[0] == "flush" {
			return busy
		}
		return nil
	}
	svc.now = func() time.Time { return base.Add(ConfirmWindow + time.Second) }
	err = svc.CheckPendingExpired(ctx)
	if err == nil {
		t.Fatal("com o nft recusando, a reversão tinha que reportar erro")
	}
	p := pending(t, svc)
	if p == nil {
		t.Fatal("FURO: o pendente foi apagado mesmo com a reconciliação falhando -- a regra perigosa continua viva no nft, o watchdog fica sem nada para observar (WatchPending só age quando há linha na tabela) e ninguém mais tenta de novo: o operador fica trancado fora da máquina para sempre")
	}
	// O banco já está no estado anterior — é a reversão em andamento, não uma
	// reversão que não aconteceu.
	if got := groupNames(t, db); strings.Join(got, "|") != strings.Join(antes, "|") {
		t.Errorf("o lado banco da reversão tinha que ter acontecido:\n  obtive %v\n  queria %v", got, antes)
	}
	// E confirmar deixa de ser possível: o estado anterior já saiu do banco.
	if err := svc.ConfirmPending(ctx); err == nil {
		t.Error("confirmar uma mudança cuja reversão já começou tinha que falhar: o estado anterior já voltou ao banco, e 'confirmar' deixaria banco e nft em estados diferentes")
	}

	// ── segunda passada: o nft voltou. A reversão se auto-cura.
	exec.failOn = nil
	exec.executed = nil
	if err := svc.CheckPendingExpired(ctx); err != nil {
		t.Fatalf("com o nft de volta, a reversão tinha que se completar sozinha: %v", err)
	}
	if p := pending(t, svc); p != nil {
		t.Errorf("concluída a reversão, o pendente tem que sumir; ainda há: %+v", p)
	}
	if !rebuiltChain(exec, nftables.InputChain) {
		t.Fatalf("a segunda passada tinha que reconstruir a chain input; comandos: %v", mutatingCommands(exec))
	}
	for _, args := range exec.executed {
		if !isAddRuleTo(args, nftables.InputChain) {
			continue
		}
		for _, tok := range args {
			if tok == g.ChainName {
				t.Errorf("a chain input reconstruída ainda pula para o grupo revertido (%s): %v", g.ChainName, strings.Join(args, " "))
			}
		}
	}
	// Um alerta só, e não um por tentativa: a reversão é um evento, não uma
	// batida de relógio.
	if len(alerter.reverted) != 1 {
		t.Errorf("a reversão tinha que alertar UMA vez (a retomada não é um evento novo para o operador), obtive %d: %v", len(alerter.reverted), alerter.reverted)
	}
}

// m-7: se a expiração ganha a corrida por um segundo, o operador que aperta
// "Confirmar" merece saber o que aconteceu. "Não há mudança aguardando
// confirmação" soa como "você já confirmou" — a leitura errada no pior
// momento possível, porque ele vai embora achando que a alteração ficou.
func TestConfirmAfterTheWindowExpiredSaysItWasReverted(t *testing.T) {
	db := newTestDB(t)
	svc, _ := newBootedService(t, db)
	ctx := context.Background()

	base := time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return base }

	before, err := svc.SnapshotState()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	inputGroup(t, db, "aaaaaaaa-0000-4000-8000-000000000006", "Trava SSH")
	if err := svc.OpenConfirmWindow(ctx, before, "admin", "grupo Trava SSH aplicado"); err != nil {
		t.Fatalf("abrir janela: %v", err)
	}

	svc.now = func() time.Time { return base.Add(ConfirmWindow + time.Second) }
	if err := svc.CheckPendingExpired(ctx); err != nil {
		t.Fatalf("expirar a janela: %v", err)
	}

	err = svc.ConfirmPending(ctx)
	if err == nil {
		t.Fatal("confirmar depois da reversão tinha que falhar")
	}
	if !strings.Contains(err.Error(), "revertida") || !strings.Contains(err.Error(), "Trava SSH aplicado") {
		t.Errorf("a mensagem tem que dizer que a mudança FOI REVERTIDA e qual era, obtive %q", err.Error())
	}
}

// O backoff da retomada. O laço nunca desiste (do outro lado pode estar o
// operador trancado fora), mas tentar de 5 em 5 segundos para sempre são ~17
// mil linhas de ERROR por dia no journal de um firewall de produção — que é
// onde alguém vai procurar a causa na próxima emergência.
func TestRevertBackoffGrowsAndIsCapped(t *testing.T) {
	interval := 5 * time.Second

	if got := nextRevertBackoff(0, interval); got != interval {
		t.Errorf("a primeira nova tentativa tem que ser no próprio intervalo do timer, obtive %v", got)
	}
	if got := nextRevertBackoff(interval, interval); got != 10*time.Second {
		t.Errorf("o backoff tem que dobrar a cada falha, obtive %v", got)
	}
	d := interval
	for i := 0; i < 40; i++ {
		d = nextRevertBackoff(d, interval)
		if d <= 0 {
			t.Fatalf("backoff não positivo na iteração %d: %v", i, d)
		}
		if d > maxRevertBackoff {
			t.Fatalf("o backoff passou do teto na iteração %d: %v > %v", i, d, maxRevertBackoff)
		}
	}
	if d != maxRevertBackoff {
		t.Errorf("depois de muitas falhas o backoff tem que estar no teto (%v), obtive %v", maxRevertBackoff, d)
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

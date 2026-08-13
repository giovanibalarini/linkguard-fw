package firewallrules

import (
	"context"
	"encoding/json"
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

// fakeClock é o par de relógios do serviço — o de PAREDE (de onde sai o
// expires_at que o painel desenha) e o MONOTÔNICO (que mede tempo decorrido).
//
// Os dois juntos, e num tipo só, porque a diferença entre eles é o que estes
// testes medem. `advance` é o tempo PASSANDO: mexe nos dois, como acontece
// numa máquina em que ninguém mexeu no relógio. `jumpWall` é o chrony dando um
// passo (`makestep`): mexe só no relógio de parede, para frente ou para trás.
// Um teste que simulasse a expiração empurrando só o relógio de parede estaria
// testando um salto de NTP, não a passagem do tempo.
type fakeClock struct {
	wall time.Time
	mono time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{wall: t, mono: t} }

func (c *fakeClock) wire(s *Service) {
	s.now = func() time.Time { return c.wall }
	s.monoNow = func() time.Time { return c.mono }
}

func (c *fakeClock) advance(d time.Duration) {
	c.wall = c.wall.Add(d)
	c.mono = c.mono.Add(d)
}

func (c *fakeClock) jumpWall(d time.Duration) { c.wall = c.wall.Add(d) }

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

	clock := newFakeClock(time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC))
	clock.wire(svc)

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
	clock.advance(ConfirmWindow - time.Second)
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
	clock.advance(2 * time.Second)
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

	clock := newFakeClock(time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC))
	clock.wire(svc)

	antes := groupNames(t, db)
	before, err := svc.SnapshotState()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	inputGroup(t, db, "aaaaaaaa-0000-4000-8000-000000000009", "Trava SSH")
	if err := svc.OpenConfirmWindow(ctx, before, "admin", "grupo Trava SSH aplicado"); err != nil {
		t.Fatalf("abrir janela: %v", err)
	}

	// o tempo real anda 91 segundos desde que a janela abriu
	clock.advance(ConfirmWindow + time.Second)
	// e o chrony dá um passo de 10 minutos PARA TRÁS: o expires_at gravado
	// (aberta + 90 s) passa a estar 10 minutos no futuro
	clock.jumpWall(-10 * time.Minute)

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

// N-6, a outra direção do mesmo `makestep`. Um passo do relógio PARA A FRENTE
// (o primeiro sync do chrony numa máquina que acabou de subir é bidirecional,
// e esta máquina É o servidor NTP da rede) ultrapassa o expires_at gravado
// antes de os 90 segundos terem PASSADO de verdade.
//
// A direção é segura — o acesso volta —, mas o operador perde o prazo sem
// aviso: ele está lendo "faltam 1:12" na tela, aperta Confirmar, e recebe "a
// mudança foi revertida automaticamente porque o prazo terminou". A contagem
// do painel mentiu, e o trabalho dele foi desfeito por um relógio, não pelo
// tempo. Enquanto houver prazo monotônico desta janela, é ele quem decide.
func TestTheWindowDoesNotEndEarlyWhenTheClockJumpsForward(t *testing.T) {
	db := newTestDB(t)
	svc, exec := newBootedService(t, db)
	ctx := context.Background()

	clock := newFakeClock(time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC))
	clock.wire(svc)

	before, err := svc.SnapshotState()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	inputGroup(t, db, "aaaaaaaa-0000-4000-8000-000000000010", "Trava SSH")
	if err := svc.OpenConfirmWindow(ctx, before, "admin", "grupo Trava SSH aplicado"); err != nil {
		t.Fatalf("abrir janela: %v", err)
	}
	exec.executed = nil

	// 2 segundos de tempo real, e o chrony dá um passo de 10 minutos PARA A
	// FRENTE: o expires_at gravado fica no passado sem que a janela tenha
	// corrido.
	clock.advance(2 * time.Second)
	clock.jumpWall(10 * time.Minute)

	if err := svc.CheckPendingExpired(ctx); err != nil {
		t.Fatalf("verificação depois do salto de relógio: %v", err)
	}
	if p := pending(t, svc); p == nil {
		t.Fatal("a janela foi encerrada por um salto do relógio para a frente: passaram 2 segundos de tempo real, e o operador tinha 90 -- ele perde a alteração sem aviso, com a contagem do painel ainda mostrando tempo de sobra")
	}
	if !contains(groupNames(t, db), "Trava SSH") {
		t.Error("os grupos foram revertidos antes de a janela ter corrido de verdade")
	}
	if cmds := mutatingCommands(exec); len(cmds) != 0 {
		t.Errorf("nada podia ter sido aplicado no nft: %v", cmds)
	}

	// E o prazo continua valendo: quando os 90 segundos passam DE VERDADE, a
	// reversão acontece.
	clock.advance(ConfirmWindow)
	if err := svc.CheckPendingExpired(ctx); err != nil {
		t.Fatalf("verificação depois do prazo real: %v", err)
	}
	if p := pending(t, svc); p != nil {
		t.Errorf("passados os 90 segundos reais, a janela tinha que ter sido revertida; ainda há: %+v", p)
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

	clock := newFakeClock(time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC))
	clock.wire(svc)

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
	clock.advance(10 * time.Second)
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

	clock := newFakeClock(time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC))
	clock.wire(svc)

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
	clock.advance(ConfirmWindow + time.Second)
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

	clock := newFakeClock(time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC))
	clock.wire(svc)

	before, err := svc.SnapshotState()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	inputGroup(t, db, "aaaaaaaa-0000-4000-8000-000000000006", "Trava SSH")
	if err := svc.OpenConfirmWindow(ctx, before, "admin", "grupo Trava SSH aplicado"); err != nil {
		t.Fatalf("abrir janela: %v", err)
	}

	clock.advance(ConfirmWindow + time.Second)
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

// ─── Segunda revisão da Fase C2 ───────────────────────────────────────────

// N-1. O furo que sobrou da primeira revisão, reproduzido como o revisor o
// descreveu: reversão travada (banco já revertido, regra perigosa ainda viva
// no nft) + LinkGuard reiniciado = um Service novo sobre o mesmo banco.
//
// Com a marca de "reversão em andamento" em memória de processo, esse Service
// novo ACEITAVA a confirmação e respondia sucesso. O pendente era apagado, a
// alteração do operador já não existia no banco, ninguém retomava a reversão do
// nft — e ele ia embora informado de que a mudança "passa a valer
// definitivamente". O cenário concreto: uma regra corta o SSH mas não o painel,
// ele confirma pelo painel, e o SSH segue bloqueado para sempre, sem watchdog e
// sem nada tentando de novo. É o modo de falha crítico da fase, alcançável por
// um simples restart.
func TestAStuckRevertCannotBeConfirmedAfterARestart(t *testing.T) {
	db := newTestDB(t)
	svc, exec := newBootedService(t, db)
	ctx := context.Background()

	clock := newFakeClock(time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC))
	clock.wire(svc)

	antes := groupNames(t, db)
	before, err := svc.SnapshotState()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	g := inputGroup(t, db, "aaaaaaaa-0000-4000-8000-000000000011", "Trava SSH")
	if err := svc.OpenConfirmWindow(ctx, before, "admin", "grupo Trava SSH aplicado"); err != nil {
		t.Fatalf("abrir janela: %v", err)
	}

	// a reversão trava no nft: o banco volta ao estado anterior, o firewall
	// vivo não
	exec.failOn = func(args []string) error {
		if len(args) > 0 && args[0] == "flush" {
			return errors.New("Device or resource busy")
		}
		return nil
	}
	clock.advance(ConfirmWindow + time.Second)
	if err := svc.CheckPendingExpired(ctx); err == nil {
		t.Fatal("com o nft recusando, a reversão tinha que reportar erro")
	}
	p := pending(t, svc)
	if p == nil {
		t.Fatal("o pendente tem que ficar: é ele que faz a reversão ser retomada")
	}
	if !p.Reverting() {
		t.Fatal("a reversão em andamento tem que estar marcada NO BANCO (reverting_at): é o que sobrevive ao restart")
	}

	// ── o LinkGuard reinicia: Service NOVO sobre o MESMO banco
	svc2, exec2 := newTestServiceWithExec(t, db)
	if err := svc2.ConfirmPending(ctx); err == nil {
		t.Fatal("FURO: um processo novo aceitou confirmar uma reversão já começada -- o pendente some, a alteração do operador já não existe no banco, ninguém retoma a reversão no nft, e ele é informado de que a mudança 'passa a valer definitivamente' com o acesso dele ainda cortado")
	} else if !strings.Contains(err.Error(), "reversão desta mudança já começou") {
		t.Errorf("a recusa tem que dizer POR QUE não dá mais para confirmar, obtive %q", err.Error())
	}

	// e o processo novo RETOMA a reversão assim que o nft aceita
	if err := svc2.CheckPendingExpired(ctx); err != nil {
		t.Fatalf("o processo novo tinha que concluir a reversão travada: %v", err)
	}
	if p := pending(t, svc2); p != nil {
		t.Errorf("concluída a reversão, o pendente tem que sumir; ainda há: %+v", p)
	}
	if got := groupNames(t, db); strings.Join(got, "|") != strings.Join(antes, "|") {
		t.Errorf("o estado anterior não voltou:\n  obtive %v\n  queria %v", got, antes)
	}
	if !rebuiltChain(exec2, nftables.InputChain) {
		t.Errorf("o processo novo tinha que reconstruir a chain input; comandos: %v", mutatingCommands(exec2))
	}
	for _, args := range exec2.executed {
		if !isAddRuleTo(args, nftables.InputChain) {
			continue
		}
		for _, tok := range args {
			if tok == g.ChainName {
				t.Errorf("a chain input reconstruída ainda pula para o grupo revertido (%s): %v", g.ChainName, strings.Join(args, " "))
			}
		}
	}
}

// N-2. A marca de "reversão em andamento" é uma AFIRMAÇÃO sobre o banco — "o
// estado anterior já está aqui" —, e por isso só pode ser gravada depois de a
// transação de restauração ter commitado.
//
// Marcada antes, ela vira mentira exatamente no caso em que a transação falha,
// com dois efeitos: confirmar passa a responder "o estado anterior já foi
// restaurado no banco" sobre um banco intocado, e a verificação de expiração
// passa a reverter antes do prazo — tirando do operador o tempo que ele ainda
// tinha para confirmar.
func TestTheRevertMarkIsOnlyWrittenAfterTheDatabaseRestoreCommits(t *testing.T) {
	db := newTestDB(t)
	svc, _ := newBootedService(t, db)
	ctx := context.Background()

	clock := newFakeClock(time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC))
	clock.wire(svc)

	// Um snapshot que PASSA na validação (tem os dois grupos do sistema) e que
	// o banco recusa no meio da transação: o mesmo grupo duas vezes viola a
	// PRIMARY KEY no segundo INSERT, e a restauração inteira volta atrás.
	raw, err := svc.SnapshotState()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	var snap stateSnapshot
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		t.Fatalf("desserializar o snapshot: %v", err)
	}
	snap.Groups = append(snap.Groups, snap.Groups[0])
	quebrado, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("serializar o snapshot: %v", err)
	}
	if err := db.SavePendingChange(storage.PendingChange{
		ID:        "restauracao-que-falha",
		Snapshot:  string(quebrado),
		ExpiresAt: clock.wall.Add(ConfirmWindow),
		AppliedBy: "admin",
		Summary:   "grupo Trava SSH aplicado",
		CreatedAt: clock.wall,
	}); err != nil {
		t.Fatalf("SavePendingChange: %v", err)
	}

	if err := svc.RevertPending(ctx); err == nil {
		t.Fatal("com a restauração falhando no banco, a reversão tinha que reportar erro")
	}
	p := pending(t, svc)
	if p == nil {
		t.Fatal("o pendente tem que ficar quando a reversão falha")
	}
	if p.Reverting() {
		t.Error("a reversão NÃO começou: a transação que restauraria o estado anterior falhou e voltou atrás -- marcar aqui faz o LinkGuard afirmar ao operador que o estado anterior já voltou ao banco, quando nada voltou")
	}

	// Consequência 1: dentro do prazo, a verificação continua deixando a
	// janela em paz. Com a marca gravada cedo demais, ela passaria a "retomar"
	// uma reversão que nunca começou, antes da hora.
	clock.advance(ConfirmWindow - time.Second)
	if err := svc.CheckPendingExpired(ctx); err != nil {
		t.Errorf("a janela ainda não expirou e nada tinha a retomar, mas a verificação agiu: %v", err)
	}
	if pending(t, svc) == nil {
		t.Fatal("a janela foi encerrada antes do prazo")
	}

	// Consequência 2: o operador ainda pode confirmar — é o que ele tem, e
	// nada foi restaurado no banco para impedi-lo.
	if err := svc.ConfirmPending(ctx); err != nil {
		t.Errorf("confirmar tinha que continuar possível: nada foi restaurado no banco. Obtive %q", err)
	}
}

// N-3. O que faz o watchdog RECUAR tem que ser uma reversão que falhou, e não
// qualquer erro.
//
// O laço tratava todo erro de CheckPendingExpired como falha de reversão,
// inclusive o SELECT do pendente falhando — e aí uma janela FUTURA vencia com o
// laço já no teto do backoff: os 90 segundos do próximo operador terminavam com
// ninguém olhando.
func TestOnlyAFailedRevertSlowsTheWatchdogDown(t *testing.T) {
	interval := 5 * time.Second

	// (a) erro de LEITURA do pendente: não há reversão nenhuma em andamento,
	// então a próxima batida do timer tenta de novo, no intervalo normal.
	db := newTestDB(t)
	svc, _ := newBootedService(t, db)
	before, err := svc.SnapshotState()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	inputGroup(t, db, "aaaaaaaa-0000-4000-8000-000000000012", "Trava SSH")
	if err := svc.OpenConfirmWindow(context.Background(), before, "admin", "grupo Trava SSH aplicado"); err != nil {
		t.Fatalf("abrir janela: %v", err)
	}
	db.Close() // o banco sai debaixo do laço: GetPendingChange passa a falhar
	readErr := svc.CheckPendingExpired(context.Background())
	if readErr == nil {
		t.Fatal("com o banco fechado, a verificação tinha que reportar erro")
	}
	if isRevertAttempt(readErr) {
		t.Errorf("um SELECT que falhou não é uma reversão que falhou: %v", readErr)
	}
	if got := nextRevertPace(readErr, 0, interval); got != 0 {
		t.Errorf("erro de leitura não pode espaçar as tentativas (obtive %v): uma janela futura venceria com o laço no teto do backoff, e os 90 segundos do próximo operador terminariam com ninguém olhando", got)
	}

	// (b) reversão que falhou de verdade: aí sim espaça, para não repetir uma
	// reconciliação inteira de 5 em 5 segundos com o nft fora do ar.
	db2 := newTestDB(t)
	svc2, exec2 := newBootedService(t, db2)
	clock := newFakeClock(time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC))
	clock.wire(svc2)
	before2, err := svc2.SnapshotState()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	inputGroup(t, db2, "aaaaaaaa-0000-4000-8000-000000000013", "Trava SSH")
	if err := svc2.OpenConfirmWindow(context.Background(), before2, "admin", "grupo Trava SSH aplicado"); err != nil {
		t.Fatalf("abrir janela: %v", err)
	}
	exec2.failOn = func(args []string) error {
		if len(args) > 0 && args[0] == "flush" {
			return errors.New("Device or resource busy")
		}
		return nil
	}
	clock.advance(ConfirmWindow + time.Second)
	revertErr := svc2.CheckPendingExpired(context.Background())
	if revertErr == nil {
		t.Fatal("com o nft recusando, a reversão tinha que reportar erro")
	}
	if !isRevertAttempt(revertErr) {
		t.Errorf("a falha de uma tentativa de reversão tem que ser reconhecida como tal: %v", revertErr)
	}
	if got := nextRevertPace(revertErr, 0, interval); got != interval {
		t.Errorf("a reversão que falhou tem que espaçar a próxima tentativa em %v, obtive %v", interval, got)
	}
}

// A cadência de LOGAR é separada da de TENTAR. Tentar é barato e cada tentativa
// pode ser a que devolve o acesso ao operador; escrever é que enche o journal
// de um firewall de produção — que é onde alguém vai procurar a causa na
// próxima emergência.
func TestTheJournalGetsTheFirstFailureAndThenOnePerMinute(t *testing.T) {
	gate := &logGate{every: revertLogInterval}
	base := time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC)

	if !gate.allow(base) {
		t.Error("a primeira falha de uma sequência tem que sair sempre: é ela que diz que algo começou a dar errado")
	}
	// 5 em 5 segundos durante um minuto: nada mais sai
	for i := 1; i < 12; i++ {
		if gate.allow(base.Add(time.Duration(i) * 5 * time.Second)) {
			t.Fatalf("a falha repetida %d saiu no journal: com um nft fora do ar por um dia isso são ~17 mil linhas de ERROR", i)
		}
	}
	if !gate.allow(base.Add(revertLogInterval)) {
		t.Error("passado um minuto, a falha que continua acontecendo tem que voltar a aparecer")
	}
	// resolvido: a próxima sequência volta a ser anunciada na hora
	gate.reset()
	if !gate.allow(base.Add(revertLogInterval + time.Second)) {
		t.Error("depois de uma passada boa, a próxima falha é a primeira de uma nova sequência e tem que sair na hora")
	}
}

// O backoff da retomada. O laço nunca desiste (do outro lado pode estar o
// operador trancado fora), e o teto é curto de propósito: o que ele custa é a
// CAUDA — o tempo que o operador continua trancado DEPOIS de a máquina já ter
// voltado a aceitar a reversão. Num componente cuja promessa inteira é "90
// segundos", o teto antigo de 5 minutos era 3,3× a promessa. O barulho no
// journal, que era a justificativa daquele teto, agora é cuidado pela cadência
// de log (ver o teste acima).
func TestRevertBackoffGrowsAndIsCapped(t *testing.T) {
	interval := 5 * time.Second

	if maxRevertBackoff > ConfirmWindow {
		t.Errorf("o teto do backoff (%v) não pode passar da própria janela de confirmação (%v): a cauda de uma reversão travada ficaria maior que a promessa que este mecanismo faz ao operador",
			maxRevertBackoff, ConfirmWindow)
	}
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

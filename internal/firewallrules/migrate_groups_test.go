package firewallrules

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// migrateExec grava os comandos já separados em argumentos, para que um
// teste possa afirmar a ORDEM em que o nft os recebeu — que é a única coisa
// que separa "a chain user_rules foi removida" de "o nft recusou removê-la
// porque a forward ainda pulava para ela".
type migrateExec struct {
	executed [][]string
	dryRun   bool
	failOn   func(args []string) error
}

func (e *migrateExec) Execute(_ context.Context, _ string, args ...string) (string, error) {
	e.executed = append(e.executed, args)
	if e.failOn != nil {
		if err := e.failOn(args); err != nil {
			return "", err
		}
	}
	return "", nil
}

func (e *migrateExec) ExecuteRead(_ context.Context, _ string, _ ...string) (string, error) {
	return "table inet linkguard {\n}\n", nil
}

func (e *migrateExec) IsDryRun() bool { return e.dryRun }

func newTestDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func newTestServiceWithExec(t *testing.T, db *storage.DB) (*Service, *migrateExec) {
	t.Helper()
	exec := &migrateExec{}
	nft := nftables.NewService(exec)
	// O nft grava o ruleset de boot em disco ao fim de cada reconciliação, e
	// essa é a única escrita que o executor falso NÃO intercepta: sem esta
	// linha, cada teste daqui que reconcilia tenta sobrescrever o
	// /etc/nftables.conf DA MÁQUINA com o dump do executor falso (`table inet
	// linkguard {}`). Numa estação de trabalho isso só falha por permissão; na
	// própria appliance, rodando como root, é o firewall vazio no próximo boot.
	nft.SetConfPath(filepath.Join(t.TempDir(), "nftables.conf"))
	// m3 da revisão da Fase C2: sem uma fonte de NTP ligada, ntpInputState
	// agora devolve erro (fechou o fail-open de fonte não ligada) em vez do
	// antigo "desligado" silencioso — o que faria todo teste que reconcilia
	// grupos por aqui falhar só por causa da chain input, que nenhum destes
	// testes exercita. A fonte abaixo declara a intenção explicitamente:
	// nenhum grupo de escopo input, NTP desligado.
	nft.SetInputChainSources(
		func() ([]nftables.StoredGroup, error) { return nil, nil },
		func() ([]string, bool, error) { return nil, false, nil },
	)
	return NewService(db, nft), exec
}

func newTestService(t *testing.T, db *storage.DB) *Service {
	t.Helper()
	svc, _ := newTestServiceWithExec(t, db)
	return svc
}

// newBootedService devolve o serviço no estado em que o boot o deixa antes
// de qualquer migração: os dois grupos do sistema já criados (é o PRIMEIRO
// passo da sequência em cmd/linkguard-fw/main.go, justamente porque as
// migrações reconciliam por dentro). O histórico do exec vem zerado, para o
// teste só enxergar os comandos que ele mesmo provocou.
//
// Um teste de migração que não passe por aqui não reproduz nenhum estado que
// a produção alcance: sem grupo do sistema na lista, Reconcile se recusa a
// reconstruir a chain forward.
func newBootedService(t *testing.T, db *storage.DB) (*Service, *migrateExec) {
	t.Helper()
	svc, exec := newTestServiceWithExec(t, db)
	if err := svc.EnsureSystemGroups(context.Background()); err != nil {
		t.Fatalf("criar os grupos do sistema: %v", err)
	}
	exec.executed = nil
	return svc, exec
}

// adminGroups devolve só os grupos que o admin tem — os dois do sistema
// existem em toda máquina e não interessam a quem está medindo migração de
// regra.
func adminGroups(t *testing.T, db *storage.DB) []storage.FirewallGroup {
	t.Helper()
	all, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatalf("ListFirewallGroups: %v", err)
	}
	var out []storage.FirewallGroup
	for _, g := range all {
		if !nftables.IsSystemGroup(g.Kind) {
			out = append(out, g)
		}
	}
	return out
}

func TestEnsureSystemGroupsCreatesBothAtTheTop(t *testing.T) {
	db := newTestDB(t)
	// um grupo do admin que já existe, na posição 0
	g := storage.FirewallGroup{ID: "a", Name: "Meu grupo", ChainName: "grp_aaa",
		Position: 0, Enabled: true, Fallthrough: "continue"}
	if err := db.CreateFirewallGroup(&g); err != nil {
		t.Fatal(err)
	}
	svc := newTestService(t, db)

	if err := svc.EnsureSystemGroups(context.Background()); err != nil {
		t.Fatalf("criar grupos do sistema: %v", err)
	}

	got, _ := db.ListFirewallGroups()
	if len(got) != 3 {
		t.Fatalf("esperava 3 grupos, obtive %d: %+v", len(got), got)
	}
	// Os dois do sistema nas posições 0 e 1, o do admin empurrado para 2:
	// o padrão continua sendo bloqueio primeiro.
	if !nftables.IsSystemGroup(got[0].Kind) || !nftables.IsSystemGroup(got[1].Kind) {
		t.Errorf("os dois primeiros têm que ser do sistema: %+v", got)
	}
	if got[2].ID != "a" {
		t.Errorf("o grupo do admin foi para o fim: %+v", got)
	}
}

// A trava é "já rodou", não "a tabela tem grupo do sistema": senão o boot
// seguinte ressuscita o que o admin apagou ou desligou de propósito.
func TestEnsureSystemGroupsIsIdempotent(t *testing.T) {
	db := newTestDB(t)
	svc := newTestService(t, db)
	ctx := context.Background()

	if err := svc.EnsureSystemGroups(ctx); err != nil {
		t.Fatal(err)
	}
	groups, _ := db.ListFirewallGroups()
	// o admin desliga um deles
	if err := db.SetFirewallGroupEnabled(groups[0].ID, false); err != nil {
		t.Fatal(err)
	}

	if err := svc.EnsureSystemGroups(ctx); err != nil {
		t.Fatal(err)
	}
	after, _ := db.ListFirewallGroups()
	if len(after) != 2 {
		t.Fatalf("rodou de novo e duplicou: %+v", after)
	}
	for _, x := range after {
		if x.ID == groups[0].ID && x.Enabled {
			t.Error("religou um grupo que o admin desligou de propósito")
		}
	}
}

// A trava é "isto já rodou", e não "a tabela tem grupo do sistema". A
// diferença entre as duas só aparece quando as LINHAS somem: desligar um
// grupo (o que o teste acima faz) passa nas duas formulações.
//
// Com a segunda formulação o estrago é duplo, e este teste mede os dois: os
// bloqueios ressuscitam LIGADOS e no topo — desfazendo, a cada boot, a
// escolha do admin que os apagou — e, pior, cada recriação desloca todos os
// grupos do admin em +2 (CreateSystemGroups abre espaço no topo), então a
// lista se reordena sozinha a cada reinicialização.
//
// Apagar as duas linhas é um estado alcançável hoje: a API devolve os grupos
// do sistema como grupo comum, e o DeleteGroup ainda não os recusa.
func TestEnsureSystemGroupsDoesNotRecreateGroupsDeletedFromTheTable(t *testing.T) {
	db := newTestDB(t)
	svc := newTestService(t, db)
	ctx := context.Background()

	if err := svc.EnsureSystemGroups(ctx); err != nil {
		t.Fatal(err)
	}
	// Dois grupos do admin, depois dos bloqueios, como o CRUD real cria.
	for i, id := range []string{
		"a0000000-0000-4000-8000-000000000000",
		"b0000000-0000-4000-8000-000000000000",
	} {
		g := storage.FirewallGroup{ID: id, Name: "grupo " + id[:1],
			ChainName: nftables.GroupChainName(id), Position: 2 + i,
			Enabled: true, Fallthrough: nftables.FallthroughContinue}
		if err := db.CreateFirewallGroup(&g); err != nil {
			t.Fatal(err)
		}
	}

	// O admin apaga os dois bloqueios da lista.
	for _, g := range systemGroupsIn(t, db) {
		if err := db.DeleteFirewallGroup(g.ID); err != nil {
			t.Fatalf("apagar %q: %v", g.Name, err)
		}
	}
	before := adminGroups(t, db)

	if err := svc.EnsureSystemGroups(ctx); err != nil {
		t.Fatalf("segunda passada: %v", err)
	}

	if back := systemGroupsIn(t, db); len(back) != 0 {
		t.Errorf("os grupos do sistema ressuscitaram no boot seguinte, desfazendo o que o admin apagou: %+v", back)
	}
	after := adminGroups(t, db)
	if len(after) != len(before) {
		t.Fatalf("a lista do admin mudou de tamanho: antes %+v, depois %+v", before, after)
	}
	for i := range before {
		if after[i].ID != before[i].ID || after[i].Position != before[i].Position {
			t.Errorf("o grupo %q saiu do lugar sem ninguém ter pedido: posição %d -> %d (a cada boot, +2)",
				before[i].Name, before[i].Position, after[i].Position)
		}
	}
}

// systemGroupsIn devolve as linhas de grupo do sistema que estão na tabela.
func systemGroupsIn(t *testing.T, db *storage.DB) []storage.FirewallGroup {
	t.Helper()
	all, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatalf("ListFirewallGroups: %v", err)
	}
	var out []storage.FirewallGroup
	for _, g := range all {
		if nftables.IsSystemGroup(g.Kind) {
			out = append(out, g)
		}
	}
	return out
}

// A defesa NÃO pode ser guardada pela trava. A trava só é gravada quando
// EnsureSystemGroups conclui com sucesso — então, no cenário que mais
// importa (a criação dos grupos falhou: erro de banco, transação abortada),
// ela fica vazia e uma defesa condicionada a ela ficaria desligada
// exatamente ali. A invariante certa é sobre a LISTA que vai ser
// renderizada: sem nenhum grupo do sistema nela, a forward não é
// reconstruída, tenha a trava sido gravada ou não.
//
// Isto cobre também a janela do boot: se alguma reconciliação rodasse antes
// da criação dos grupos, ela renderizaria uma forward sem os bloqueios sem
// parecer erro nenhum.
func TestReconcileRefusesAForwardWithNoSystemGroupAtAllEvenWithoutTheGuard(t *testing.T) {
	db := newTestDB(t)
	svc, exec := newTestServiceWithExec(t, db)
	ctx := context.Background()

	// O admin tem grupo; o que não existe é grupo do sistema. E a trava não
	// foi gravada — é assim que a máquina fica quando EnsureSystemGroups
	// falhou no boot.
	const id = "c3f21c08-0000-4000-8000-000000000000"
	g := storage.FirewallGroup{ID: id, Name: "Meu grupo", ChainName: nftables.GroupChainName(id),
		Position: 0, Enabled: true, Fallthrough: nftables.FallthroughContinue}
	if err := db.CreateFirewallGroup(&g); err != nil {
		t.Fatal(err)
	}
	if flag, _ := db.GetSetting(SystemGroupsSettingKey); flag != "" {
		t.Fatalf("o teste precisa da trava vazia, obtive %q", flag)
	}

	if err := svc.Reconcile(ctx); err == nil {
		t.Fatal("sem nenhum grupo do sistema na lista, reconciliar tem que ser erro — senão a forward sai sem bloqueio nenhum e ninguém percebe")
	}
	if len(exec.executed) != 0 {
		t.Errorf("nenhum comando do nft pode ter rodado: a forward viva é a última que foi aplicada COM os bloqueios; rodou: %v", exec.executed)
	}
	if st := svc.LastApplyStatus(); st == nil || st.OK {
		t.Errorf("o apply status tem que ficar não-ok, para a faixa aparecer na tela: %+v", st)
	}
}

// A sequência do boot, na ordem do main.go: os grupos do sistema nascem
// ANTES das duas migrações, porque as duas reconciliam por dentro — e uma
// reconciliação com a lista ainda sem os bloqueios é exatamente o que a
// defesa acima recusa. Nenhum passo pode falhar, e o resultado final tem que
// ser o mesmo padrão que já vale em produção: bloqueio primeiro, grupo do
// admin depois, cada um na sua posição.
func TestBootSequenceCreatesTheSystemGroupsBeforeAnyReconcile(t *testing.T) {
	db := newTestDB(t)
	if err := db.CreateFirewallRule(&storage.FirewallRule{ID: "r1", Enabled: true,
		Action: "accept", Proto: "tcp", Dport: "22"}); err != nil {
		t.Fatal(err)
	}
	svc := newTestService(t, db)
	ctx := context.Background()

	if err := svc.EnsureSystemGroups(ctx); err != nil {
		t.Fatalf("EnsureSystemGroups: %v", err)
	}
	if err := svc.ImportOnce(ctx); err != nil {
		t.Fatalf("ImportOnce depois dos grupos do sistema: %v", err)
	}
	if err := svc.MigrateRulesIntoDefaultGroup(ctx); err != nil {
		t.Fatalf("MigrateRulesIntoDefaultGroup depois dos grupos do sistema: %v", err)
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile no fim do boot: %v", err)
	}

	groups, _ := db.ListFirewallGroups()
	if len(groups) != 3 {
		t.Fatalf("esperava os 2 do sistema + o grupo padrão, obtive %d: %+v", len(groups), groups)
	}
	if groups[0].Kind != nftables.GroupKindBlockedHosts ||
		groups[1].Kind != nftables.GroupKindBlocklist ||
		groups[2].Name != DefaultGroupName {
		t.Fatalf("a ordem tem que continuar sendo bloqueio primeiro, grupo do admin depois: %+v", groups)
	}
	// Posições distintas: duas linhas empatadas em 0 deixam a ordem da lista
	// à mercê do desempate do SELECT, e é essa lista que decide a ordem de
	// avaliação da forward.
	seen := map[int]string{}
	for _, g := range groups {
		if other, dup := seen[g.Position]; dup {
			t.Errorf("posição %d empatada entre %q e %q", g.Position, other, g.Name)
		}
		seen[g.Position] = g.Name
	}
}

// O mesmo, no banco recém-criado: nenhum grupo de espécie nenhuma. É a
// janela do boot de uma instalação nova — e uma lista vazia é justamente o
// que ReconcileGroups trata como "o admin não tem grupo nenhum", reduzindo a
// forward. Sem grupo do sistema na lista, essa redução não pode acontecer.
func TestReconcileRefusesAForwardWhenTheGroupListIsEmpty(t *testing.T) {
	db := newTestDB(t)
	svc, exec := newTestServiceWithExec(t, db)

	if err := svc.Reconcile(context.Background()); err == nil {
		t.Fatal("lista vazia não pode render uma forward: ela sairia sem os bloqueios")
	}
	if len(exec.executed) != 0 {
		t.Errorf("nenhum comando do nft pode ter rodado, rodou: %v", exec.executed)
	}
}

// Faltar UM dos dois já é motivo para não renderizar (migração parcial,
// linha apagada à mão no banco, restauração incompleta): a forward sairia
// sem aquele bloqueio, e isso não pareceria erro — pareceria um admin que
// simplesmente não bloqueou nada. Abortar mantém o que já estava valendo e
// mostra o problema.
//
// Os dois casos são medidos, e não só o primeiro: com o teste sempre
// apagando o mesmo grupo, metade da verificação podia ser removida sem
// nenhum teste ficar vermelho.
func TestReconcileRefusesToRenderAForwardWithoutTheSystemGroups(t *testing.T) {
	for _, tc := range []struct{ nome, kind, esperado string }{
		{"sem hosts bloqueados", nftables.GroupKindBlockedHosts, BlockedHostsGroupName},
		{"sem destinos bloqueados", nftables.GroupKindBlocklist, BlocklistGroupName},
	} {
		t.Run(tc.nome, func(t *testing.T) {
			db := newTestDB(t)
			svc, exec := newTestServiceWithExec(t, db)
			ctx := context.Background()

			if err := svc.EnsureSystemGroups(ctx); err != nil {
				t.Fatal(err)
			}
			// simula a linha sumindo do banco depois de criada
			if _, err := db.Conn().Exec(`DELETE FROM firewall_groups WHERE kind = ?`, tc.kind); err != nil {
				t.Fatal(err)
			}

			err := svc.Reconcile(ctx)
			if err == nil {
				t.Fatal("reconciliar sem um dos grupos do sistema tem que ser erro, não silêncio")
			}
			if !strings.Contains(err.Error(), tc.esperado) {
				t.Errorf("o erro tem que nomear o bloqueio que sumiu (%q), obtive %q", tc.esperado, err)
			}
			for _, cmd := range exec.executed {
				if strings.Contains(strings.Join(cmd, " "), "flush chain") && strings.Contains(strings.Join(cmd, " "), "forward") {
					t.Fatalf("a forward NÃO pode ter sido tocada: %q", cmd)
				}
			}
			if st := svc.LastApplyStatus(); st == nil || st.OK {
				t.Error("o apply status tem que ficar não-ok, para a faixa aparecer na tela")
			}
		})
	}
}

// A defesa olha PRESENÇA na lista, nunca Enabled — e isto é intenção, não
// descuido. Desligar um bloqueio é escolha explícita do admin (é assim que o
// toggle do painel vai funcionar), e um grupo desligado continua sendo uma
// linha na lista.
//
// Exigir Enabled aqui é o "conserto" óbvio para quem ler esta verificação
// pela primeira vez, e o efeito seria absurdo: o admin desligaria um
// bloqueio e o firewall inteiro pararia de aceitar qualquer mudança — toda
// reconciliação abortando, apply não-ok permanente, alerta crítico aberto,
// e nenhuma mutação da API conseguindo passar.
func TestReconcileAcceptsTheSystemGroupsTurnedOffByTheAdmin(t *testing.T) {
	db := newTestDB(t)
	svc, exec := newBootedService(t, db)
	ctx := context.Background()

	for _, g := range systemGroupsIn(t, db) {
		if err := db.SetFirewallGroupEnabled(g.ID, false); err != nil {
			t.Fatalf("desligar %q: %v", g.Name, err)
		}
	}

	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("desligar um bloqueio não pode travar a reconciliação: %v", err)
	}
	if st := svc.LastApplyStatus(); st == nil || !st.OK {
		t.Errorf("o apply tem que ficar ok: %+v", st)
	}
	rebuilt := false
	for _, cmd := range exec.executed {
		j := strings.Join(cmd, " ")
		if strings.HasPrefix(j, "flush chain") && strings.HasSuffix(j, " forward") {
			rebuilt = true
		}
	}
	if !rebuilt {
		t.Errorf("a forward tinha que ter sido reconstruída normalmente: %v", exec.executed)
	}
}

// Criar os dois grupos do sistema não pode custar nada ao firewall que já
// está valendo: a reconciliação seguinte tem que dar certo, o apply tem que
// ficar ok e a forward tem que continuar com os quatro bloqueios. Sem esta
// asserção, "migrou" significaria só "mexeu no banco" — e o custo real seria
// invisível aqui: o nome de chain reservado dos grupos do sistema não é um
// grp_, então tratá-los como grupo do admin marca os DOIS como não aplicados
// em toda passada (faixa vermelha eterna no painel) e faz o pré-voo `nft -c`
// recusar qualquer mutação de regra com 400.
func TestReconcileStaysHealthyAfterTheSystemGroupsAreCreated(t *testing.T) {
	db := newTestDB(t)
	svc, exec := newTestServiceWithExec(t, db)
	ctx := context.Background()

	if err := svc.EnsureSystemGroups(ctx); err != nil {
		t.Fatal(err)
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("reconciliar com os grupos do sistema na lista: %v", err)
	}
	if st := svc.LastApplyStatus(); st == nil || !st.OK {
		t.Errorf("o apply tem que ficar ok depois da migração: %+v", st)
	}

	// O pré-voo de toda mutação enxerga o conjunto COMPLETO de grupos.
	groups, err := svc.StoredGroups()
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.CheckPendingGroups(ctx, groups); err != nil {
		t.Errorf("o pré-voo passou a recusar tudo por causa dos grupos do sistema: %v", err)
	}

	var forward []string
	for _, cmd := range exec.executed {
		j := strings.Join(cmd, " ")
		if strings.HasPrefix(j, "add rule inet linkguard forward ") {
			forward = append(forward, j)
		}
	}
	for _, want := range []string{
		"ip saddr @blocked_hosts counter drop",
		"ip daddr @blocked_hosts counter drop",
		"ip daddr @blocklist counter drop",
		"ip saddr @blocklist counter drop",
	} {
		found := false
		for _, line := range forward {
			if strings.HasSuffix(line, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("a forward perdeu o bloqueio %q: %v", want, forward)
		}
	}
}

// recordingAlerter conta as duas notificações da invariante, para um teste
// poder afirmar o que foi ANUNCIADO ao operador — que é diferente do que a
// função devolveu.
type recordingAlerter struct {
	missing []string
	ok      int
	// reverted guarda os alertas de reversão automática do confirmar-ou-
	// reverte (Fase C2): o que o operador vai encontrar quando voltar e
	// descobrir que a alteração dele não está mais valendo.
	reverted []string
}

func (a *recordingAlerter) FirewallSystemGroupsMissing(detail string) error {
	a.missing = append(a.missing, detail)
	return nil
}
func (a *recordingAlerter) FirewallSystemGroupsOK() { a.ok++ }
func (a *recordingAlerter) FirewallChangeReverted(detail string) error {
	a.reverted = append(a.reverted, detail)
	return nil
}

// O alerta de recuperação afirma, no texto que vai para o Telegram e para o
// webhook, que "a chain forward foi reconstruída com os bloqueios". Só que a
// lista estar completa não reconstrói nada: quem reconstrói é o
// ReconcileGroups da linha seguinte, e ele pode falhar.
//
// Anunciar antes do apply fecharia o alerta crítico e mandaria um "voltou"
// para uma máquina cuja forward continua sendo a antiga — a distinção
// Enabled × Applied que este projeto aplica em todo o resto.
func TestReconcileDoesNotAnnounceRecoveryWhenTheApplyItselfFailed(t *testing.T) {
	db := newTestDB(t)
	svc, exec := newBootedService(t, db)
	alerter := &recordingAlerter{}
	svc.SetAlerter(alerter)
	exec.failOn = func(args []string) error {
		if len(args) > 4 && args[0] == "add" && args[1] == "rule" && args[4] == "forward" {
			return errors.New("nft: Error: Could not process rule: Device or resource busy")
		}
		return nil
	}

	if err := svc.Reconcile(context.Background()); err == nil {
		t.Fatal("esperava a recusa do nft ao reconstruir a forward")
	}
	if alerter.ok != 0 {
		t.Errorf("um 'voltou ao normal' foi anunciado %d vez(es) com a forward NÃO reconstruída — é a mentira que o alerta existe para evitar", alerter.ok)
	}
}

// O contrapeso do teste acima: quando o apply dá certo de verdade, a
// recuperação TEM que ser anunciada — senão o alerta crítico fica aberto
// para sempre e o operador aprende a ignorar a lista.
func TestReconcileAnnouncesRecoveryOnceTheForwardWasActuallyRebuilt(t *testing.T) {
	db := newTestDB(t)
	svc, _ := newBootedService(t, db)
	alerter := &recordingAlerter{}
	svc.SetAlerter(alerter)

	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if alerter.ok != 1 {
		t.Errorf("esperava exatamente um fechamento do alerta depois do apply bem-sucedido, obtive %d", alerter.ok)
	}
	if len(alerter.missing) != 0 {
		t.Errorf("nenhum alerta crítico podia ter sido aberto: %v", alerter.missing)
	}
}

func TestMigrateCreatesDefaultGroupAndAdoptsRulesInOrder(t *testing.T) {
	db := newTestDB(t)
	for i, r := range []storage.FirewallRule{
		{ID: "r1", Position: 0, Enabled: true, Action: "drop", Proto: "udp", Dport: "161"},
		{ID: "r2", Position: 1, Enabled: true, Action: "accept", Proto: "tcp", Dport: "22"},
	} {
		r.Position = i
		if err := db.CreateFirewallRule(&r); err != nil {
			t.Fatalf("preparar regra: %v", err)
		}
	}
	svc, _ := newBootedService(t, db)

	if err := svc.MigrateRulesIntoDefaultGroup(context.Background()); err != nil {
		t.Fatalf("migrar: %v", err)
	}

	groups := adminGroups(t, db)
	if len(groups) != 1 {
		t.Fatalf("esperava exatamente 1 grupo do admin, obtive %d: %+v", len(groups), groups)
	}
	g := groups[0]
	if g.Name != "Minhas regras" {
		t.Errorf("nome do grupo padrão: %q", g.Name)
	}
	// Comportamento idêntico ao de hoje: sem condição, "continuar avaliando".
	if g.CondSaddr != "" || g.CondDaddr != "" || g.CondIif != "" {
		t.Errorf("o grupo da migração não pode ter condição: %+v", g)
	}
	if g.Fallthrough != "continue" {
		t.Errorf("o grupo da migração tem que continuar avaliando, obtive %q", g.Fallthrough)
	}
	if !g.Enabled {
		t.Error("o grupo da migração tem que nascer ligado")
	}

	rules, _ := db.ListFirewallRules()
	for _, r := range rules {
		if r.GroupID != g.ID {
			t.Errorf("regra %s ficou fora do grupo (group_id=%q)", r.ID, r.GroupID)
		}
	}
	if rules[0].ID != "r1" || rules[1].ID != "r2" {
		t.Errorf("a ordem das regras não foi preservada: %+v", rules)
	}
}

func TestMigrateIsIdempotentAndDoesNotResurrectDeletedRules(t *testing.T) {
	db := newTestDB(t)
	r := storage.FirewallRule{ID: "r1", Position: 0, Enabled: true, Action: "accept", Proto: "tcp", Dport: "22"}
	if err := db.CreateFirewallRule(&r); err != nil {
		t.Fatal(err)
	}
	svc, _ := newBootedService(t, db)
	ctx := context.Background()

	if err := svc.MigrateRulesIntoDefaultGroup(ctx); err != nil {
		t.Fatalf("primeira migração: %v", err)
	}
	groups := adminGroups(t, db)
	if err := db.DeleteFirewallGroup(groups[0].ID); err != nil {
		t.Fatalf("apagar: %v", err)
	}
	// E o admin segue usando a máquina: uma regra nova, ainda sem grupo. Sem
	// esta linha o teste não distingue a trava certa ("isto já rodou") de uma
	// trava ingênua ("a tabela de grupos está vazia"), porque as duas passam
	// num banco onde não sobrou regra nenhuma para agrupar. É justamente com
	// uma regra solta na mesa que a trava ingênua recria, no boot seguinte, o
	// grupo que o admin acabou de apagar.
	if err := db.CreateFirewallRule(&storage.FirewallRule{ID: "r2", Enabled: true,
		Action: "drop", Saddr: "10.0.0.3"}); err != nil {
		t.Fatal(err)
	}

	if err := svc.MigrateRulesIntoDefaultGroup(ctx); err != nil {
		t.Fatalf("segunda migração: %v", err)
	}
	if groups := adminGroups(t, db); len(groups) != 0 {
		t.Fatalf("a migração rodou de novo e ressuscitou o que o admin apagou: %+v", groups)
	}
}

func TestMigrateWithNoRulesStillSetsTheGuard(t *testing.T) {
	db := newTestDB(t)
	svc := newTestService(t, db)
	if err := svc.MigrateRulesIntoDefaultGroup(context.Background()); err != nil {
		t.Fatalf("migrar: %v", err)
	}
	groups, _ := db.ListFirewallGroups()
	if len(groups) != 0 {
		t.Errorf("sem regras não há o que agrupar, não deveria criar grupo vazio: %+v", groups)
	}
	v, _ := db.GetSetting(GroupsMigratedSettingKey)
	if v == "" {
		t.Error("a trava tem que ser gravada mesmo sem nada a migrar, senão roda de novo todo boot")
	}
}

// A chain user_rules só pode ser apagada depois de a forward parar de
// referenciá-la — o nft recusa apagar chain ainda referenciada.
func TestMigrateRemovesUserRulesChainOnlyAfterForwardRebuild(t *testing.T) {
	db := newTestDB(t)
	r := storage.FirewallRule{ID: "r1", Position: 0, Enabled: true, Action: "accept", Proto: "tcp", Dport: "22"}
	if err := db.CreateFirewallRule(&r); err != nil {
		t.Fatal(err)
	}
	svc, exec := newBootedService(t, db)

	if err := svc.MigrateRulesIntoDefaultGroup(context.Background()); err != nil {
		t.Fatalf("migrar: %v", err)
	}

	idxForward, idxDelete := -1, -1
	for i, cmd := range exec.executed {
		j := strings.Join(cmd, " ")
		if strings.HasPrefix(j, "flush chain") && strings.HasSuffix(j, " forward") {
			idxForward = i
		}
		if strings.HasPrefix(j, "delete chain") && strings.Contains(j, "user_rules") {
			idxDelete = i
		}
	}
	if idxDelete < 0 {
		t.Fatal("a chain user_rules não foi removida depois da migração")
	}
	if idxForward < 0 || idxDelete < idxForward {
		t.Errorf("user_rules apagada antes de a forward ser reconstruída — o nft recusaria (ordem: forward=%d, delete=%d)", idxForward, idxDelete)
	}
}

// A migração termina com o firewall se comportando igual ao de antes: as
// mesmas regras, agora dentro da chain do grupo, alcançada por um jump sem
// condição na forward. Sem isto, "migrou" poderia significar apenas "mexeu
// no banco" — e o admin ficaria com o painel cheio e o firewall vazio.
func TestMigrateLeavesTheAdoptedRulesRenderedInTheGroupChain(t *testing.T) {
	db := newTestDB(t)
	if err := db.CreateFirewallRule(&storage.FirewallRule{ID: "r1", Enabled: true,
		Action: "drop", Daddr: "203.0.113.7"}); err != nil {
		t.Fatal(err)
	}
	svc, exec := newBootedService(t, db)

	if err := svc.MigrateRulesIntoDefaultGroup(context.Background()); err != nil {
		t.Fatalf("migrar: %v", err)
	}
	groups := adminGroups(t, db)
	if len(groups) != 1 {
		t.Fatalf("esperava o grupo padrão criado, obtive %+v", groups)
	}
	chain := groups[0].ChainName

	rendered, jumped := false, false
	for _, cmd := range exec.executed {
		j := strings.Join(cmd, " ")
		if strings.HasPrefix(j, "add rule inet linkguard "+chain+" ") && strings.Contains(j, "203.0.113.7") {
			rendered = true
		}
		if strings.HasPrefix(j, "add rule inet linkguard forward ") && strings.HasSuffix(j, "counter jump "+chain) {
			jumped = true
		}
	}
	if !rendered {
		t.Errorf("a regra adotada não foi renderizada na chain do grupo: %v", exec.executed)
	}
	if !jumped {
		t.Errorf("a forward não ganhou o jump incondicional para o grupo padrão: %v", exec.executed)
	}
}

// Regra que JÁ está num grupo não é mexida: a migração adota só o que está
// solto. Um UPDATE largo demais reescreveria o group_id de todas as regras e
// jogaria dentro de "Minhas regras" grupos que o admin já tinha organizado.
func TestMigrateAdoptsOnlyTheRulesThatHaveNoGroup(t *testing.T) {
	db := newTestDB(t)
	const id = "b3f21c08-0000-4000-8000-000000000000"
	existing := storage.FirewallGroup{ID: id, Name: "Wi-Fi visitantes",
		ChainName: nftables.GroupChainName(id), Position: 2, Enabled: true,
		Fallthrough: nftables.FallthroughDrop}
	if err := db.CreateFirewallGroup(&existing); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateFirewallRule(&storage.FirewallRule{ID: "dentro", GroupID: existing.ID,
		Enabled: true, Action: "accept", Proto: "tcp", Dport: "443"}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateFirewallRule(&storage.FirewallRule{ID: "solta", Enabled: true,
		Action: "drop", Saddr: "10.0.0.9"}); err != nil {
		t.Fatal(err)
	}
	svc, _ := newBootedService(t, db)

	if err := svc.MigrateRulesIntoDefaultGroup(context.Background()); err != nil {
		t.Fatalf("migrar: %v", err)
	}

	rules, _ := db.ListFirewallRules()
	byID := map[string]storage.FirewallRule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	if byID["dentro"].GroupID != existing.ID {
		t.Errorf("a regra que já tinha grupo foi movida para outro: %+v", byID["dentro"])
	}
	if byID["solta"].GroupID == "" || byID["solta"].GroupID == existing.ID {
		t.Errorf("a regra solta tinha que ser adotada pelo grupo NOVO, obtive group_id=%q", byID["solta"].GroupID)
	}
}

// O caso que mais custa caro: o nft recusa reconstruir a forward (regra
// rejeitada) e, por causa disso, a forward VIVA ainda pode pular para
// user_rules. Remover a chain nesse estado é o que o `Device or resource
// busy` da produção descreve — e, se a remoção fosse feita com um flush
// antes (que o nft aceita em chain referenciada), o resultado seria pior que
// um erro: a forward continuaria pulando para uma chain agora VAZIA, e todo
// tráfego que as regras do admin bloqueavam passaria a passar.
func TestMigrateDoesNotTouchUserRulesWhenTheForwardCouldNotBeRebuilt(t *testing.T) {
	db := newTestDB(t)
	if err := db.CreateFirewallRule(&storage.FirewallRule{ID: "r1", Enabled: true,
		Action: "accept", Proto: "tcp", Dport: "22"}); err != nil {
		t.Fatal(err)
	}
	// Uma regra ativada que não renderiza (linha de banco antiga): faz
	// ReconcileGroups devolver o erro COMPOSTO — recusa do nft embrulhando um
	// SkippedRulesError —, que é onde um errors.As ingênuo vira "sucesso".
	if err := db.CreateFirewallRule(&storage.FirewallRule{ID: "r2", Enabled: true,
		Action: "accept", Iif: "eth0\" ; flush ruleset #"}); err != nil {
		t.Fatal(err)
	}
	svc, exec := newTestServiceWithExec(t, db)
	exec.failOn = func(args []string) error {
		if len(args) > 4 && args[0] == "add" && args[1] == "rule" && args[4] == "forward" {
			return errors.New("nft: Error: Could not process rule: Device or resource busy")
		}
		return nil
	}

	if err := svc.MigrateRulesIntoDefaultGroup(context.Background()); err == nil {
		t.Fatal("a migração tem que falhar quando a forward não pôde ser reconstruída")
	}
	for _, cmd := range exec.executed {
		j := strings.Join(cmd, " ")
		if strings.Contains(j, "user_rules") && (strings.HasPrefix(j, "delete chain") || strings.HasPrefix(j, "flush chain")) {
			t.Errorf("a user_rules foi mexida com a forward quebrada: %q", j)
		}
	}
}

// Ignorar o erro de leitura da trava (`flag, _ := s.db.GetSetting(...)`) faz
// a migração rodar de novo achando que nunca rodou -- e, para uma regra
// solta que surgiu depois da primeira migração, isso cria um SEGUNDO grupo
// "Minhas regras" com metade das regras do admin em cada um.
//
// A corrupção aqui é cirúrgica de propósito: recria a tabela settings sem a
// restrição NOT NULL e grava NULL só na linha da trava, o que faz o SELECT
// (Scan de NULL num *string) falhar, mas deixa ESCRITAS na mesma linha
// funcionando normalmente depois. Derrubar a tabela inteira (DROP TABLE)
// não serve de teste: a escrita da trava dentro de MigrateRulesIntoGroup
// falharia também, e a transação (achado 4) desfaria o grupo novo de
// qualquer jeito -- mascarando exatamente a diferença que este teste
// precisa enxergar entre o código certo e o mutante.
func TestMigrateAbortsInsteadOfRerunningWhenTheGuardCannotBeRead(t *testing.T) {
	db := newTestDB(t)
	if err := db.CreateFirewallRule(&storage.FirewallRule{ID: "r1", Position: 0, Enabled: true,
		Action: "accept", Proto: "tcp", Dport: "22"}); err != nil {
		t.Fatal(err)
	}
	svc, exec := newBootedService(t, db)
	ctx := context.Background()

	if err := svc.MigrateRulesIntoDefaultGroup(ctx); err != nil {
		t.Fatalf("primeira migração: %v", err)
	}
	if groupsBefore := adminGroups(t, db); len(groupsBefore) != 1 {
		t.Fatalf("esperava 1 grupo do admin depois da primeira migração, obtive %d", len(groupsBefore))
	}

	// O admin segue usando a máquina: uma regra nova, ainda sem grupo.
	if err := db.CreateFirewallRule(&storage.FirewallRule{ID: "r2", Enabled: true,
		Action: "drop", Saddr: "10.0.0.9"}); err != nil {
		t.Fatal(err)
	}

	if _, err := db.Conn().Exec(`CREATE TABLE settings_tmp (key TEXT PRIMARY KEY, value TEXT, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatalf("criar settings_tmp: %v", err)
	}
	if _, err := db.Conn().Exec(`INSERT INTO settings_tmp SELECT * FROM settings`); err != nil {
		t.Fatalf("copiar settings: %v", err)
	}
	if _, err := db.Conn().Exec(`DROP TABLE settings`); err != nil {
		t.Fatalf("derrubar settings original: %v", err)
	}
	if _, err := db.Conn().Exec(`ALTER TABLE settings_tmp RENAME TO settings`); err != nil {
		t.Fatalf("renomear settings_tmp: %v", err)
	}
	if _, err := db.Conn().Exec(`UPDATE settings SET value = NULL WHERE key = ?`, GroupsMigratedSettingKey); err != nil {
		t.Fatalf("corromper a trava: %v", err)
	}

	exec.executed = nil
	if err := svc.MigrateRulesIntoDefaultGroup(ctx); err == nil {
		t.Fatal("esperava erro quando a trava não pôde ser lida")
	}

	groupsAfter := adminGroups(t, db)
	if len(groupsAfter) != 1 {
		t.Fatalf("um erro de leitura da trava não pode disparar uma segunda migração -- esperava continuar com 1 grupo do admin, obtive %d: %+v", len(groupsAfter), groupsAfter)
	}
	rules, _ := db.ListFirewallRules()
	for _, r := range rules {
		if r.ID == "r2" && r.GroupID != "" {
			t.Errorf("a regra nova não pode ter sido adotada por uma migração que devia ter abortado no erro de leitura da trava: %+v", r)
		}
	}
	if len(exec.executed) != 0 {
		t.Errorf("nenhum comando do nft pode ter rodado com a trava ilegível, rodou: %v", exec.executed)
	}
}

// A retentativa da remoção da chain legada tem que rodar em TODO boot em que
// a trava já está gravada -- é o que dá a uma máquina onde o `delete` falhou
// uma vez (nft ocupado, forward ainda referenciando a user_rules) uma
// segunda chance, em vez de carregar a chain morta para sempre. Reverter
// isso para um `return nil` seco no ramo `if flag != ""` não é pego por
// nenhum outro teste: os demais só olham o resultado da PRIMEIRA migração.
//
// A ordem importa tanto quanto a existência da retentativa: o ruleset com
// que este boot começa é o que foi persistido em /etc/nftables.conf, que
// pode ter ficado desatualizado (persistência falhou num boot anterior, ou
// o próprio delete falhou e nada mexeu na forward depois) -- então esta
// retentativa reconcilia de novo ANTES de tentar remover, exatamente como o
// ramo de primeira migração já faz. Este teste assere que o `flush chain
// ... forward` do Reconcile vem antes do `delete chain ... user_rules`, não
// só que o delete aconteceu.
func TestMigrateRetriesRemovingTheLegacyChainOnEveryBootAfterTheGuardIsSet(t *testing.T) {
	db := newTestDB(t)
	svc, exec := newBootedService(t, db)
	ctx := context.Background()

	if err := svc.MigrateRulesIntoDefaultGroup(ctx); err != nil {
		t.Fatalf("primeira migração: %v", err)
	}
	exec.executed = nil // só interessa o que roda na SEGUNDA chamada, com a trava já gravada

	if err := svc.MigrateRulesIntoDefaultGroup(ctx); err != nil {
		t.Fatalf("segunda chamada (trava já gravada): %v", err)
	}

	idxForward, idxDelete := -1, -1
	for i, cmd := range exec.executed {
		j := strings.Join(cmd, " ")
		if strings.HasPrefix(j, "flush chain") && strings.HasSuffix(j, " forward") {
			idxForward = i
		}
		if strings.HasPrefix(j, "delete chain") && strings.Contains(j, "user_rules") {
			idxDelete = i
		}
	}
	if idxDelete < 0 {
		t.Fatal("com a trava já gravada, a remoção da chain legada tem que ser retentada -- nenhum comando de delete rodou")
	}
	if idxForward < 0 || idxDelete < idxForward {
		t.Errorf("a retentativa tem que reconciliar a forward antes de tentar apagar a user_rules, senão esbarra no mesmo \"Device or resource busy\" que a migração inicial evita (ordem: forward=%d, delete=%d)", idxForward, idxDelete)
	}
}

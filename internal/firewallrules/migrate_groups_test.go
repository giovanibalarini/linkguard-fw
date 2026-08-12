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
	return NewService(db, nftables.NewService(exec)), exec
}

func newTestService(t *testing.T, db *storage.DB) *Service {
	t.Helper()
	svc, _ := newTestServiceWithExec(t, db)
	return svc
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
	svc := newTestService(t, db)

	if err := svc.MigrateRulesIntoDefaultGroup(context.Background()); err != nil {
		t.Fatalf("migrar: %v", err)
	}

	groups, _ := db.ListFirewallGroups()
	if len(groups) != 1 {
		t.Fatalf("esperava exatamente 1 grupo, obtive %d: %+v", len(groups), groups)
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
	svc := newTestService(t, db)
	ctx := context.Background()

	if err := svc.MigrateRulesIntoDefaultGroup(ctx); err != nil {
		t.Fatalf("primeira migração: %v", err)
	}
	groups, _ := db.ListFirewallGroups()
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
	groups, _ = db.ListFirewallGroups()
	if len(groups) != 0 {
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
	svc, exec := newTestServiceWithExec(t, db)

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
	svc, exec := newTestServiceWithExec(t, db)

	if err := svc.MigrateRulesIntoDefaultGroup(context.Background()); err != nil {
		t.Fatalf("migrar: %v", err)
	}
	groups, _ := db.ListFirewallGroups()
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
		ChainName: nftables.GroupChainName(id), Enabled: true,
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
	svc := newTestService(t, db)

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

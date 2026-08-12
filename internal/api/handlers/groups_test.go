package handlers_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// ─── Um nft de mentira que recusa o que o nft de verdade recusa ───────────
//
// Os executores falsos que esta suíte já tinha devolvem ""/nil para tudo:
// aprovam qualquer script, inclusive os que a produção rejeita. Foi
// exatamente isso que deixou o defeito C-1 atravessar a suíte inteira — o
// pré-voo `nft -c` de toda mutação de regra começa por `flush chain inet
// linkguard user_rules`, e depois da migração para grupos essa chain não
// existe mais.
//
// Verificado ao vivo no nft de produção (Debian 13), e é o único
// comportamento que este falso simula além de guardar estado:
//
//	$ printf 'flush chain inet lgprobe user_rules\n...' | nft -c -f -
//	Error: No such file or directory
//	$ printf 'add chain inet lgprobe user_rules\nflush chain ...' | nft -c -f -
//	(passa limpo)
//
// Ele nasce como a produção nasce DEPOIS da migração: a chain forward
// existe (bootstrap), a user_rules não.
type fakeNft struct {
	chains   map[string][]string // chain viva → expressões, na ordem
	executed []string
}

// errNoSuchChain é a mensagem que o nft dá para referência a chain
// inexistente, tanto no comando solto quanto dentro de `nft -c -f`.
var errNoSuchChain = errors.New("Error: No such file or directory")

func newFakeNft() *fakeNft {
	return &fakeNft{chains: map[string][]string{nftables.ForwardChain: {}}}
}

func (f *fakeNft) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	f.executed = append(f.executed, cmd+" "+strings.Join(args, " "))
	if cmd != "nft" {
		return "", nil
	}
	return "", applyNftCommand(f.chains, args)
}

func (f *fakeNft) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd != "nft" || len(args) == 0 {
		return "", nil
	}
	switch {
	case len(args) >= 3 && args[0] == "-c" && args[1] == "-f":
		return "", f.check(args[2])
	case args[0] == "list", len(args) >= 2 && args[0] == "-a" && args[1] == "list":
		return f.render(), nil
	}
	return "", nil
}

func (f *fakeNft) IsDryRun() bool { return false }

// check roda o script de `nft -c -f` contra uma CÓPIA do estado: um dry run
// não materializa nada, mas enxerga o que o script cria dentro dele mesmo
// (é por isso que o `add chain` no topo salva o pré-voo de um grupo novo).
func (f *fakeNft) check(path string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	scratch := make(map[string][]string, len(f.chains))
	for name, rules := range f.chains {
		scratch[name] = append([]string{}, rules...)
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if err := applyNftCommand(scratch, strings.Fields(line)); err != nil {
			return err
		}
	}
	return nil
}

// applyNftCommand entende os quatro comandos que a reconciliação emite, e é
// compartilhado pelo caminho de verdade (Execute) e pelo dry run (check)
// justamente para que o dry run não possa ser mais permissivo que o real.
func applyNftCommand(state map[string][]string, args []string) error {
	if len(args) < 5 || args[2] != nftables.Family || args[3] != nftables.Table {
		return nil
	}
	verb, object, name := args[0], args[1], args[4]
	switch {
	case verb == "add" && object == "chain":
		if _, ok := state[name]; !ok {
			state[name] = []string{}
		}
	case verb == "flush" && object == "chain":
		if _, ok := state[name]; !ok {
			return errNoSuchChain
		}
		state[name] = []string{}
	case verb == "delete" && object == "chain":
		if _, ok := state[name]; !ok {
			return errNoSuchChain
		}
		delete(state, name)
	case verb == "add" && object == "rule":
		if _, ok := state[name]; !ok {
			return errNoSuchChain
		}
		expr := strings.Join(args[5:], " ")
		if target := jumpTargetOf(expr); target != "" {
			if _, ok := state[target]; !ok {
				return errNoSuchChain // o nft recusa jump para chain inexistente
			}
		}
		state[name] = append(state[name], expr)
	}
	return nil
}

func jumpTargetOf(expr string) string {
	idx := strings.LastIndex(expr, "jump ")
	if idx < 0 {
		return ""
	}
	return strings.TrimSpace(expr[idx+len("jump "):])
}

// render devolve o estado no formato de `nft -a list table inet linkguard`,
// com contador e handle como a produção imprime — é o que o parser do painel
// consome.
func (f *fakeNft) render() string {
	names := make([]string, 0, len(f.chains))
	for name := range f.chains {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString("table " + nftables.Family + " " + nftables.Table + " {\n")
	handle := 10
	for _, name := range names {
		b.WriteString("\tchain " + name + " {\n")
		if name == nftables.ForwardChain {
			b.WriteString("\t\ttype filter hook forward priority filter; policy accept;\n")
		}
		for _, expr := range f.chains[name] {
			handle++
			live := strings.Replace(expr, "counter", "counter packets 0 bytes 0", 1)
			fmt.Fprintf(&b, "\t\t%s # handle %d\n", live, handle)
		}
		b.WriteString("\t}\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func (f *fakeNft) forwardHasJumpTo(chain string) bool {
	for _, expr := range f.chains[nftables.ForwardChain] {
		if jumpTargetOf(expr) == chain {
			return true
		}
	}
	return false
}

func (f *fakeNft) ranWith(substr string) bool {
	for _, c := range f.executed {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

// ─── Fixtures ─────────────────────────────────────────────────────────────

func newGroupTestHandler(t *testing.T) (*handlers.NftablesHandler, *storage.DB) {
	t.Helper()
	h, db, _ := newGroupTestHandlerNft(t)
	return h, db
}

func newGroupTestHandlerNft(t *testing.T) (*handlers.NftablesHandler, *storage.DB, *fakeNft) {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	exec := newFakeNft()
	svc := nftables.NewService(exec)
	fr := firewallrules.NewService(db, svc)
	return handlers.NewNftablesHandler(svc, db, fr), db, exec
}

func doJSON(t *testing.T, fn http.HandlerFunc, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	w := httptest.NewRecorder()
	fn(w, req)
	return w
}

// createGroupViaAPI cria um grupo pelo endpoint (nunca direto no banco) e
// devolve a linha gravada — inclusive o ChainName que o SERVIDOR escolheu.
func createGroupViaAPI(t *testing.T, h *handlers.NftablesHandler, db *storage.DB, body string) storage.FirewallGroup {
	t.Helper()
	w := doJSON(t, h.CreateGroup, "POST", "/api/nftables/groups", body)
	if w.Code != http.StatusOK {
		t.Fatalf("CreateGroup(%s): status %d, body %s", body, w.Code, w.Body.String())
	}
	var created storage.FirewallGroup
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode do grupo criado: %v (body %s)", err, w.Body.String())
	}
	groups, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatalf("ListFirewallGroups: %v", err)
	}
	for _, g := range groups {
		if g.ID == created.ID {
			return g
		}
	}
	t.Fatalf("grupo criado não está no banco: %+v", groups)
	return storage.FirewallGroup{}
}

func createRuleViaAPI(t *testing.T, h *handlers.NftablesHandler, db *storage.DB, body string) storage.FirewallRule {
	t.Helper()
	w := doJSON(t, h.CreateRule, "POST", "/api/nftables/rules", body)
	if w.Code != http.StatusOK {
		t.Fatalf("CreateRule(%s): status %d, body %s", body, w.Code, w.Body.String())
	}
	var created storage.FirewallRule
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode da regra criada: %v (body %s)", err, w.Body.String())
	}
	return created
}

// ─── Criação ──────────────────────────────────────────────────────────────

// A ordem que a Fase B estabeleceu e a revisão confirmou: nada chega ao
// banco antes de o nft aceitar.
func TestCreateGroupRejectsBadConditionBeforeItReachesTheDB(t *testing.T) {
	h, db := newGroupTestHandler(t)
	for _, body := range []string{
		`{"name":"g","cond_saddr":"2001:db8::1","fallthrough":"continue"}`,
		`{"name":"g","cond_iif":"eth0; rm -rf /","fallthrough":"continue"}`,
		`{"name":"g","fallthrough":"talvez"}`,
		`{"name":"   ","fallthrough":"continue"}`,
	} {
		w := doJSON(t, h.CreateGroup, "POST", "/api/nftables/groups", body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("corpo %s: esperava 400, obtive %d (%s)", body, w.Code, w.Body.String())
		}
	}
	groups, _ := db.ListFirewallGroups()
	if len(groups) != 0 {
		t.Fatalf("nada podia ter chegado ao banco, obtive %+v", groups)
	}
}

// O nome da chain é do servidor, não do cliente: ele vai inteiro para o argv
// do nft, e aceitá-lo do corpo seria injeção de comando.
func TestCreateGroupDerivesItsOwnChainName(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)
	g := createGroupViaAPI(t, h, db,
		`{"name":"Servidores","chain_name":"forward","cond_saddr":"192.168.50.0/24","fallthrough":"drop"}`)

	if !regexp.MustCompile(`^grp_[a-f0-9]{1,12}$`).MatchString(g.ChainName) {
		t.Fatalf("nome de chain fora do formato derivado pelo servidor: %q", g.ChainName)
	}
	if g.ChainName == nftables.ForwardChain {
		t.Fatal("o nome de chain veio do cliente")
	}
	if !g.Enabled {
		t.Error("um grupo criado nasce ligado")
	}
	if _, ok := exec.chains[g.ChainName]; !ok {
		t.Errorf("a chain do grupo não foi criada no nft: %v", exec.executed)
	}
	if !exec.forwardHasJumpTo(g.ChainName) {
		t.Errorf("a forward não ganhou o jump para o grupo: %v", exec.chains[nftables.ForwardChain])
	}
	if !exec.ranWith("add rule inet linkguard " + g.ChainName + " counter drop") {
		t.Errorf("o \"e o que sobrar: descartar\" não foi renderizado: %v", exec.executed)
	}
}

func TestCreateRuleRequiresAnExistingGroup(t *testing.T) {
	h, db := newGroupTestHandler(t)
	w := doJSON(t, h.CreateRule, "POST", "/api/nftables/rules",
		`{"group_id":"nao-existe","action":"accept","proto":"tcp","dport":"22"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("esperava 400 para grupo inexistente, obtive %d (%s)", w.Code, w.Body.String())
	}
	w = doJSON(t, h.CreateRule, "POST", "/api/nftables/rules",
		`{"action":"accept","proto":"tcp","dport":"22"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("esperava 400 para regra sem grupo, obtive %d (%s)", w.Code, w.Body.String())
	}
	rules, _ := db.ListFirewallRules()
	if len(rules) != 0 {
		t.Fatal("regra órfã foi gravada")
	}
}

// C-1: o pré-voo de TODA mutação de regra roda num firewall onde a chain
// user_rules não existe mais (a migração da Task 5 a removeu). Validar a
// user_rules ali devolve 400 com a mensagem crua do nft para criar, editar e
// reativar — o painel inteiro de regras parado em produção.
func TestRuleMutationsPassPreflightWithoutTheUserRulesChain(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)
	if _, ok := exec.chains[nftables.UserChain]; ok {
		t.Fatal("a fixture precisa nascer SEM a chain user_rules, como a produção depois da migração")
	}
	g := createGroupViaAPI(t, h, db, `{"name":"Minhas regras","fallthrough":"continue"}`)

	w := doJSON(t, h.CreateRule, "POST", "/api/nftables/rules",
		`{"group_id":"`+g.ID+`","action":"accept","proto":"tcp","dport":"22"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("criar regra: status %d, body %s", w.Code, w.Body.String())
	}
	rules, _ := db.ListFirewallRules()
	if len(rules) != 1 {
		t.Fatalf("esperava a regra gravada, obtive %+v", rules)
	}
	id := rules[0].ID

	w = doJSON(t, h.UpdateRule, "PUT", "/api/nftables/rules",
		`{"id":"`+id+`","group_id":"`+g.ID+`","action":"drop","proto":"tcp","dport":"23"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("editar regra: status %d, body %s", w.Code, w.Body.String())
	}

	w = doJSON(t, h.ToggleRule, "POST", "/api/nftables/rules/toggle", `{"id":"`+id+`","enabled":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("desativar regra: status %d, body %s", w.Code, w.Body.String())
	}
	w = doJSON(t, h.ToggleRule, "POST", "/api/nftables/rules/toggle", `{"id":"`+id+`","enabled":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("reativar regra: status %d, body %s", w.Code, w.Body.String())
	}
}

// C-2: editar uma regra pelo painel não pode expulsá-la do grupo. Sem o
// group_id preservado, storedGroups descarta a regra com um slog.Warn: ela
// some do firewall e continua na tela.
func TestUpdateRuleKeepsTheRuleInsideItsGroup(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)
	g := createGroupViaAPI(t, h, db, `{"name":"Minhas regras","fallthrough":"continue"}`)
	rule := createRuleViaAPI(t, h, db,
		`{"group_id":"`+g.ID+`","action":"accept","saddr":"10.0.0.1"}`)
	exec.executed = nil

	w := doJSON(t, h.UpdateRule, "PUT", "/api/nftables/rules",
		`{"id":"`+rule.ID+`","action":"drop","saddr":"10.0.0.9","description":"editada"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("UpdateRule: status %d, body %s", w.Code, w.Body.String())
	}

	rules, _ := db.ListFirewallRules()
	if len(rules) != 1 {
		t.Fatalf("esperava uma regra, obtive %+v", rules)
	}
	if rules[0].GroupID != g.ID {
		t.Errorf("a edição expulsou a regra do grupo: group_id=%q, esperado %q", rules[0].GroupID, g.ID)
	}
	want := "add rule inet linkguard " + g.ChainName + " ip saddr 10.0.0.9 counter drop"
	if !exec.ranWith(want) {
		t.Errorf("a regra editada não chegou à chain do grupo; esperava %q em %v", want, exec.executed)
	}
}

// ─── Edição, remoção, ligar/desligar, ordem ───────────────────────────────

func TestUpdateGroupChangesTheConditionKeepingChainAndPosition(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)
	g := createGroupViaAPI(t, h, db, `{"name":"Servidores","cond_saddr":"192.168.50.0/24","fallthrough":"continue"}`)

	bad := doJSON(t, h.UpdateGroup, "PUT", "/api/nftables/groups",
		`{"id":"`+g.ID+`","name":"Servidores","cond_saddr":"2001:db8::1","fallthrough":"continue"}`)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("esperava 400 para condição inválida, obtive %d (%s)", bad.Code, bad.Body.String())
	}
	unknown := doJSON(t, h.UpdateGroup, "PUT", "/api/nftables/groups",
		`{"id":"fantasma","name":"x","fallthrough":"continue"}`)
	if unknown.Code != http.StatusBadRequest {
		t.Errorf("esperava 400 para id desconhecido, obtive %d (%s)", unknown.Code, unknown.Body.String())
	}

	w := doJSON(t, h.UpdateGroup, "PUT", "/api/nftables/groups",
		`{"id":"`+g.ID+`","name":"Servidores da sala","cond_saddr":"192.168.60.0/24","fallthrough":"drop"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("UpdateGroup: status %d, body %s", w.Code, w.Body.String())
	}
	groups, _ := db.ListFirewallGroups()
	if len(groups) != 1 {
		t.Fatalf("esperava um grupo, obtive %+v", groups)
	}
	got := groups[0]
	if got.Name != "Servidores da sala" || got.CondSaddr != "192.168.60.0/24" || got.Fallthrough != nftables.FallthroughDrop {
		t.Errorf("a edição não foi aplicada: %+v", got)
	}
	if got.ChainName != g.ChainName || got.Position != g.Position || got.Enabled != g.Enabled {
		t.Errorf("editar o conteúdo não pode mexer em chain/posição/estado: antes %+v, depois %+v", g, got)
	}
	if !exec.ranWith("ip saddr 192.168.60.0/24 counter jump " + g.ChainName) {
		t.Errorf("a forward não foi reconstruída com a condição nova: %v", exec.executed)
	}
}

func TestDeleteGroupRemovesItsRules(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)
	g := createGroupViaAPI(t, h, db, `{"name":"Minhas regras","fallthrough":"continue"}`)
	createRuleViaAPI(t, h, db, `{"group_id":"`+g.ID+`","action":"drop","saddr":"10.0.0.5"}`)
	other := createGroupViaAPI(t, h, db, `{"name":"Convidados","fallthrough":"continue"}`)
	keep := createRuleViaAPI(t, h, db, `{"group_id":"`+other.ID+`","action":"accept","saddr":"10.0.0.6"}`)

	unknown := doJSON(t, h.DeleteGroup, "DELETE", "/api/nftables/groups", `{"id":"fantasma"}`)
	if unknown.Code != http.StatusBadRequest {
		t.Errorf("esperava 400 para id desconhecido, obtive %d (%s)", unknown.Code, unknown.Body.String())
	}

	w := doJSON(t, h.DeleteGroup, "DELETE", "/api/nftables/groups", `{"id":"`+g.ID+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("DeleteGroup: status %d, body %s", w.Code, w.Body.String())
	}

	groups, _ := db.ListFirewallGroups()
	if len(groups) != 1 || groups[0].ID != other.ID {
		t.Fatalf("esperava só o outro grupo, obtive %+v", groups)
	}
	rules, _ := db.ListFirewallRules()
	if len(rules) != 1 || rules[0].ID != keep.ID {
		t.Fatalf("as regras do grupo removido tinham que sumir junto, obtive %+v", rules)
	}
	if _, alive := exec.chains[g.ChainName]; alive {
		t.Errorf("a chain do grupo removido continua no firewall: %v", exec.chains)
	}
	if exec.forwardHasJumpTo(g.ChainName) {
		t.Errorf("a forward continua pulando para o grupo removido: %v", exec.chains[nftables.ForwardChain])
	}
	if _, alive := exec.chains[other.ChainName]; !alive {
		t.Errorf("o outro grupo não podia ter sido tocado: %v", exec.chains)
	}
}

// Desligar um grupo é tirar o jump: as regras continuam guardadas na chain,
// prontas para quando ele voltar (spec §2.1).
func TestToggleGroupOnlyRemovesTheJump(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)
	g := createGroupViaAPI(t, h, db, `{"name":"Minhas regras","fallthrough":"continue"}`)
	createRuleViaAPI(t, h, db, `{"group_id":"`+g.ID+`","action":"drop","saddr":"10.0.0.5"}`)

	w := doJSON(t, h.ToggleGroup, "POST", "/api/nftables/groups/toggle", `{"id":"`+g.ID+`","enabled":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("ToggleGroup: status %d, body %s", w.Code, w.Body.String())
	}
	groups, _ := db.ListFirewallGroups()
	if groups[0].Enabled {
		t.Error("o grupo continua ligado no banco")
	}
	if exec.forwardHasJumpTo(g.ChainName) {
		t.Error("desligar o grupo tinha que tirar o jump da forward")
	}
	if len(exec.chains[g.ChainName]) != 1 {
		t.Errorf("as regras do grupo desligado continuam guardadas na chain, obtive %v", exec.chains[g.ChainName])
	}

	w = doJSON(t, h.ToggleGroup, "POST", "/api/nftables/groups/toggle", `{"id":"`+g.ID+`","enabled":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("religar: status %d, body %s", w.Code, w.Body.String())
	}
	if !exec.forwardHasJumpTo(g.ChainName) {
		t.Error("religar o grupo tinha que devolver o jump à forward")
	}

	if bad := doJSON(t, h.ToggleGroup, "POST", "/api/nftables/groups/toggle",
		`{"id":"fantasma","enabled":true}`); bad.Code != http.StatusBadRequest {
		t.Errorf("esperava 400 para id desconhecido, obtive %d", bad.Code)
	}
}

// Lista parcial ou com id desconhecido produz posições duplicadas em
// silêncio (ReorderFirewallGroups escreve o índice de cada id que existe e
// deixa os outros onde estavam). A recusa é do handler, que é quem tem a
// requisição e a lista atual para comparar.
func TestReorderGroupsRejectsUnknownID(t *testing.T) {
	h, db, _ := newGroupTestHandlerNft(t)
	a := createGroupViaAPI(t, h, db, `{"name":"A","fallthrough":"continue"}`)
	b := createGroupViaAPI(t, h, db, `{"name":"B","fallthrough":"continue"}`)

	for _, body := range []string{
		`{"ids":["` + b.ID + `","fantasma"]}`,     // id desconhecido
		`{"ids":["` + b.ID + `"]}`,                // lista parcial
		`{"ids":["` + b.ID + `","` + b.ID + `"]}`, // id repetido
		`{"ids":[]}`, // vazia
	} {
		w := doJSON(t, h.ReorderGroups, "POST", "/api/nftables/groups/reorder", body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("corpo %s: esperava 400, obtive %d (%s)", body, w.Code, w.Body.String())
		}
	}

	groups, _ := db.ListFirewallGroups()
	if len(groups) != 2 || groups[0].ID != a.ID || groups[1].ID != b.ID {
		t.Fatalf("a ordem original tinha que ficar intacta, obtive %+v", groups)
	}

	w := doJSON(t, h.ReorderGroups, "POST", "/api/nftables/groups/reorder",
		`{"ids":["`+b.ID+`","`+a.ID+`"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("reordenar com a lista completa: status %d, body %s", w.Code, w.Body.String())
	}
	groups, _ = db.ListFirewallGroups()
	if groups[0].ID != b.ID || groups[1].ID != a.ID {
		t.Fatalf("a ordem nova não foi gravada: %+v", groups)
	}
}

// ─── Leitura ──────────────────────────────────────────────────────────────

type groupsResponseBody struct {
	Groups []struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		ChainName string `json:"chain_name"`
		Enabled   bool   `json:"enabled"`
		Applied   bool   `json:"applied"`
		Rules     struct {
			Rules []struct {
				Expression string `json:"expression"`
				Applied    bool   `json:"applied"`
				Enabled    *bool  `json:"enabled"`
			} `json:"rules"`
		} `json:"rules"`
	} `json:"groups"`
	ApplyStatus *firewallrules.ApplyStatus `json:"apply_status"`
}

func TestListGroupsIsHonestAboutWhatIsApplied(t *testing.T) {
	h, db, _ := newGroupTestHandlerNft(t)
	live := createGroupViaAPI(t, h, db, `{"name":"Ligado","fallthrough":"continue"}`)
	createRuleViaAPI(t, h, db, `{"group_id":"`+live.ID+`","action":"drop","saddr":"10.0.0.5"}`)
	off := createRuleViaAPI(t, h, db, `{"group_id":"`+live.ID+`","action":"accept","saddr":"10.0.0.6"}`)
	if w := doJSON(t, h.ToggleRule, "POST", "/api/nftables/rules/toggle",
		`{"id":"`+off.ID+`","enabled":false}`); w.Code != http.StatusOK {
		t.Fatalf("desativar a regra: %d %s", w.Code, w.Body.String())
	}
	dark := createGroupViaAPI(t, h, db, `{"name":"Desligado","fallthrough":"continue"}`)
	createRuleViaAPI(t, h, db, `{"group_id":"`+dark.ID+`","action":"drop","saddr":"10.0.0.7"}`)
	if w := doJSON(t, h.ToggleGroup, "POST", "/api/nftables/groups/toggle",
		`{"id":"`+dark.ID+`","enabled":false}`); w.Code != http.StatusOK {
		t.Fatalf("desligar o grupo: %d %s", w.Code, w.Body.String())
	}

	w := doJSON(t, h.ListGroups, "GET", "/api/nftables/groups", "")
	if w.Code != http.StatusOK {
		t.Fatalf("ListGroups: status %d, body %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "null") {
		t.Fatalf("a resposta nunca pode trazer null: %s", w.Body.String())
	}
	var body groupsResponseBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v (body %s)", err, w.Body.String())
	}
	if len(body.Groups) != 2 {
		t.Fatalf("esperava 2 grupos, obtive %+v", body.Groups)
	}
	if body.ApplyStatus == nil || !body.ApplyStatus.OK {
		t.Errorf("esperava o apply-status da última reconciliação, obtive %+v", body.ApplyStatus)
	}

	first := body.Groups[0]
	if first.ID != live.ID || !first.Applied {
		t.Errorf("o grupo ligado tinha que aparecer aplicado (jump vivo na forward): %+v", first)
	}
	if len(first.Rules.Rules) != 2 {
		t.Fatalf("a regra desativada mora só no banco e não pode sumir da lista: %+v", first.Rules.Rules)
	}
	var seenKept, seenOff bool
	for _, r := range first.Rules.Rules {
		switch {
		case strings.Contains(r.Expression, "10.0.0.5"):
			seenKept = true
			if !r.Applied {
				t.Errorf("a regra ativa está no firewall e tinha que aparecer aplicada: %+v", r)
			}
		case strings.Contains(r.Expression, "10.0.0.6"):
			seenOff = true
			if r.Applied {
				t.Errorf("a regra desativada não está no firewall: %+v", r)
			}
		}
	}
	if !seenKept || !seenOff {
		t.Errorf("faltou uma das regras na visão do grupo: %+v", first.Rules.Rules)
	}

	second := body.Groups[1]
	if second.ID != dark.ID || second.Applied {
		t.Errorf("o grupo desligado não tem jump: Applied tinha que ser falso: %+v", second)
	}
	for _, r := range second.Rules.Rules {
		if r.Applied {
			t.Errorf("nada dentro de um grupo sem jump está em vigor: %+v", r)
		}
	}
}

// I-3: a Visão geral parou de mostrar as regras desativadas quando a chain
// user_rules foi apagada — o merge só rodava nela. As regras do admin agora
// moram nas chains grp_, e é lá que a interleaving com o banco tem que
// acontecer, senão a única tela que mostra o firewall inteiro esconde
// exatamente o que não está nele.
func TestOverviewKeepsDisabledRulesInsideTheGroupChain(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)
	g := createGroupViaAPI(t, h, db, `{"name":"Minhas regras","fallthrough":"continue"}`)
	createRuleViaAPI(t, h, db, `{"group_id":"`+g.ID+`","action":"drop","saddr":"10.0.0.5"}`)
	off := createRuleViaAPI(t, h, db, `{"group_id":"`+g.ID+`","action":"accept","saddr":"10.0.0.6"}`)
	if w := doJSON(t, h.ToggleRule, "POST", "/api/nftables/rules/toggle",
		`{"id":"`+off.ID+`","enabled":false}`); w.Code != http.StatusOK {
		t.Fatalf("desativar a regra: %d %s", w.Code, w.Body.String())
	}
	if len(exec.chains[g.ChainName]) != 1 {
		t.Fatalf("a fixture precisa ter a regra desativada FORA do nft, obtive %v", exec.chains[g.ChainName])
	}

	w := doJSON(t, h.Overview, "GET", "/api/nftables/overview", "")
	if w.Code != http.StatusOK {
		t.Fatalf("Overview: status %d, body %s", w.Code, w.Body.String())
	}
	var chains []nftables.ChainInfo
	if err := json.Unmarshal(w.Body.Bytes(), &chains); err != nil {
		t.Fatalf("decode: %v (body %s)", err, w.Body.String())
	}
	var grp *nftables.ChainInfo
	for i := range chains {
		if chains[i].Name == g.ChainName {
			grp = &chains[i]
		}
	}
	if grp == nil {
		t.Fatalf("a chain do grupo sumiu da visão geral: %+v", chains)
	}
	if len(grp.Rules) != 2 {
		t.Fatalf("esperava as 2 regras (a desativada mora só no banco), obtive %+v", grp.Rules)
	}
	for _, r := range grp.Rules {
		switch {
		case strings.Contains(r.Expression, "10.0.0.6"):
			if r.Applied {
				t.Errorf("a regra desativada não está no firewall: %+v", r)
			}
			if r.Enabled == nil || *r.Enabled {
				t.Errorf("a regra desativada tinha que vir marcada como desativada: %+v", r)
			}
		case strings.Contains(r.Expression, "10.0.0.5"):
			if !r.Applied {
				t.Errorf("a regra ativa está no firewall: %+v", r)
			}
		}
	}
}

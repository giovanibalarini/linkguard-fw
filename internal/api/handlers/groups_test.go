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
	"sync"
	"testing"
	"time"

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
	// mu existe porque há teste que dispara duas requisições ao mesmo tempo
	// (a corrida da janela de confirmação). Sem ela o -race acusa este falso,
	// não o código que está sendo medido.
	mu       sync.Mutex
	chains   map[string][]string // chain viva → expressões, na ordem
	executed []string
	// applyRefusesIn são as chains cujo `add rule` falha no APPLY e passa no
	// pré-voo. É o cenário que a revisão da Fase C2 reproduziu por sonda: numa
	// máquina em que qualquer outro grupo tem uma regra que o nft recusa na
	// hora de aplicar, o Reconcile devolve erro (ReconcileGroups junta as
	// falhas por grupo) DEPOIS de já ter reconstruído a chain input. Como
	// nftRefusesToken, é um marcador de teste para a categoria — não a imitação
	// de uma sintaxe específica.
	applyRefusesIn map[string]bool
	// checked guarda o TEXTO de cada script que passou pelo pré-voo `nft -c
	// -f`. Sem isso não há como um teste afirmar que o pré-voo validou a MESMA
	// linha que o apply escreveu — e é exatamente aí que uma conversão
	// incompleta se esconde: o dry run aprova a linha antiga, o apply escreve
	// outra, e as duas passam.
	checked []string
}

// errNoSuchChain é a mensagem que o nft dá para referência a chain
// inexistente, tanto no comando solto quanto dentro de `nft -c -f`.
var errNoSuchChain = errors.New("Error: No such file or directory")

// ─── Recusa por CONTEÚDO ──────────────────────────────────────────────────
//
// Recusar só por chain faltando prova metade da invariante. A ordem
// obrigatória de toda mutação é validar campos → pré-voo `nft -c` → gravar no
// banco → reconciliar, e a metade que importa é a segunda seta: NADA chega ao
// banco antes de o nft aceitar. Um falso que aprova todo conteúdo nunca chega
// a exercitá-la — mover a escrita para antes do pré-voo passava pela suíte
// inteira sem um teste vermelho, porque os testes de "nada foi gravado"
// morriam uma camada antes, na validação de campo, e nunca alcançavam o nft.
//
// nftRefusesToken é um MARCADOR DE TESTE, não a imitação de uma recusa real
// do nft: o que ele existe para simular é a categoria inteira de recusas
// semânticas que a validação de campo não pega (o motivo de o pré-voo
// existir), sem depender de descobrir e fixar aqui uma sintaxe específica que
// o nft de hoje recusa. Ele passa em reIface (15 caracteres, [a-z]) e em
// ValidateGroup, então chega intacto até o `nft -c` — é lá, e só lá, que
// morre. Serve como interface (regra) e como condição de entrada (grupo).
const nftRefusesToken = "recusadapelonft"

// errNftRefusedContent é a cara de uma recusa de conteúdo do nft: a mensagem
// crua dele, que o handler propaga para o admin no 400.
var errNftRefusedContent = errors.New("Error: syntax error, unexpected string")

func newFakeNft() *fakeNft {
	return &fakeNft{chains: map[string][]string{nftables.ForwardChain: {}}}
}

func (f *fakeNft) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.executed = append(f.executed, cmd+" "+strings.Join(args, " "))
	if cmd != "nft" {
		return "", nil
	}
	if err := f.refusedAtApply(args); err != nil {
		return "", err
	}
	return "", applyNftCommand(f.chains, args)
}

// refusedAtApply é a recusa que o dry run NÃO vê: `nft -c` aprova o script e o
// comando de verdade falha. Chamada com f.mu travado.
func (f *fakeNft) refusedAtApply(args []string) error {
	if len(f.applyRefusesIn) == 0 || len(args) < 5 {
		return nil
	}
	if args[0] == "add" && args[1] == "rule" && f.applyRefusesIn[args[4]] {
		return errNftRefusedContent
	}
	return nil
}

// refuseApplyIn liga a recusa no apply para uma chain; devolve a função que a
// desliga (a máquina "voltando", que é quando o watchdog consegue reverter).
func (f *fakeNft) refuseApplyIn(chain string) func() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.applyRefusesIn == nil {
		f.applyRefusesIn = map[string]bool{}
	}
	f.applyRefusesIn[chain] = true
	return func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		delete(f.applyRefusesIn, chain)
	}
}

func (f *fakeNft) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
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
	f.checked = append(f.checked, string(body))
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
		if strings.Contains(expr, nftRefusesToken) {
			// Recusa por CONTEÚDO — a que o pré-voo existe para pegar e que
			// nenhuma validação de campo alcança.
			return errNftRefusedContent
		}
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
	return f.chainHasJumpTo(nftables.ForwardChain, chain)
}

// chainHasJumpTo pergunta se a chain VIVA pula para outra — é como um teste
// enxerga o firewall do jeito que o operador o enxergaria.
func (f *fakeNft) chainHasJumpTo(chain, target string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, expr := range f.chains[chain] {
		if jumpTargetOf(expr) == target {
			return true
		}
	}
	return false
}

// liveChain devolve uma cópia das expressões da chain viva.
func (f *fakeNft) liveChain(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.chains[name]...)
}

// checkedWith diz se algum script de pré-voo continha o trecho. Chamado sem
// travar f.mu porque ExecuteRead já o mantém travado durante o check e os
// testes que usam isto leem depois da requisição.
func (f *fakeNft) checkedWith(substr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, script := range f.checked {
		if strings.Contains(script, substr) {
			return true
		}
	}
	return false
}

func (f *fakeNft) ranWith(substr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
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
	h, db, exec, _ := newGroupTestHandlerFR(t)
	return h, db, exec
}

// newGroupTestHandlerFR devolve também o firewallrules.Service — é por ele que
// um teste abre a janela de confirmação sem passar por um handler (openWindow),
// que é o único jeito de medir a TRAVA isoladamente: se abrir a janela
// dependesse de uma mutação, um defeito na trava e um defeito no arme dela
// ficariam indistinguíveis.
func newGroupTestHandlerFR(t *testing.T) (*handlers.NftablesHandler, *storage.DB, *fakeNft, *firewallrules.Service) {
	t.Helper()
	h, db, exec, fr, _ := newGroupTestHandlerConf(t)
	return h, db, exec, fr
}

// newGroupTestHandlerConf é a fixture completa, com o caminho do ARQUIVO DE
// BOOT desta máquina de teste — o /etc/nftables.conf que o nftables.service
// carregaria antes de o LinkGuard subir.
//
// Ele é por teste (t.TempDir()), e não o do TestMain deste pacote, porque a
// partir da Fase C2 há teste que AFIRMA o conteúdo do arquivo: um arquivo
// compartilhado por toda a suíte carregaria o dump deixado pelo teste anterior.
//
// A guarda do Persist é ligada aqui pela mesma razão que SetInputChainSources:
// é assim que o binário de produção monta os dois serviços (main.go), e uma
// fixture sem ela mediria um LinkGuard que não existe.
func newGroupTestHandlerConf(t *testing.T) (*handlers.NftablesHandler, *storage.DB, *fakeNft, *firewallrules.Service, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	exec := newFakeNft()
	svc := nftables.NewService(exec)
	confPath := filepath.Join(dir, "nftables.conf")
	svc.SetConfPath(confPath)
	// m3 da revisão da Fase C2: sem uma fonte de NTP ligada, a reconciliação
	// da chain input agora devolve erro (fechou o fail-open de fonte não
	// ligada) em vez do antigo "NTP desligado" silencioso — o que faria todo
	// CRUD de grupo destes testes responder 500 só por causa da chain input,
	// que nenhum deles exercita. Declara a intenção explicitamente: nenhum
	// grupo de escopo input, NTP desligado.
	svc.SetInputChainSources(
		func() ([]nftables.StoredGroup, error) { return nil, nil },
		func() ([]string, bool, error) { return nil, false, nil },
	)
	fr := firewallrules.NewService(db, svc)
	svc.SetPersistGuard(fr.UnconfirmedChangePending)
	// Como no boot: sem os dois grupos do sistema na lista, o Reconcile de
	// toda mutação se recusa a reconstruir a chain forward.
	if err := fr.EnsureSystemGroups(context.Background()); err != nil {
		t.Fatalf("EnsureSystemGroups: %v", err)
	}
	return handlers.NewNftablesHandler(svc, db, fr), db, exec, fr, confPath
}

// adminGroups são os grupos que o admin criou. Toda máquina carrega também
// os dois grupos do sistema (os bloqueios), criados no boot antes de
// qualquer coisa que reconcilie — e eles não interessam a um teste que está
// medindo o CRUD de grupo do admin.
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
	if groups := adminGroups(t, db); len(groups) != 0 {
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
	groups := adminGroups(t, db)
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

	groups := adminGroups(t, db)
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
	if groups := adminGroups(t, db); groups[0].Enabled {
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

	groups := adminGroups(t, db)
	if len(groups) != 2 || groups[0].ID != a.ID || groups[1].ID != b.ID {
		t.Fatalf("a ordem original tinha que ficar intacta, obtive %+v", groups)
	}

	// A lista COMPLETA inclui os dois grupos do sistema: eles são linhas de
	// grupo como as outras e entram na mesma reordenação (é o que permite ao
	// admin escolher onde os bloqueios são avaliados).
	all, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatalf("ListFirewallGroups: %v", err)
	}
	ids := make([]string, 0, len(all))
	for _, g := range all {
		if g.ID != a.ID && g.ID != b.ID {
			ids = append(ids, `"`+g.ID+`"`)
		}
	}
	ids = append(ids, `"`+b.ID+`"`, `"`+a.ID+`"`)

	w := doJSON(t, h.ReorderGroups, "POST", "/api/nftables/groups/reorder",
		`{"ids":[`+strings.Join(ids, ",")+`]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("reordenar com a lista completa: status %d, body %s", w.Code, w.Body.String())
	}
	groups = adminGroups(t, db)
	if groups[0].ID != b.ID || groups[1].ID != a.ID {
		t.Fatalf("a ordem nova não foi gravada: %+v", groups)
	}
}

// ─── Leitura ──────────────────────────────────────────────────────────────

type groupView struct {
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
}

type groupsResponseBody struct {
	Groups      []groupView                `json:"groups"`
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
	// Os dois grupos do sistema vêm na frente em toda máquina; o que este
	// teste mede é a honestidade da visão dos grupos do ADMIN.
	//
	// Eles chegam aqui com applied=false, e isso é um desvio conhecido: um
	// grupo do sistema não tem chain própria, então MergeGroups não acha
	// jump nenhum para ele na forward e conclui "não aplicado" — para dois
	// bloqueios que estão valendo. É da tarefa que arruma o MergeGroups.
	var admin []groupView
	for _, g := range body.Groups {
		if !strings.HasPrefix(g.ChainName, "sys_") {
			admin = append(admin, g)
		}
	}
	if len(admin) != 2 {
		t.Fatalf("esperava 2 grupos do admin, obtive %+v", body.Groups)
	}
	if body.ApplyStatus == nil || !body.ApplyStatus.OK {
		t.Errorf("esperava o apply-status da última reconciliação, obtive %+v", body.ApplyStatus)
	}

	first := admin[0]
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

	second := admin[1]
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

// C-2, no payload de verdade: as duas regras do MESMO admin, no MESMO grupo,
// precisam voltar classificadas do mesmo jeito. Antes, a ativada (lida do nft
// vivo, chain grp_) vinha managed=true / owner "LinkGuard" / descrição crua, e
// a desativada (sintética) vinha do admin e em português — lado a lado, na
// mesma lista.
func TestOverviewClassifiesGroupRulesAsTheAdminsOwn(t *testing.T) {
	h, db, _ := newGroupTestHandlerNft(t)
	g := createGroupViaAPI(t, h, db, `{"name":"Minhas regras","fallthrough":"continue"}`)
	createRuleViaAPI(t, h, db, `{"group_id":"`+g.ID+`","action":"drop","saddr":"10.0.0.5"}`)
	off := createRuleViaAPI(t, h, db, `{"group_id":"`+g.ID+`","action":"accept","saddr":"10.0.0.6"}`)
	if w := doJSON(t, h.ToggleRule, "POST", "/api/nftables/rules/toggle",
		`{"id":"`+off.ID+`","enabled":false}`); w.Code != http.StatusOK {
		t.Fatalf("desativar a regra: %d %s", w.Code, w.Body.String())
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
		t.Fatalf("esperava as 2 regras do grupo, obtive %+v", grp.Rules)
	}
	for _, r := range grp.Rules {
		if r.Chain != g.ChainName {
			t.Errorf("regra diz morar em %q, e não na chain do grupo %q: %+v", r.Chain, g.ChainName, r)
		}
		if r.Managed {
			t.Errorf("regra do admin marcada como gerenciada pelo LinkGuard: %+v", r)
		}
		if r.Owner.Key != "" || r.Owner.Label != "" {
			t.Errorf("regra do admin não tem dono, obtive %+v", r.Owner)
		}
		if r.Description == r.Expression {
			t.Errorf("a descrição tem que sair em português, não a expressão crua: %+v", r)
		}
	}
}

// ─── A invariante inegociável: nada chega ao banco antes de o nft aceitar ──
//
// Validar campos → pré-voo `nft -c` → gravar → reconciliar. Estes dois testes
// são a rede da segunda seta, a que não tinha nenhuma: eles exercitam uma
// recusa POR CONTEÚDO (nftRefusesToken), que atravessa a validação de campo
// inteira e só morre no nft — exatamente o motivo de o pré-voo existir.
//
// Prova por mutação (feita, e a repetir quando alguém mexer nesta ordem):
// mover h.db.CreateFirewallRule / h.db.CreateFirewallGroup para ANTES do
// pré-voo deixa os dois vermelhos, com a regra/o grupo gravados no banco e
// ausentes do firewall — a "proteção configurada que não existe" que o
// projeto chama de inaceitável.

func TestCreateRuleRefusedByNftNeverReachesTheDB(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)
	g := createGroupViaAPI(t, h, db, `{"name":"Minhas regras","fallthrough":"continue"}`)
	exec.executed = nil

	w := doJSON(t, h.CreateRule, "POST", "/api/nftables/rules",
		`{"group_id":"`+g.ID+`","action":"accept","iif":"`+nftRefusesToken+`","proto":"tcp","dport":"22"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("esperava 400 com a recusa do nft, obtive %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), errNftRefusedContent.Error()) {
		t.Errorf("o 400 tem que carregar a mensagem do próprio nft, obtive %s", w.Body.String())
	}

	rules, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("a regra chegou ao banco antes de o nft aceitar: %+v", rules)
	}
	if exec.ranWith("add rule") {
		t.Errorf("nada podia ter sido escrito no firewall: %v", exec.executed)
	}
	if len(exec.chains[g.ChainName]) != 0 {
		t.Errorf("a chain do grupo devia continuar vazia, obtive %v", exec.chains[g.ChainName])
	}
}

func TestCreateGroupRefusedByNftNeverReachesTheDB(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)

	w := doJSON(t, h.CreateGroup, "POST", "/api/nftables/groups",
		`{"name":"Visitantes","cond_iif":"`+nftRefusesToken+`","fallthrough":"drop"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("esperava 400 com a recusa do nft, obtive %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), errNftRefusedContent.Error()) {
		t.Errorf("o 400 tem que carregar a mensagem do próprio nft, obtive %s", w.Body.String())
	}

	if groups := adminGroups(t, db); len(groups) != 0 {
		t.Fatalf("o grupo chegou ao banco antes de o nft aceitar: %+v", groups)
	}
	for name := range exec.chains {
		if strings.HasPrefix(name, nftables.GroupChainPrefix) {
			t.Errorf("nenhuma chain de grupo podia ter sido criada, obtive %v", exec.chains)
		}
	}
}

// ─── Mover uma regra de grupo ─────────────────────────────────────────────
//
// É o group_id do corpo que move a regra (UpdateRule), e é a única coisa que
// o cliente pode dizer sobre chain nenhuma. Tirar o requireGroup dali deixava
// a suíte verde: o cliente passava a poder mandar um group_id qualquer, a
// linha era gravada órfã e a reconciliação a descartava com um slog.Warn —
// ela sumia do firewall e continuava na tela, sem 400 nenhum. Perda
// silenciosa, o defeito que este painel existe para não ter.

func TestUpdateRuleMovesTheRuleToAnotherGroup(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)
	from := createGroupViaAPI(t, h, db, `{"name":"Origem","fallthrough":"continue"}`)
	to := createGroupViaAPI(t, h, db, `{"name":"Destino","fallthrough":"continue"}`)
	rule := createRuleViaAPI(t, h, db, `{"group_id":"`+from.ID+`","action":"drop","saddr":"10.0.0.5"}`)
	exec.executed = nil

	w := doJSON(t, h.UpdateRule, "PUT", "/api/nftables/rules",
		`{"id":"`+rule.ID+`","group_id":"`+to.ID+`","action":"drop","saddr":"10.0.0.5"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("mover a regra: status %d, body %s", w.Code, w.Body.String())
	}

	rules, _ := db.ListFirewallRules()
	if len(rules) != 1 || rules[0].GroupID != to.ID {
		t.Fatalf("a regra tinha que estar no grupo destino, obtive %+v", rules)
	}
	// O que decide de verdade é onde o kernel avalia a regra, não o banco.
	if want := "add rule inet linkguard " + to.ChainName + " ip saddr 10.0.0.5 counter drop"; !exec.ranWith(want) {
		t.Errorf("a regra não foi renderizada na chain do destino; esperava %q em %v", want, exec.executed)
	}
	if len(exec.chains[to.ChainName]) != 1 {
		t.Errorf("a chain do destino tinha que ter a regra, obtive %v", exec.chains[to.ChainName])
	}
	if len(exec.chains[from.ChainName]) != 0 {
		t.Errorf("a chain de origem tinha que ficar vazia, obtive %v", exec.chains[from.ChainName])
	}
}

func TestUpdateRuleRefusesAnUnknownGroupAndLeavesTheRuleWhereItWas(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)
	g := createGroupViaAPI(t, h, db, `{"name":"Origem","fallthrough":"continue"}`)
	rule := createRuleViaAPI(t, h, db, `{"group_id":"`+g.ID+`","action":"drop","saddr":"10.0.0.5"}`)

	w := doJSON(t, h.UpdateRule, "PUT", "/api/nftables/rules",
		`{"id":"`+rule.ID+`","group_id":"fantasma","action":"accept","saddr":"10.0.0.9"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("esperava 400 para grupo inexistente, obtive %d (%s)", w.Code, w.Body.String())
	}

	rules, _ := db.ListFirewallRules()
	if len(rules) != 1 {
		t.Fatalf("esperava a regra intacta, obtive %+v", rules)
	}
	if rules[0].GroupID != g.ID {
		t.Errorf("a regra saiu do grupo dela: group_id=%q, esperado %q", rules[0].GroupID, g.ID)
	}
	if rules[0].Action != "drop" || rules[0].Saddr != "10.0.0.5" {
		t.Errorf("a edição recusada não podia ter mexido no conteúdo: %+v", rules[0])
	}
	if got := exec.chains[g.ChainName]; len(got) != 1 || !strings.Contains(got[0], "10.0.0.5") {
		t.Errorf("a chain do grupo tinha que continuar com a regra original, obtive %v", got)
	}
}

// G-3: reativar é a única metade do ToggleRule que ACRESCENTA linha ao
// firewall, e por isso a única que precisa de pré-voo. Uma regra desativada
// nunca é validada enquanto está desativada (o create/update dela pode ter
// sido de outra versão, o banco pode ter sido editado à mão): sem o pré-voo,
// ligar o interruptor grava enabled=true e só então o nft recusa, no meio da
// reconciliação — a regra fica no banco e na tela como ativada, e fora do
// firewall. Remover o pré-voo daqui não era pego por teste nenhum.
func TestToggleRuleRefusesToReenableWhatNftRejects(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)
	g := createGroupViaAPI(t, h, db, `{"name":"Minhas regras","fallthrough":"continue"}`)

	// Uma linha "velha" gravada direto no banco, desativada: é exatamente o
	// caso que o pré-voo existe para pegar, porque ela nunca passou pelo
	// create/update desta versão.
	stale := &storage.FirewallRule{GroupID: g.ID, Action: "accept", Iif: nftRefusesToken}
	if err := db.CreateFirewallRule(stale); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}
	if err := db.SetFirewallRuleEnabled(stale.ID, false); err != nil {
		t.Fatalf("SetFirewallRuleEnabled: %v", err)
	}
	exec.executed = nil

	w := doJSON(t, h.ToggleRule, "POST", "/api/nftables/rules/toggle",
		`{"id":"`+stale.ID+`","enabled":true}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("esperava 400 com a recusa do nft, obtive %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), errNftRefusedContent.Error()) {
		t.Errorf("o 400 tem que carregar a mensagem do próprio nft, obtive %s", w.Body.String())
	}

	rules, _ := db.ListFirewallRules()
	if len(rules) != 1 {
		t.Fatalf("esperava a regra, obtive %+v", rules)
	}
	if rules[0].Enabled {
		t.Error("a regra foi marcada como ativada mesmo com o nft recusando: o painel diria que ela vale")
	}
	if len(exec.chains[g.ChainName]) != 0 {
		t.Errorf("nada podia ter entrado na chain do grupo, obtive %v", exec.chains[g.ChainName])
	}
}

// G-4: nenhum teste provava que proto/dport/iif/oif chegam ao comando do nft
// — só saddr/daddr. Fazer o CreateRule descartar o dport em silêncio (a linha
// gravada no banco com a porta, a regra aplicada SEM ela: uma porta liberada
// para todo mundo, ou um bloqueio muito mais largo do que o admin pediu)
// passava despercebido pela suíte inteira. Cada campo é conferido sozinho,
// para que a falta de um não seja mascarada pela presença dos outros, e
// depois todos juntos, na ordem exata que buildRuleTokens emite.
func TestCreateRuleRendersEveryFieldIntoTheNftCommand(t *testing.T) {
	cases := []struct {
		nome, corpo, esperado string
	}{
		{"iif", `"iif":"enp1s0"`, "iifname enp1s0 counter accept"},
		{"oif", `"oif":"enp2s0"`, "oifname enp2s0 counter accept"},
		{"proto sem porta", `"proto":"udp"`, "ip protocol udp counter accept"},
		{"proto icmp", `"proto":"icmp"`, "ip protocol icmp counter accept"},
		{"proto com porta", `"proto":"tcp","dport":"22"`, "tcp dport 22 counter accept"},
		{"intervalo de portas", `"proto":"udp","dport":"8000-8080"`, "udp dport 8000-8080 counter accept"},
		{"tudo junto", `"iif":"enp1s0","oif":"enp2s0","saddr":"10.0.0.1","daddr":"192.168.9.0/24","proto":"tcp","dport":"443"`,
			"iifname enp1s0 oifname enp2s0 ip saddr 10.0.0.1 ip daddr 192.168.9.0/24 tcp dport 443 counter accept"},
	}
	for _, c := range cases {
		t.Run(c.nome, func(t *testing.T) {
			h, db, exec := newGroupTestHandlerNft(t)
			g := createGroupViaAPI(t, h, db, `{"name":"Minhas regras","fallthrough":"continue"}`)
			exec.executed = nil

			createRuleViaAPI(t, h, db, `{"group_id":"`+g.ID+`","action":"accept",`+c.corpo+`}`)

			want := "add rule inet linkguard " + g.ChainName + " " + c.esperado
			if !exec.ranWith(want) {
				t.Errorf("o campo não chegou ao comando do nft.\nesperava: %q\nexecutado: %v", want, exec.executed)
			}
			if got := exec.chains[g.ChainName]; len(got) != 1 || got[0] != c.esperado {
				t.Errorf("a chain do grupo ficou com %v, esperava [%q]", got, c.esperado)
			}
		})
	}
}

// C-5: o CreateGroup lia os grupos do banco ANTES de olhar para o corpo da
// requisição. Além do trabalho jogado fora numa requisição que já nasce
// inválida, isso produzia o status ERRADO: com o banco fora do ar, um corpo
// inválido virava 500 ("erro interno do servidor"), escondendo do admin que o
// problema estava no que ele mandou. Validar primeiro é o que os irmãos
// (UpdateGroup, CreateRule) já fazem.
func TestCreateGroupValidatesTheBodyBeforeReadingTheDB(t *testing.T) {
	h, db, _ := newGroupTestHandlerNft(t)
	if err := db.Close(); err != nil {
		t.Fatalf("fechar o banco: %v", err)
	}

	w := doJSON(t, h.CreateGroup, "POST", "/api/nftables/groups",
		`{"name":"Visitantes","fallthrough":"talvez"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("corpo inválido tem que ser 400 mesmo se o banco não responder, obtive %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "e o que sobrar") {
		t.Errorf("a resposta tem que dizer o que está errado no corpo, obtive %s", w.Body.String())
	}
}

// C-6: o DeleteGroup era o único handler de grupo que não resolvia o id com
// findGroup, deixando o storage responder pelo "não encontrado". Enquanto o
// banco responde, dá no mesmo; quando ele NÃO responde, a assimetria aparece:
// os irmãos (UpdateGroup, ToggleGroup) devolvem 500 — falha do servidor, que é
// o que é —, e o delete devolvia 400 com o texto cru do erro de banco, ou
// seja, culpava o cliente por uma pane do servidor e ainda vazava a mensagem
// interna para a tela.
func TestDeleteGroupResolvesTheIDLikeItsSiblings(t *testing.T) {
	h, db, _ := newGroupTestHandlerNft(t)
	g := createGroupViaAPI(t, h, db, `{"name":"Minhas regras","fallthrough":"continue"}`)

	unknown := doJSON(t, h.DeleteGroup, "DELETE", "/api/nftables/groups", `{"id":"fantasma"}`)
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("id desconhecido é 400, obtive %d (%s)", unknown.Code, unknown.Body.String())
	}
	if !strings.Contains(unknown.Body.String(), `grupo \"fantasma\" não encontrado`) {
		t.Errorf("a resposta tem que nomear o grupo que não existe, obtive %s", unknown.Body.String())
	}

	if err := db.Close(); err != nil {
		t.Fatalf("fechar o banco: %v", err)
	}
	broken := doJSON(t, h.DeleteGroup, "DELETE", "/api/nftables/groups", `{"id":"`+g.ID+`"}`)
	if broken.Code != http.StatusInternalServerError {
		t.Fatalf("banco fora do ar é falha do servidor (500), obtive %d (%s)", broken.Code, broken.Body.String())
	}
	if strings.Contains(broken.Body.String(), "sql:") {
		t.Errorf("a mensagem interna do banco não pode vazar para a tela: %s", broken.Body.String())
	}
}

// Um grupo do sistema apagado não é "um grupo a menos": as duas linhas de
// bloqueio são o que faz a forward ainda descartar tráfego de host e destino
// bloqueados. Sem uma delas a reconciliação aborta em toda passada — para
// não renderizar uma forward sem proteção, calada — e o firewall inteiro
// fica somente-leitura, sem caminho de volta pelo painel (CreateGroup sempre
// grava kind=admin). Esta guarda foi puxada para antes da tarefa que a
// planejava, para a árvore nunca ficar nesse estado.
func TestSystemGroupCannotBeDeletedOrRenamed(t *testing.T) {
	h, db := newGroupTestHandler(t)

	groups, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatalf("listar: %v", err)
	}
	var sys *storage.FirewallGroup
	for i := range groups {
		if nftables.IsSystemGroup(groups[i].Kind) {
			sys = &groups[i]
			break
		}
	}
	if sys == nil {
		t.Fatal("o ambiente de teste tem que ter os grupos do sistema criados")
	}

	del := httptest.NewRequest("DELETE", "/api/nftables/groups",
		strings.NewReader(`{"id":"`+sys.ID+`"}`))
	w := httptest.NewRecorder()
	h.DeleteGroup(w, del)
	if w.Code != http.StatusBadRequest {
		t.Errorf("apagar grupo do sistema: esperava 400, obtive %d", w.Code)
	}

	upd := httptest.NewRequest("PUT", "/api/nftables/groups",
		strings.NewReader(`{"id":"`+sys.ID+`","name":"Renomeado","fallthrough":"continue"}`))
	w2 := httptest.NewRecorder()
	h.UpdateGroup(w2, upd)
	if w2.Code != http.StatusBadRequest {
		t.Errorf("renomear grupo do sistema: esperava 400, obtive %d", w2.Code)
	}

	after, _ := db.ListFirewallGroups()
	var still bool
	for _, g := range after {
		if g.ID == sys.ID {
			still = true
			if g.Name != sys.Name {
				t.Errorf("o nome foi alterado: %q -> %q", sys.Name, g.Name)
			}
		}
	}
	if !still {
		t.Fatal("o grupo do sistema sumiu do banco")
	}
}

// O outro lado da proteção, e ele importa tanto quanto: o que o admin PODE
// fazer com um grupo do sistema tem que continuar funcionando. Reordenar é a
// razão de eles terem virado grupos, e desligar é como se testa sem perder a
// lista de membros. Uma guarda larga demais mataria as duas coisas e ninguém
// perceberia — o teste de "não pode apagar" continuaria verde.
func TestSystemGroupCanStillBeReorderedAndToggled(t *testing.T) {
	h, db := newGroupTestHandler(t)

	groups, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatalf("listar: %v", err)
	}
	var sysID string
	ids := make([]string, 0, len(groups))
	for _, g := range groups {
		ids = append(ids, g.ID)
		if sysID == "" && nftables.IsSystemGroup(g.Kind) {
			sysID = g.ID
		}
	}
	if sysID == "" || len(ids) < 2 {
		t.Fatal("o ambiente de teste precisa dos grupos do sistema criados")
	}

	// desligar
	tog := httptest.NewRequest("POST", "/api/nftables/groups/toggle",
		strings.NewReader(`{"id":"`+sysID+`","enabled":false}`))
	w := httptest.NewRecorder()
	h.ToggleGroup(w, tog)
	if w.Code != http.StatusOK {
		t.Errorf("desligar grupo do sistema tem que ser permitido, obtive %d: %s", w.Code, w.Body)
	}
	after, _ := db.ListFirewallGroups()
	for _, g := range after {
		if g.ID == sysID && g.Enabled {
			t.Error("o grupo do sistema continuou ligado")
		}
	}

	// reordenar: manda a lista completa invertida
	rev := make([]string, len(ids))
	for i, id := range ids {
		rev[len(ids)-1-i] = id
	}
	body, _ := json.Marshal(map[string]any{"ids": rev})
	ro := httptest.NewRequest("POST", "/api/nftables/groups/reorder", strings.NewReader(string(body)))
	w2 := httptest.NewRecorder()
	h.ReorderGroups(w2, ro)
	if w2.Code != http.StatusOK {
		t.Errorf("reordenar com grupo do sistema tem que ser permitido, obtive %d: %s", w2.Code, w2.Body)
	}
	reordered, _ := db.ListFirewallGroups()
	if reordered[0].ID != rev[0] {
		t.Errorf("a nova ordem não valeu: esperava %q no topo, obtive %q", rev[0], reordered[0].ID)
	}
}

// O cliente não pode criar um grupo do sistema: groupBody não tem o campo, e
// CreateGroup monta a linha sem ele. Se algum dia alguém acrescentar o campo
// ao corpo "por simetria", isto fica vermelho — e o estrago seria um grupo
// que o admin não consegue apagar nem renomear, criado por ele mesmo.
func TestCreateGroupNeverProducesASystemGroup(t *testing.T) {
	h, db := newGroupTestHandler(t)

	req := httptest.NewRequest("POST", "/api/nftables/groups",
		strings.NewReader(`{"name":"Tentativa","kind":"blocked_hosts","fallthrough":"continue"}`))
	w := httptest.NewRecorder()
	h.CreateGroup(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("criar grupo comum: esperava 200, obtive %d: %s", w.Code, w.Body)
	}

	groups, _ := db.ListFirewallGroups()
	for _, g := range groups {
		if g.Name == "Tentativa" && nftables.IsSystemGroup(g.Kind) {
			t.Fatalf("o cliente conseguiu criar um grupo do sistema: %+v", g)
		}
	}
}

// systemGroupID devolve o id do primeiro grupo do sistema da máquina de
// teste — os bloqueios, criados por EnsureSystemGroups como no boot.
func systemGroupID(t *testing.T, db *storage.DB) string {
	t.Helper()
	groups, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatalf("ListFirewallGroups: %v", err)
	}
	for _, g := range groups {
		if nftables.IsSystemGroup(g.Kind) {
			return g.ID
		}
	}
	t.Fatal("o ambiente de teste tem que ter os grupos do sistema criados")
	return ""
}

// C-1 da revisão final: uma regra estacionada dentro de um grupo do sistema
// some do firewall e o apply diz "ok". O grupo do sistema não tem chain de
// regras do admin: o conteúdo dele é o named set. CheckGroups pula grupo de
// sistema, ReconcileGroups pula nos passos 1 e 2, e MergeGroups devolve
// Rules: [] para ele — cada camada certa isoladamente, e o resultado é que
// o pré-voo aceita, o reconcile devolve nil (status "ok" na tela) e nenhum
// comando emitido contém a regra. Ela fica no banco, fora do nft, e não
// aparece em tela nenhuma. Não dá para chegar lá por clique hoje, mas
// qualquer cliente com firewall.write chega — e requireGroup é o único lugar
// que ainda pode avisar o admin, antes da escrita.
func TestCreateRuleRefusesASystemGroup(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)
	sysID := systemGroupID(t, db)
	exec.executed = nil

	w := doJSON(t, h.CreateRule, "POST", "/api/nftables/rules",
		`{"group_id":"`+sysID+`","action":"drop","saddr":"10.0.0.5"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("esperava 400 para regra em grupo do sistema, obtive %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "grupo do sistema") {
		t.Errorf("a mensagem tem que explicar que o grupo é do sistema, obtive %s", w.Body.String())
	}

	rules, _ := db.ListFirewallRules()
	if len(rules) != 0 {
		t.Fatalf("a regra chegou ao banco e nunca vai existir no nft: %+v", rules)
	}
	if exec.ranWith("10.0.0.5") {
		t.Errorf("nada com a regra podia ter sido executado: %v", exec.executed)
	}
}

// O PUT é o caso pior: a regra JÁ vale no firewall. Movê-la para um grupo do
// sistema a apagava da chain viva e devolvia HTTP 200 — o admin vê a regra
// na tela, o kernel não a tem mais.
func TestUpdateRuleRefusesToMoveARuleIntoASystemGroup(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)
	sysID := systemGroupID(t, db)
	g := createGroupViaAPI(t, h, db, `{"name":"Minhas regras","fallthrough":"continue"}`)
	rule := createRuleViaAPI(t, h, db, `{"group_id":"`+g.ID+`","action":"drop","saddr":"10.0.0.5"}`)
	exec.executed = nil

	w := doJSON(t, h.UpdateRule, "PUT", "/api/nftables/rules",
		`{"id":"`+rule.ID+`","group_id":"`+sysID+`","action":"drop","saddr":"10.0.0.5"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("esperava 400 ao mover regra para grupo do sistema, obtive %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "grupo do sistema") {
		t.Errorf("a mensagem tem que explicar que o grupo é do sistema, obtive %s", w.Body.String())
	}

	rules, _ := db.ListFirewallRules()
	if len(rules) != 1 || rules[0].GroupID != g.ID {
		t.Fatalf("a regra tinha que continuar no grupo do admin, obtive %+v", rules)
	}
	// O que decide é o kernel: a linha tinha que continuar viva na chain.
	if got := exec.chains[g.ChainName]; len(got) != 1 || !strings.Contains(got[0], "10.0.0.5") {
		t.Errorf("a regra sumiu do firewall com a edição recusada, chain=%v", got)
	}
}

// ─── A janela trava a edição (Fase C2, spec §5.3) ─────────────────────────

// openWindow abre uma janela de confirmação pelo SERVIÇO, sem passar por
// handler nenhum. É de propósito: o que estes testes medem é a trava, e abrir
// a janela por uma mutação misturaria dois defeitos possíveis num resultado só
// — uma trava quebrada e um arme quebrado dariam o mesmo vermelho.
func openWindow(t *testing.T, fr *firewallrules.Service) string {
	t.Helper()
	id, err := fr.OpenConfirmWindow(context.Background(), "admin", "regra de escopo input aplicada")
	if err != nil {
		t.Fatalf("OpenConfirmWindow: %v", err)
	}
	return id
}

// Com janela aberta, nenhuma mutação de grupo ou regra é aceita. Sem isso,
// "reverter ao estado anterior" vira ambíguo — anterior a qual mudança? — e
// o admin pode empilhar uma segunda alteração arriscada sobre uma que ainda
// não se provou boa.
func TestEveryMutationIsRefusedWhileAConfirmWindowIsOpen(t *testing.T) {
	h, db, exec, fr := newGroupTestHandlerFR(t)
	g := createGroupViaAPI(t, h, db, `{"name":"LAN","cond_saddr":"192.168.3.0/24","fallthrough":"continue"}`)
	createGroupViaAPI(t, h, db, `{"name":"Convidados","fallthrough":"continue"}`)
	rule := createRuleViaAPI(t, h, db, `{"group_id":"`+g.ID+`","action":"drop","saddr":"10.0.0.5"}`)
	second := createRuleViaAPI(t, h, db, `{"group_id":"`+g.ID+`","action":"drop","saddr":"10.0.0.6"}`)

	openWindow(t, fr)
	exec.executed = nil

	for _, c := range []struct {
		name string
		call func() *httptest.ResponseRecorder
	}{
		{"criar grupo", func() *httptest.ResponseRecorder {
			return doJSON(t, h.CreateGroup, "POST", "/api/nftables/groups", `{"name":"Novo","fallthrough":"continue"}`)
		}},
		{"editar grupo", func() *httptest.ResponseRecorder {
			return doJSON(t, h.UpdateGroup, "PUT", "/api/nftables/groups",
				`{"id":"`+g.ID+`","name":"Outro nome","fallthrough":"continue"}`)
		}},
		{"apagar grupo", func() *httptest.ResponseRecorder {
			return doJSON(t, h.DeleteGroup, "DELETE", "/api/nftables/groups", `{"id":"`+g.ID+`"}`)
		}},
		{"ligar/desligar grupo", func() *httptest.ResponseRecorder {
			return doJSON(t, h.ToggleGroup, "POST", "/api/nftables/groups/toggle", `{"id":"`+g.ID+`","enabled":false}`)
		}},
		{"reordenar grupos", func() *httptest.ResponseRecorder {
			return doJSON(t, h.ReorderGroups, "POST", "/api/nftables/groups/reorder",
				`{"ids":`+reversedGroupIDsJSON(t, db)+`}`)
		}},
		{"criar regra", func() *httptest.ResponseRecorder {
			return doJSON(t, h.CreateRule, "POST", "/api/nftables/rules",
				`{"group_id":"`+g.ID+`","action":"drop","saddr":"10.0.0.9"}`)
		}},
		{"editar regra", func() *httptest.ResponseRecorder {
			return doJSON(t, h.UpdateRule, "PUT", "/api/nftables/rules",
				`{"id":"`+rule.ID+`","group_id":"`+g.ID+`","action":"accept","saddr":"10.0.0.5"}`)
		}},
		{"apagar regra", func() *httptest.ResponseRecorder {
			return doJSON(t, h.DeleteRule, "DELETE", "/api/nftables/rules", `{"id":"`+rule.ID+`"}`)
		}},
		{"ligar/desligar regra", func() *httptest.ResponseRecorder {
			return doJSON(t, h.ToggleRule, "POST", "/api/nftables/rules/toggle", `{"id":"`+rule.ID+`","enabled":false}`)
		}},
		{"reordenar regras", func() *httptest.ResponseRecorder {
			return doJSON(t, h.ReorderRules, "POST", "/api/nftables/rules/reorder",
				`{"ids":["`+second.ID+`","`+rule.ID+`"]}`)
		}},
	} {
		w := c.call()
		if w.Code != http.StatusConflict {
			t.Errorf("%s: esperava 409 com janela aberta, obtive %d (%s)", c.name, w.Code, w.Body.String())
		}
	}

	// A recusa é ANTES da escrita, e antes do nft: nada mudou no banco e
	// nenhum comando foi emitido. Um 409 depois de já ter gravado seria a
	// pior versão possível desta trava.
	groups := adminGroups(t, db)
	if len(groups) != 2 {
		t.Errorf("a janela aberta tinha que impedir toda escrita de grupo, obtive %+v", groups)
	}
	rules, _ := db.ListFirewallRules()
	if len(rules) != 2 {
		t.Errorf("a janela aberta tinha que impedir toda escrita de regra, obtive %+v", rules)
	}
	if len(exec.executed) != 0 {
		t.Errorf("nenhuma mutação recusada podia ter tocado o nft: %v", exec.executed)
	}
}

// Confirmar e reverter TÊM que funcionar com a janela aberta — são as duas
// saídas dela. Uma trava larga demais prenderia o admin dentro da janela: ele
// receberia 409 ao confirmar, 409 ao reverter, e só sairia dali quando o
// prazo vencesse sozinho — sem escolha nenhuma sobre a própria mudança.
func TestConfirmAndRevertAreAllowedWhileTheWindowIsOpen(t *testing.T) {
	// Confirmar.
	h, _, _, fr := newGroupTestHandlerFR(t)
	id := openWindow(t, fr)
	w := doJSON(t, h.ConfirmPendingChange, "POST", "/api/nftables/pending/confirm", `{"id":"`+id+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("confirmar com a janela aberta: esperava 200, obtive %d (%s)", w.Code, w.Body.String())
	}

	// Reverter, em uma máquina limpa (a janela é uma só por vez).
	h2, _, _, fr2 := newGroupTestHandlerFR(t)
	id2 := openWindow(t, fr2)
	w = doJSON(t, h2.RevertPendingChange, "POST", "/api/nftables/pending/revert", `{"id":"`+id2+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("reverter com a janela aberta: esperava 200, obtive %d (%s)", w.Code, w.Body.String())
	}

	// E ler o pendente também: é o GET que alimenta a faixa da contagem
	// regressiva. Travá-lo esconderia da tela justamente a explicação de por
	// que a edição está travada.
	h3, _, _, fr3 := newGroupTestHandlerFR(t)
	openWindow(t, fr3)
	w = doJSON(t, h3.PendingChange, "GET", "/api/nftables/pending", "")
	if w.Code != http.StatusOK {
		t.Fatalf("ler o pendente com a janela aberta: esperava 200, obtive %d (%s)", w.Code, w.Body.String())
	}
}

// Uma reversão marcada como em andamento mas cujo estado anterior AINDA NÃO
// voltou ao banco tranca a edição. É a metade que continua travando depois do
// N-2: o que libera a mutação não é a marca de "revertendo", é o banco já ser,
// linha por linha, o estado anterior (firewallrules.RevertSettled). Enquanto
// não for, mutar escreveria por cima de um estado que ninguém sabe qual é.
//
// A marca é gravada à mão, sem o trabalho que ela afirma ter sido feito — que
// é exatamente a forma de uma linha corrompida ou de uma reversão interrompida
// entre a transação e a marca.
func TestMutationIsRefusedWhileARevertHasNotRestoredTheDBYet(t *testing.T) {
	h, db, _, fr := newGroupTestHandlerFR(t)
	id := openWindow(t, fr)
	// O banco anda DEPOIS do snapshot da janela: agora ele não descreve mais o
	// estado que o pendente guardou. Direto no banco porque, pela API, a janela
	// aberta recusaria — é o estado que se quer montar, não o caminho.
	if err := db.CreateFirewallGroup(&storage.FirewallGroup{
		ID: "depois-do-snapshot", Name: "Depois do snapshot",
		ChainName: nftables.GroupChainName("depois-do-snapshot"), Position: 9,
		Enabled: true, Fallthrough: nftables.FallthroughContinue, Kind: nftables.GroupKindAdmin,
	}); err != nil {
		t.Fatalf("CreateFirewallGroup: %v", err)
	}
	if err := db.MarkPendingReverting(id, time.Now()); err != nil {
		t.Fatalf("MarkPendingReverting: %v", err)
	}

	w := doJSON(t, h.CreateGroup, "POST", "/api/nftables/groups", `{"name":"Novo","fallthrough":"continue"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("esperava 409 durante a reversão, obtive %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "revers") {
		t.Errorf("a mensagem tem que dizer que a reversão está em curso, obtive %s", w.Body.String())
	}
	for _, g := range adminGroups(t, db) {
		if g.Name == "Novo" {
			t.Errorf("nada podia ter sido gravado durante a reversão: %+v", g)
		}
	}
}

// reversedGroupIDsJSON devolve TODOS os ids de grupo (inclusive os do
// sistema) na ordem inversa, como o corpo do /groups/reorder pede. A lista
// completa importa: ReorderGroups recusa uma lista parcial com 400, e um 400
// passaria por engano no teste da trava, que espera 409 — o caso mediria a
// validação da lista, não a trava.
func reversedGroupIDsJSON(t *testing.T, db *storage.DB) string {
	t.Helper()
	all, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatalf("ListFirewallGroups: %v", err)
	}
	ids := make([]string, 0, len(all))
	for i := len(all) - 1; i >= 0; i-- {
		ids = append(ids, all[i].ID)
	}
	out, err := json.Marshal(ids)
	if err != nil {
		t.Fatalf("marshal dos ids: %v", err)
	}
	return string(out)
}

// ─── "Vale para toda conexão" × "só conexões novas" ───────────────────────
//
// O campo tem DUAS pontas, e elas entram juntas ou não entram: o corpo do
// handler e o UPDATE do storage. Com o campo `scope` isso já deu errado neste
// projeto — o campo existia na tela, não era gravado, e o operador mudava a
// escolha com HTTP 200 e nada acontecendo. Os testes abaixo medem sempre as
// duas: o que ficou no BANCO e o que ficou no FIREWALL VIVO.

// jumpLineTo devolve a linha viva da chain que salta para target — é onde o
// `ct state new` tem que aparecer, e não em outro lugar.
func jumpLineTo(t *testing.T, exec *fakeNft, chain, target string) string {
	t.Helper()
	for _, expr := range exec.liveChain(chain) {
		if jumpTargetOf(expr) == target {
			return expr
		}
	}
	t.Fatalf("nenhum jump para %q na chain %q: %v", target, chain, exec.liveChain(chain))
	return ""
}

// A escolha feita na criação tem que chegar ao nft. Este é o teste que pega o
// furo deixado em aberto pela Task 1: o campo era gravável e renderizável, mas
// a conversão storage.FirewallGroup → nftables.StoredGroup não o carregava, de
// modo que o grupo nascia "só conexões novas" no banco e "toda conexão" no
// firewall — a pior divergência possível, porque a tela mostraria a escolha do
// operador e o kernel faria o contrário dela.
func TestCreateGroupWithNewConnectionsOnlyReachesTheFirewall(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)
	g := createGroupViaAPI(t, h, db,
		`{"name":"Wi-Fi visitantes","cond_saddr":"192.168.50.0/24","fallthrough":"continue","conn_state":"new"}`)

	if g.ConnState != nftables.ConnStateNew {
		t.Fatalf("a escolha não chegou ao banco: %+v", g)
	}
	line := jumpLineTo(t, exec, nftables.ForwardChain, g.ChainName)
	if !strings.Contains(line, "ct state new") {
		t.Errorf("o firewall vivo não recebeu a restrição: %q", line)
	}
	// E o pré-voo tem que ter validado ESTA linha, não a de antes: a ordem
	// obrigatória de toda mutação é validar → `nft -c` → gravar → reconciliar,
	// e um dry run que aprova uma linha diferente da que vai ser aplicada é o
	// pré-voo existindo só para constar.
	if !exec.checkedWith("ct state new") {
		t.Errorf("o pré-voo `nft -c` não viu a restrição que foi aplicada: %v", exec.checked)
	}
}

// E o contrapeso, que é a garantia de compatibilidade da entrega inteira: o
// grupo criado sem falar do campo — todo grupo que já existe, e todo cliente
// que não conhece a escolha — continua emitindo a linha de sempre.
func TestCreateGroupWithoutConnStateStillEmitsTheLineItAlwaysDid(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)
	g := createGroupViaAPI(t, h, db,
		`{"name":"LAN","cond_saddr":"192.168.50.0/24","fallthrough":"continue"}`)

	if g.ConnState != "" {
		t.Errorf("o grupo nasceu restrito sem ninguém pedir: %+v", g)
	}
	line := jumpLineTo(t, exec, nftables.ForwardChain, g.ChainName)
	if strings.Contains(line, "ct state") {
		t.Errorf("vazou ct state para um grupo de toda conexão: %q", line)
	}
}

// A edição nos dois sentidos. Restringir é o caso que o operador vai usar;
// SOLTAR de volta é o que ele vai fazer quando perceber que precisava da
// marreta, e uma edição que só sabe apertar deixaria o grupo preso na escolha
// nova para sempre.
func TestUpdateGroupChangesConnStateInBothDirections(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)
	g := createGroupViaAPI(t, h, db, `{"name":"Wi-Fi","cond_saddr":"192.168.50.0/24","fallthrough":"continue"}`)

	w := doJSON(t, h.UpdateGroup, "PUT", "/api/nftables/groups",
		`{"id":"`+g.ID+`","name":"Wi-Fi","cond_saddr":"192.168.50.0/24","fallthrough":"continue","conn_state":"new"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("UpdateGroup: status %d, body %s", w.Code, w.Body.String())
	}
	if after := adminGroups(t, db)[0]; after.ConnState != nftables.ConnStateNew {
		t.Fatalf("a escolha nova não chegou ao banco (mudei na tela e não aconteceu nada): %+v", after)
	}
	if line := jumpLineTo(t, exec, nftables.ForwardChain, g.ChainName); !strings.Contains(line, "ct state new") {
		t.Fatalf("a escolha nova não chegou ao firewall vivo: %q", line)
	}

	back := doJSON(t, h.UpdateGroup, "PUT", "/api/nftables/groups",
		`{"id":"`+g.ID+`","name":"Wi-Fi","cond_saddr":"192.168.50.0/24","fallthrough":"continue","conn_state":"any"}`)
	if back.Code != http.StatusOK {
		t.Fatalf("UpdateGroup (voltar): status %d, body %s", back.Code, back.Body.String())
	}
	if after := adminGroups(t, db)[0]; after.ConnState != nftables.ConnStateAny {
		t.Fatalf("não deu para voltar a valer para toda conexão: %+v", after)
	}
	if line := jumpLineTo(t, exec, nftables.ForwardChain, g.ChainName); strings.Contains(line, "ct state") {
		t.Errorf("a restrição ficou no firewall depois de ser desfeita: %q", line)
	}
}

// Campo AUSENTE no corpo significa MANTER o gravado — mesmo contrato do
// `scope`, e pela mesma razão: um cliente que não conhece o campo (ou uma
// chamada que só quer renomear o grupo) devolveria em silêncio a "toda
// conexão" um grupo que o operador restringiu de propósito, com HTTP 200 e
// nada na tela mudando. Para soltar o grupo, o cliente manda "any"
// explicitamente — que é o que a tela faz.
func TestUpdateWithoutConnStateKeepsTheStoredOne(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)
	g := createGroupViaAPI(t, h, db,
		`{"name":"Wi-Fi","cond_saddr":"192.168.50.0/24","fallthrough":"continue","conn_state":"new"}`)

	w := doJSON(t, h.UpdateGroup, "PUT", "/api/nftables/groups",
		`{"id":"`+g.ID+`","name":"Outro nome","cond_saddr":"192.168.50.0/24","fallthrough":"continue"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("UpdateGroup: status %d, body %s", w.Code, w.Body.String())
	}
	after := adminGroups(t, db)[0]
	if after.ConnState != nftables.ConnStateNew {
		t.Fatalf("a escolha gravada foi perdida por um corpo que nem falava dela: %+v", after)
	}
	if line := jumpLineTo(t, exec, nftables.ForwardChain, g.ChainName); !strings.Contains(line, "ct state new") {
		t.Errorf("o firewall foi afrouxado por um corpo que nem falava da escolha: %q", line)
	}
}

// Valor desconhecido é recusado na entrada, nunca normalizado em silêncio: um
// "established" gravado por um cliente confuso viraria "any" na renderização e
// a tela diria uma coisa enquanto o firewall faz outra.
func TestUnknownConnStateIsRefused(t *testing.T) {
	h, db := newGroupTestHandler(t)

	w := doJSON(t, h.CreateGroup, "POST", "/api/nftables/groups",
		`{"name":"Estranho","fallthrough":"continue","conn_state":"established"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("criar com conn_state inválido: esperava 400, obtive %d (%s)", w.Code, w.Body.String())
	}
	if len(adminGroups(t, db)) != 0 {
		t.Fatalf("o grupo inválido chegou ao banco: %+v", adminGroups(t, db))
	}

	g := createGroupViaAPI(t, h, db, `{"name":"Wi-Fi","fallthrough":"continue","conn_state":"new"}`)
	upd := doJSON(t, h.UpdateGroup, "PUT", "/api/nftables/groups",
		`{"id":"`+g.ID+`","name":"Wi-Fi","fallthrough":"continue","conn_state":"invalid"}`)
	if upd.Code != http.StatusBadRequest {
		t.Errorf("editar com conn_state inválido: esperava 400, obtive %d (%s)", upd.Code, upd.Body.String())
	}
	if after := adminGroups(t, db)[0]; after.ConnState != nftables.ConnStateNew {
		t.Errorf("a escolha válida anterior foi corrompida pela edição recusada: %+v", after)
	}
}

// Grupo do sistema (blocked_hosts, blocklist) não recebe `ct state new`: é
// lista fechada, renderizada por um mapa próprio, e bloqueio de host é
// justamente onde se quer a marreta — derrubar na hora inclusive o que já
// estava estabelecido.
//
// NÃO HÁ TESTE DE API PARA ISSO AQUI, E É DE PROPÓSITO. Havia um
// (TestSystemGroupRefusesConnState) e ele passava trivialmente: a guarda de
// UpdateGroup recusa QUALQUER edição de grupo do sistema (groups.go, o
// IsSystemGroup logo depois do findGroup) antes de sequer olhar o conn_state,
// então o 400 que ele media não tinha nada a ver com o campo, e a asserção de
// que a coluna continuou vazia era verdadeira mesmo com a feature inteira
// arrancada. Pela mesma guarda, o campo também não tem caminho de CRIAÇÃO por
// onde chegar a um grupo do sistema: CreateGroup nunca carimba Kind, e os
// grupos do sistema nascem só de EnsureSystemGroups.
//
// A garantia real é do renderizador, onde ela pode de fato ser violada, e está
// presa por dois testes em internal/nftables:
//
//   - TestSystemGroupNeverGetsCtState — o mapa que EMITE as linhas do sistema
//     não produz `ct state` nem com ConnState: ConnStateNew no grupo, e a
//     expressão por onde a forward viva é PROCURADA também não;
//   - TestForwardChainKeepsSystemBlockLinesUntouchedByConnState — a forward
//     reconstruída inteira mantém as linhas de bloqueio como sempre foram.
//
// Um teste que não guarda nada é pior que teste nenhum: dá sensação de
// cobertura onde não há.

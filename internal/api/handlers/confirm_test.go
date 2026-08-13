package handlers_test

// A janela de confirmação pelo lado da API (Fase C2, spec §5).
//
// O que estes testes seguram, e por que cada um existe:
//
//   - mutação de tráfego ATRAVESSANDO o firewall NÃO abre janela. Abrir por
//     tudo tornaria o mecanismo insuportável (toda edição de regra da LAN
//     travaria o painel por 90 segundos) e o operador aprenderia a confirmar
//     no reflexo — que é o mesmo que não ter janela nenhuma;
//   - mutação que envolve grupo de escopo input ABRE. É o único caminho pelo
//     qual uma regra pode trancar o operador para fora de uma máquina remota;
//   - confirmar fecha sem mexer no firewall vivo; reverter desfaz E fecha;
//   - sem nada pendente, o GET responde `null` explicitamente.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// pendingJSON é o pendente como o painel o recebe. Declarado aqui, e não
// importado do handler (é privado), justamente para que a suíte cobre o
// CONTRATO da API: um campo renomeado no servidor quebra este teste.
type pendingJSON struct {
	ID        string    `json:"id"`
	Summary   string    `json:"summary"`
	AppliedBy string    `json:"applied_by"`
	ExpiresAt time.Time `json:"expires_at"`
	Reverting bool      `json:"reverting"`
}

type pendingBody struct {
	Pending *pendingJSON `json:"pending"`
}

// getPending lê GET /api/nftables/pending.
func getPending(t *testing.T, h *handlers.NftablesHandler) *pendingJSON {
	t.Helper()
	w := doJSON(t, h.PendingChange, "GET", "/api/nftables/pending", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET pending: status %d, body %s", w.Code, w.Body.String())
	}
	var body pendingBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode do pendente: %v (body %s)", err, w.Body.String())
	}
	return body.Pending
}

// pendingOf extrai o pendente que veio JUNTO do 200 da mutação — a metade do
// contrato que o GET não cobre: o painel precisa saber, na resposta da própria
// mutação, que a partir de agora ele tem 90 segundos.
func pendingOf(t *testing.T, w *httptest.ResponseRecorder) *pendingJSON {
	t.Helper()
	var body struct {
		Pending *pendingJSON `json:"pending"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode da resposta da mutação: %v (body %s)", err, w.Body.String())
	}
	return body.Pending
}

const inputGroupBody = `{"name":"Acesso ao firewall","scope":"input","cond_saddr":"192.168.3.0/24","fallthrough":"continue"}`

// ─── Quem abre e quem não abre ────────────────────────────────────────────

// A mutação de escopo forward é o caso comum do produto inteiro até a Fase C2:
// ela mexe em tráfego atravessando o firewall e não pode custar 90 segundos de
// espera nem travar as outras edições.
func TestForwardGroupMutationDoesNotOpenTheWindow(t *testing.T) {
	h, db := newGroupTestHandler(t)

	w := doJSON(t, h.CreateGroup, "POST", "/api/nftables/groups",
		`{"name":"LAN","cond_saddr":"192.168.3.0/24","fallthrough":"continue"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("CreateGroup: status %d, body %s", w.Code, w.Body.String())
	}
	if p := pendingOf(t, w); p != nil {
		t.Errorf("mutação de escopo forward não podia abrir janela: %+v", p)
	}
	if p := getPending(t, h); p != nil {
		t.Fatalf("GET devolveu janela aberta depois de uma mutação de forward: %+v", p)
	}

	// E a segunda mutação seguida tem que ser aceita — é isto que "não abriu
	// janela" significa na prática para quem está usando o painel.
	g := adminGroups(t, db)[0]
	second := doJSON(t, h.UpdateGroup, "PUT", "/api/nftables/groups",
		`{"id":"`+g.ID+`","name":"LAN interna","fallthrough":"continue"}`)
	if second.Code != http.StatusOK {
		t.Fatalf("a segunda mutação de forward tinha que passar: status %d, body %s", second.Code, second.Body.String())
	}
}

func TestInputGroupMutationOpensTheWindow(t *testing.T) {
	h, db := newGroupTestHandler(t)

	w := doJSON(t, h.CreateGroup, "POST", "/api/nftables/groups", inputGroupBody)
	if w.Code != http.StatusOK {
		t.Fatalf("CreateGroup: status %d, body %s", w.Code, w.Body.String())
	}
	inline := pendingOf(t, w)
	if inline == nil {
		t.Fatalf("criar grupo de escopo input tinha que devolver o pendente junto do 200: %s", w.Body.String())
	}
	stored := getPending(t, h)
	if stored == nil {
		t.Fatalf("GET tinha que enxergar a mesma janela")
	}
	if stored.ID != inline.ID {
		t.Errorf("o pendente da resposta e o do GET são outros: %q vs %q", inline.ID, stored.ID)
	}
	if stored.Reverting {
		t.Errorf("janela recém-aberta não está revertendo: %+v", stored)
	}
	if stored.Summary == "" || stored.AppliedBy == "" {
		t.Errorf("a faixa do painel precisa de resumo e de quem aplicou: %+v", stored)
	}
	if !stored.ExpiresAt.After(time.Now()) {
		t.Errorf("a contagem regressiva já nasceu vencida: %+v", stored)
	}
	// O grupo está VALENDO enquanto a janela corre — a mudança é aplicada de
	// verdade, não fica em quarentena.
	if len(adminGroups(t, db)) != 1 {
		t.Errorf("o grupo tinha que estar aplicado durante a janela: %+v", adminGroups(t, db))
	}
}

// Mudar o escopo de forward para input é o momento em que um grupo que só
// filtrava tráfego atravessando passa a poder trancar o operador para fora da
// máquina. Duas coisas juntas: a coluna scope tem que ir mesmo para o banco
// (UpdateFirewallGroup gravava tudo MENOS ela) e a janela tem que abrir.
func TestChangingAGroupScopeToInputSavesItAndOpensTheWindow(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)
	g := createGroupViaAPI(t, h, db, `{"name":"Serviços","cond_saddr":"192.168.3.0/24","fallthrough":"continue"}`)
	if g.Scope == nftables.ScopeInput {
		t.Fatalf("o grupo nasceu com escopo input sem ninguém pedir: %+v", g)
	}

	w := doJSON(t, h.UpdateGroup, "PUT", "/api/nftables/groups",
		`{"id":"`+g.ID+`","name":"Serviços","scope":"input","cond_saddr":"192.168.3.0/24","fallthrough":"continue"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("UpdateGroup: status %d, body %s", w.Code, w.Body.String())
	}
	if pendingOf(t, w) == nil {
		t.Errorf("virar escopo input tinha que abrir a janela: %s", w.Body.String())
	}
	after := adminGroups(t, db)[0]
	if after.Scope != nftables.ScopeInput {
		t.Fatalf("o escopo novo não chegou ao banco (mudei na tela e não aconteceu nada): %+v", after)
	}
	// E o firewall vivo seguiu o banco: o jump saiu da forward e foi para a
	// input. Sem isto, o painel afirmaria uma proteção que o kernel não faz.
	if exec.forwardHasJumpTo(g.ChainName) {
		t.Errorf("o jump continua na forward depois de o grupo virar input: %v", exec.chains[nftables.ForwardChain])
	}
	if !exec.ranWith("add rule inet linkguard " + nftables.InputChain) {
		t.Errorf("a chain input não foi reconstruída com o grupo: %v", exec.executed)
	}
}

// Escopo ausente no corpo é "mantenha o que está gravado". Um cliente que não
// conhece o campo (ou uma chamada que só quer renomear o grupo) rebaixaria em
// silêncio um grupo de input para forward, movendo as regras dele para outra
// chain com HTTP 200 e nada na tela mudando.
func TestUpdateWithoutScopeKeepsTheStoredOne(t *testing.T) {
	h, db := newGroupTestHandler(t)
	g := createGroupViaAPI(t, h, db, inputGroupBody)
	confirmWindow(t, h)

	w := doJSON(t, h.UpdateGroup, "PUT", "/api/nftables/groups",
		`{"id":"`+g.ID+`","name":"Outro nome","cond_saddr":"192.168.3.0/24","fallthrough":"continue"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("UpdateGroup: status %d, body %s", w.Code, w.Body.String())
	}
	after := adminGroups(t, db)[0]
	if after.Scope != nftables.ScopeInput {
		t.Fatalf("o escopo gravado foi perdido por um corpo que nem falava dele: %+v", after)
	}
}

// Uma regra dentro de um grupo de escopo input é uma regra na chain que decide
// sobre o SSH e o painel — abre janela. A mesma regra dentro de um grupo de
// forward, não.
func TestRuleMutationOpensTheWindowOnlyInsideAnInputGroup(t *testing.T) {
	h, db := newGroupTestHandler(t)
	fwd := createGroupViaAPI(t, h, db, `{"name":"LAN","fallthrough":"continue"}`)
	w := doJSON(t, h.CreateRule, "POST", "/api/nftables/rules",
		`{"group_id":"`+fwd.ID+`","action":"drop","saddr":"10.0.0.5"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("CreateRule: status %d, body %s", w.Code, w.Body.String())
	}
	if p := pendingOf(t, w); p != nil {
		t.Fatalf("regra em grupo de forward não podia abrir janela: %+v", p)
	}

	in := createGroupViaAPI(t, h, db, inputGroupBody)
	confirmWindow(t, h) // a criação do grupo de input já abriu a sua

	w = doJSON(t, h.CreateRule, "POST", "/api/nftables/rules",
		`{"group_id":"`+in.ID+`","action":"accept","proto":"tcp","dport":"22"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("CreateRule no grupo de input: status %d, body %s", w.Code, w.Body.String())
	}
	if pendingOf(t, w) == nil {
		t.Fatalf("regra em grupo de escopo input tinha que abrir a janela: %s", w.Body.String())
	}
	if getPending(t, h) == nil {
		t.Fatalf("GET tinha que enxergar a janela aberta pela regra")
	}
}

// ─── As saídas ────────────────────────────────────────────────────────────

// confirmWindow aperta "Confirmar" e exige que tenha funcionado. Usado pelos
// testes que precisam ENCERRAR uma janela para seguir com o que realmente
// estão medindo.
func confirmWindow(t *testing.T, h *handlers.NftablesHandler) {
	t.Helper()
	w := doJSON(t, h.ConfirmPendingChange, "POST", "/api/nftables/pending/confirm", "")
	if w.Code != http.StatusOK {
		t.Fatalf("confirmar: status %d, body %s", w.Code, w.Body.String())
	}
}

// Confirmar fecha a janela e NÃO mexe no firewall vivo: o que está valendo já
// é o estado desejado, e o operador acabou de provar isso confirmando de
// dentro da máquina.
func TestConfirmClosesTheWindowAndKeepsTheChange(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)
	g := createGroupViaAPI(t, h, db, inputGroupBody)
	before := len(exec.executed)

	confirmWindow(t, h)

	if p := getPending(t, h); p != nil {
		t.Fatalf("a janela continuou aberta depois de confirmar: %+v", p)
	}
	groups := adminGroups(t, db)
	if len(groups) != 1 || groups[0].ID != g.ID {
		t.Fatalf("confirmar tinha que MANTER a mudança: %+v", groups)
	}
	if len(exec.executed) != before {
		t.Errorf("confirmar não pode emitir comando de nft (a chain input seria reescrita no instante em que o acesso foi provado bom): %v",
			exec.executed[before:])
	}
	// Confirmar duas vezes é conflito com o estado do servidor (409), nunca
	// 500: quem apertou o botão de novo é o operador, não uma pane.
	again := doJSON(t, h.ConfirmPendingChange, "POST", "/api/nftables/pending/confirm", "")
	if again.Code != http.StatusConflict {
		t.Errorf("esperava 409 ao confirmar sem janela, obtive %d (%s)", again.Code, again.Body.String())
	}
}

// Reverter desfaz a mudança E fecha a janela — no banco e no firewall vivo.
func TestRevertUndoesTheChangeAndClosesTheWindow(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)
	g := createGroupViaAPI(t, h, db, inputGroupBody)

	w := doJSON(t, h.RevertPendingChange, "POST", "/api/nftables/pending/revert", "")
	if w.Code != http.StatusOK {
		t.Fatalf("reverter: status %d, body %s", w.Code, w.Body.String())
	}
	if p := getPending(t, h); p != nil {
		t.Fatalf("a janela continuou aberta depois de reverter: %+v", p)
	}
	if groups := adminGroups(t, db); len(groups) != 0 {
		t.Fatalf("reverter tinha que desfazer a criação do grupo: %+v", groups)
	}
	if _, alive := exec.chains[g.ChainName]; alive {
		t.Errorf("a chain do grupo revertido continua no firewall vivo: %v", exec.chains)
	}
	for _, expr := range exec.chains[nftables.InputChain] {
		if jumpTargetOf(expr) == g.ChainName {
			t.Errorf("a chain input continua pulando para o grupo revertido: %v", exec.chains[nftables.InputChain])
		}
	}
	again := doJSON(t, h.RevertPendingChange, "POST", "/api/nftables/pending/revert", "")
	if again.Code != http.StatusConflict {
		t.Errorf("esperava 409 ao reverter sem janela, obtive %d (%s)", again.Code, again.Body.String())
	}
}

// Sem nada pendente o GET responde `null` EXPLICITAMENTE, e não um objeto
// vazio nem 404: o painel desenha a faixa a partir desta resposta e precisa
// distinguir "não há janela" de "não consegui saber".
func TestPendingIsNullWhenThereIsNothing(t *testing.T) {
	h, _ := newGroupTestHandler(t)
	w := doJSON(t, h.PendingChange, "GET", "/api/nftables/pending", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET pending: status %d", w.Code)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v (body %s)", err, w.Body.String())
	}
	v, ok := raw["pending"]
	if !ok {
		t.Fatalf("o campo pending tem que existir sempre, body %s", w.Body.String())
	}
	if string(v) != "null" {
		t.Errorf("esperava null, obtive %s", string(v))
	}
}

// A faixa do painel precisa separar "aguardando confirmação" de "revertendo":
// os botões disponíveis são outros (em reversão não cabe nem confirmar nem
// reverter) e o texto tem que dizer que a reversão está em curso. Sem este
// campo, o operador aperta "Confirmar" num pendente cujo estado anterior já
// voltou ao banco e recebe uma recusa que ele não tem como entender.
func TestPendingSaysWhenARevertIsAlreadyUnderway(t *testing.T) {
	h, db := newGroupTestHandler(t)
	createGroupViaAPI(t, h, db, inputGroupBody)

	p := getPending(t, h)
	if p == nil {
		t.Fatalf("esperava a janela aberta")
	}
	if err := db.MarkPendingReverting(p.ID, time.Now()); err != nil {
		t.Fatalf("MarkPendingReverting: %v", err)
	}

	got := getPending(t, h)
	if got == nil {
		t.Fatalf("o pendente em reversão não pode sumir da tela")
	}
	if !got.Reverting {
		t.Errorf("o painel não tem como saber que a reversão está em curso: %+v", got)
	}
	// E confirmar é recusado com 409 — conflito de estado, não erro do
	// servidor e não sucesso silencioso.
	w := doJSON(t, h.ConfirmPendingChange, "POST", "/api/nftables/pending/confirm", "")
	if w.Code != http.StatusConflict {
		t.Errorf("esperava 409 ao confirmar uma reversão em andamento, obtive %d (%s)", w.Code, w.Body.String())
	}
}

// ─── O pré-voo continua valendo para o escopo input ───────────────────────

// Um grupo de escopo input recusado pelo `nft -c` não pode chegar ao banco —
// nem, muito menos, armar uma janela para uma mudança que nunca foi aplicada.
// A validação da chain input é a parte mais nova do pré-voo (CheckGroups), e é
// justamente a que este caminho estreia.
func TestInputGroupRefusedByNftNeverReachesTheDBNorOpensAWindow(t *testing.T) {
	h, db := newGroupTestHandler(t)

	w := doJSON(t, h.CreateGroup, "POST", "/api/nftables/groups",
		`{"name":"Acesso","scope":"input","cond_iif":"`+nftRefusesToken+`","fallthrough":"continue"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("esperava 400 do pré-voo, obtive %d (%s)", w.Code, w.Body.String())
	}
	if groups := adminGroups(t, db); len(groups) != 0 {
		t.Errorf("nada podia ter chegado ao banco: %+v", groups)
	}
	if p := getPending(t, h); p != nil {
		t.Errorf("uma mudança que não foi aplicada não pode ter janela: %+v", p)
	}
}

// Escopo que este código não entende é recusado, e não normalizado para
// forward: tratá-lo como forward colocaria na chain de tráfego atravessando um
// grupo escrito para outra coisa.
func TestUnknownScopeIsRefused(t *testing.T) {
	h, db := newGroupTestHandler(t)
	w := doJSON(t, h.CreateGroup, "POST", "/api/nftables/groups",
		`{"name":"Estranho","scope":"output","fallthrough":"continue"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("esperava 400 para escopo desconhecido, obtive %d (%s)", w.Code, w.Body.String())
	}
	if groups := adminGroups(t, db); len(groups) != 0 {
		t.Errorf("nada podia ter chegado ao banco: %+v", groups)
	}
}

// ─── A janela é armada ANTES de a mudança ser aplicada ────────────────────
//
// Os dois testes abaixo são os dois defeitos críticos que a revisão da Fase C2
// provou por sonda numa máquina de teste, e que a suíte antiga deixava passar
// inteira. Nos dois, a causa era a mesma: a janela era armada DEPOIS do
// reconcile.

// C1 — reconcile que falha. O caminho existe e é conhecido: ReconcileGroups
// junta as falhas por grupo (uma regra que o nft recusa na hora de aplicar) e o
// mesmo vale para o erro de leitura do estado do NTP, já visto em produção.
//
// Com o arme depois do reconcile, este era o resultado medido: 500 "erro
// interno do servidor" na tela, grupo de escopo input GRAVADO no banco, jump
// dele VIVO na chain input, e nenhuma janela — sem pendente, sem auto-revert,
// sem trava. Uma regra que pode ter trancado o operador para fora da máquina,
// valendo para sempre, enquanto a resposta sugeria que nada tinha acontecido.
//
// Armando antes, a mesma falha cai na rede: a janela existe, a reversão é
// tentada na hora e — se ela também não passar, que é o caso aqui, porque a
// máquina continua com defeito — o pendente FICA e o watchdog conclui sozinho
// assim que o nft voltar a aceitar.
func TestAFailedReconcileLeavesTheWindowArmedAndTheWatchdogFinishesTheRevert(t *testing.T) {
	h, db, exec, fr := newGroupTestHandlerFR(t)

	// A máquina com defeito: outro grupo, já existente, tem uma regra que passa
	// no `nft -c` e é recusada no apply.
	other := createGroupViaAPI(t, h, db, `{"name":"LAN","cond_saddr":"192.168.3.0/24","fallthrough":"continue"}`)
	createRuleViaAPI(t, h, db, `{"group_id":"`+other.ID+`","action":"drop","saddr":"10.0.0.5"}`)
	heal := exec.refuseApplyIn(other.ChainName)

	w := doJSON(t, h.CreateGroup, "POST", "/api/nftables/groups", inputGroupBody)
	if w.Code == http.StatusOK {
		t.Fatalf("o reconcile falhou; a mutação não podia responder 200: %s", w.Body.String())
	}

	// O que este teste existe para exigir: a rede de proteção está armada.
	p := getPending(t, h)
	if p == nil {
		t.Fatalf("a mudança de escopo input ficou sem janela depois de um reconcile que falhou: %d %s", w.Code, w.Body.String())
	}

	// A máquina volta. É o watchdog — não o handler, que já respondeu — quem
	// conclui: pendente apagado, grupo de input fora do banco e nenhum jump
	// para ele na chain input viva.
	heal()
	if err := fr.CheckPendingExpired(context.Background()); err != nil {
		t.Fatalf("o watchdog não conseguiu concluir a reversão: %v", err)
	}
	if p := getPending(t, h); p != nil {
		t.Errorf("a janela continuou aberta depois de o watchdog reverter: %+v", p)
	}
	for _, g := range adminGroups(t, db) {
		if g.Scope == nftables.ScopeInput {
			t.Errorf("o grupo de escopo input não confirmado continuou no banco: %+v", g)
		}
		if exec.chainHasJumpTo(nftables.InputChain, g.ChainName) && g.Scope == nftables.ScopeInput {
			t.Errorf("a chain input viva continua pulando para o grupo revertido: %+v", g)
		}
	}
}

// C2 — duas mutações de escopo input ao mesmo tempo. Não precisa de dois
// operadores: um duplo-clique ou um retry do cliente basta, e o produto é
// multi-admin.
//
// Com o arme depois do reconcile, as duas passavam pela trava (que lê o
// pendente, e ainda não havia nenhum), as duas gravavam e as duas aplicavam;
// só a segunda descobria, ao armar, que já havia uma janela — e recebia 500
// dizendo que NÃO há reversão automática para a mudança dela. Pior: conforme a
// intercalação, o snapshot da vencedora era tirado depois da escrita da
// perdedora, e reverter restauraria um estado que ainda contém a mudança não
// confirmada — uma reversão que o operador acredita completa e não é.
//
// Armando antes, a tabela de uma linha só (UNIQUE only_row) é a fila: a
// segunda requisição leva 409 sem ter escrito no banco nem tocado no firewall.
func TestTwoConcurrentInputMutationsOnlyOneIsEverApplied(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)

	names := []string{"AcessoA", "AcessoB"}
	codes := make([]int, len(names))
	bodies := make([]string, len(names))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			<-start
			w := doJSON(t, h.CreateGroup, "POST", "/api/nftables/groups",
				`{"name":"`+name+`","scope":"input","cond_saddr":"192.168.3.0/24","fallthrough":"continue"}`)
			codes[i], bodies[i] = w.Code, w.Body.String()
		}(i, name)
	}
	close(start)
	wg.Wait()

	got := append([]int{}, codes...)
	sort.Ints(got)
	if got[0] != http.StatusOK || got[1] != http.StatusConflict {
		t.Fatalf("esperava um 200 e um 409, obtive %v (%q / %q)", codes, bodies[0], bodies[1])
	}

	// A perdedora não escreveu NADA: um grupo no banco, um jump na chain input.
	groups := adminGroups(t, db)
	if len(groups) != 1 {
		t.Fatalf("a segunda mutação simultânea não podia ter gravado: %+v", groups)
	}
	winner := groups[0]
	if jumps := jumpsIn(exec, nftables.InputChain); len(jumps) != 1 || jumps[0] != winner.ChainName {
		t.Errorf("a chain input viva tinha que ter só o grupo vencedor (%s): %v", winner.ChainName, jumps)
	}

	// E a rede de proteção é a da mudança que valeu, não a de outra.
	p := getPending(t, h)
	if p == nil {
		t.Fatalf("a mudança de input que passou ficou sem janela")
	}
	if !strings.Contains(p.Summary, winner.Name) {
		t.Errorf("a janela aberta descreve outra mudança que não a que valeu (%q): %q", winner.Name, p.Summary)
	}
}

// jumpsIn devolve, na ordem, as chains para as quais a chain viva pula.
func jumpsIn(exec *fakeNft, chain string) []string {
	var out []string
	for _, expr := range exec.liveChain(chain) {
		if target := jumpTargetOf(expr); strings.HasPrefix(target, "grp_") {
			out = append(out, target)
		}
	}
	return out
}

// ─── Todo caminho que arma a janela ───────────────────────────────────────

// Até esta revisão só três mutações tinham teste de arme (criar grupo, trocar o
// escopo e criar regra). As outras sete foram verificadas por sonda pelo
// revisor e ficaram sem rede: uma regressão em qualquer uma delas — um grupo de
// input apagado, desligado ou reordenado sem janela — passaria a suíte inteira
// em verde e só apareceria com o operador trancado para fora da máquina.
func TestEveryInputMutationOpensTheWindow(t *testing.T) {
	for _, c := range []struct {
		name string
		call func(t *testing.T, h *handlers.NftablesHandler, db *storage.DB, g storage.FirewallGroup, rule storage.FirewallRule) *httptest.ResponseRecorder
	}{
		{"apagar grupo de input", func(t *testing.T, h *handlers.NftablesHandler, db *storage.DB, g storage.FirewallGroup, _ storage.FirewallRule) *httptest.ResponseRecorder {
			return doJSON(t, h.DeleteGroup, "DELETE", "/api/nftables/groups", `{"id":"`+g.ID+`"}`)
		}},
		{"desligar grupo de input", func(t *testing.T, h *handlers.NftablesHandler, db *storage.DB, g storage.FirewallGroup, _ storage.FirewallRule) *httptest.ResponseRecorder {
			return doJSON(t, h.ToggleGroup, "POST", "/api/nftables/groups/toggle", `{"id":"`+g.ID+`","enabled":false}`)
		}},
		{"reordenar grupos com um de input", func(t *testing.T, h *handlers.NftablesHandler, db *storage.DB, _ storage.FirewallGroup, _ storage.FirewallRule) *httptest.ResponseRecorder {
			return doJSON(t, h.ReorderGroups, "POST", "/api/nftables/groups/reorder", `{"ids":`+reversedGroupIDsJSON(t, db)+`}`)
		}},
		{"editar regra de grupo de input", func(t *testing.T, h *handlers.NftablesHandler, db *storage.DB, g storage.FirewallGroup, rule storage.FirewallRule) *httptest.ResponseRecorder {
			return doJSON(t, h.UpdateRule, "PUT", "/api/nftables/rules",
				`{"id":"`+rule.ID+`","group_id":"`+g.ID+`","action":"accept","proto":"tcp","dport":"2222"}`)
		}},
		{"apagar regra de grupo de input", func(t *testing.T, h *handlers.NftablesHandler, db *storage.DB, _ storage.FirewallGroup, rule storage.FirewallRule) *httptest.ResponseRecorder {
			return doJSON(t, h.DeleteRule, "DELETE", "/api/nftables/rules", `{"id":"`+rule.ID+`"}`)
		}},
		{"desligar regra de grupo de input", func(t *testing.T, h *handlers.NftablesHandler, db *storage.DB, _ storage.FirewallGroup, rule storage.FirewallRule) *httptest.ResponseRecorder {
			return doJSON(t, h.ToggleRule, "POST", "/api/nftables/rules/toggle", `{"id":"`+rule.ID+`","enabled":false}`)
		}},
		{"reordenar regras com uma de input", func(t *testing.T, h *handlers.NftablesHandler, db *storage.DB, g storage.FirewallGroup, rule storage.FirewallRule) *httptest.ResponseRecorder {
			rules, err := db.ListFirewallRules()
			if err != nil {
				t.Fatalf("ListFirewallRules: %v", err)
			}
			ids := make([]string, 0, len(rules))
			for i := len(rules) - 1; i >= 0; i-- {
				ids = append(ids, rules[i].ID)
			}
			out, err := json.Marshal(ids)
			if err != nil {
				t.Fatalf("marshal dos ids: %v", err)
			}
			return doJSON(t, h.ReorderRules, "POST", "/api/nftables/rules/reorder", `{"ids":`+string(out)+`}`)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, db := newGroupTestHandler(t)
			// Uma máquina com um grupo de forward (e uma regra dentro) e um
			// grupo de input com a sua regra — a cara de um firewall de
			// verdade, e o mínimo para reordenar valer alguma coisa.
			fwd := createGroupViaAPI(t, h, db, `{"name":"LAN","cond_saddr":"192.168.3.0/24","fallthrough":"continue"}`)
			createRuleViaAPI(t, h, db, `{"group_id":"`+fwd.ID+`","action":"drop","saddr":"10.0.0.5"}`)
			g := createGroupViaAPI(t, h, db, inputGroupBody)
			confirmWindow(t, h)
			rule := createRuleViaAPI(t, h, db, `{"group_id":"`+g.ID+`","action":"accept","proto":"tcp","dport":"22"}`)
			confirmWindow(t, h)

			w := c.call(t, h, db, g, rule)
			if w.Code != http.StatusOK {
				t.Fatalf("status %d, body %s", w.Code, w.Body.String())
			}
			if pendingOf(t, w) == nil {
				t.Errorf("a resposta da mutação não trouxe a janela: %s", w.Body.String())
			}
			if getPending(t, h) == nil {
				t.Fatalf("a mutação mexeu na chain que decide sobre o SSH e o painel e não abriu janela nenhuma")
			}
		})
	}
}

// ─── Grupo do sistema ─────────────────────────────────────────────────────

// Grupo do sistema mora na forward, qualquer que seja a coluna scope (é
// GroupHostChain quem decide), então reordenar ou ligar/desligar um deles não
// abre janela nenhuma. Ler a coluna crua em vez de perguntar ao renderizador
// faria o LinkGuard travar a edição do firewall inteiro por 90 segundos por
// causa de uma linha de bloqueio administrativo.
func TestSystemGroupNeverOpensTheWindow(t *testing.T) {
	h, db := newGroupTestHandler(t)
	all, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatalf("ListFirewallGroups: %v", err)
	}
	var sys *storage.FirewallGroup
	for i, g := range all {
		if nftables.IsSystemGroup(g.Kind) {
			sys = &all[i]
			break
		}
	}
	if sys == nil {
		t.Fatalf("a máquina de teste tinha que ter os grupos do sistema: %+v", all)
	}
	// Com a coluna scope suja de "input" — o caso que o parser de um banco
	// mais novo, ou uma edição à mão, poderia produzir.
	sys.Scope = nftables.ScopeInput
	if err := db.UpdateFirewallGroup(sys); err != nil {
		t.Fatalf("UpdateFirewallGroup: %v", err)
	}

	w := doJSON(t, h.ToggleGroup, "POST", "/api/nftables/groups/toggle", `{"id":"`+sys.ID+`","enabled":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("ToggleGroup: status %d, body %s", w.Code, w.Body.String())
	}
	if p := getPending(t, h); p != nil {
		t.Errorf("grupo do sistema mora na forward e não podia abrir janela: %+v", p)
	}
}

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
	ID          string    `json:"id"`
	Summary     string    `json:"summary"`
	AppliedBy   string    `json:"applied_by"`
	ExpiresAt   time.Time `json:"expires_at"`
	SecondsLeft int       `json:"seconds_left"`
	Reverting   bool      `json:"reverting"`
	// NewConnectionsOnly é o sinalizador do aviso da spec §5 — o que a faixa
	// usa para dizer que a sessão atual do operador NÃO é afetada e que o
	// teste dos 90 segundos, sozinho, não prova nada.
	NewConnectionsOnly bool `json:"new_connections_only"`
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

// confirmWindow aperta "Confirmar" na janela que o painel está mostrando —
// isto é, mandando o id que veio do GET, como o painel manda. Usado pelos
// testes que precisam ENCERRAR uma janela para seguir com o que realmente
// estão medindo.
func confirmWindow(t *testing.T, h *handlers.NftablesHandler) {
	t.Helper()
	w := doJSON(t, h.ConfirmPendingChange, "POST", "/api/nftables/pending/confirm", confirmBody(t, h))
	if w.Code != http.StatusOK {
		t.Fatalf("confirmar: status %d, body %s", w.Code, w.Body.String())
	}
}

// confirmBody é o corpo de confirmar/reverter com o id da janela em aberto —
// o mesmo caminho do painel, que lê o id da faixa antes de oferecer os botões.
// Sem janela aberta manda um id inexistente, para que o teste meça a recusa do
// servidor e não a do próprio corpo.
func confirmBody(t *testing.T, h *handlers.NftablesHandler) string {
	t.Helper()
	if p := getPending(t, h); p != nil {
		return `{"id":"` + p.ID + `"}`
	}
	return `{"id":"nenhuma-janela-aberta"}`
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
	again := doJSON(t, h.ConfirmPendingChange, "POST", "/api/nftables/pending/confirm", confirmBody(t, h))
	if again.Code != http.StatusConflict {
		t.Errorf("esperava 409 ao confirmar sem janela, obtive %d (%s)", again.Code, again.Body.String())
	}
}

// Reverter desfaz a mudança E fecha a janela — no banco e no firewall vivo.
func TestRevertUndoesTheChangeAndClosesTheWindow(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)
	g := createGroupViaAPI(t, h, db, inputGroupBody)

	w := doJSON(t, h.RevertPendingChange, "POST", "/api/nftables/pending/revert", confirmBody(t, h))
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
	again := doJSON(t, h.RevertPendingChange, "POST", "/api/nftables/pending/revert", confirmBody(t, h))
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

// A contagem regressiva da faixa não pode depender do relógio da ESTAÇÃO do
// operador. Com só o expires_at no corpo, o painel compara um instante do
// servidor com o Date.now() do navegador e erra o número na medida exata do
// deslocamento entre os dois relógios — e é esse número que o operador usa para
// decidir se ainda dá tempo de testar o SSH antes de confirmar.
//
// Duas coisas juntas aqui: o campo existe e é coerente com o expires_at, e ele
// é RECALCULADO a cada resposta (um valor gravado seria a contagem de quando a
// linha foi escrita, e ficaria parado em 90 para sempre).
func TestPendingCarriesTheServerSideCountdown(t *testing.T) {
	h, db := newGroupTestHandler(t)
	createGroupViaAPI(t, h, db, inputGroupBody)

	first := getPending(t, h)
	if first == nil {
		t.Fatalf("esperava a janela aberta")
	}
	if first.SecondsLeft <= 0 || first.SecondsLeft > 90 {
		t.Fatalf("seconds_left fora da janela de 90 s: %d", first.SecondsLeft)
	}
	// Coerente com a verdade persistida: os dois descrevem o mesmo instante.
	//
	// A tolerância é assimétrica de propósito, e o lado negativo não é folga
	// para erro — é uma diferença REAL entre as duas grandezas:
	//
	//   - expires_at faz ida e volta pelo banco como segundos INTEIROS
	//     (SavePendingChange grava ExpiresAt.Unix()), então perde a fração e
	//     sempre encolhe, em até 1 s;
	//   - seconds_left sai do relógio MONOTÔNICO, que não passou pelo banco e
	//     mantém a precisão (SecondsLeft trunca, mas sobre o valor cheio).
	//
	// Com a janela armada em T+0,8 s, expires_at guarda T e seconds_left
	// responde 89 enquanto time.Until devolve 88,8 — diferença de -0,2 s, com
	// os dois campos corretos. Exigir d >= 0 fazia isto quebrar por sorte do
	// relógio: aconteceu numa execução de release (run 32082502722), derrubando
	// a publicação de um commit que não tinha defeito nenhum.
	//
	// O limite de 2 s do outro lado é o tempo do próprio teste.
	if d := time.Until(first.ExpiresAt).Seconds() - float64(first.SecondsLeft); d < -1 || d > 2 {
		t.Errorf("seconds_left (%d) não bate com expires_at (%v): diferença de %.1f s",
			first.SecondsLeft, first.ExpiresAt, d)
	}

	time.Sleep(1100 * time.Millisecond)
	second := getPending(t, h)
	if second == nil {
		t.Fatalf("a janela sumiu no meio do teste")
	}
	if second.SecondsLeft >= first.SecondsLeft {
		t.Errorf("seconds_left não foi recalculado: %d depois de %d, com 1,1 s de intervalo",
			second.SecondsLeft, first.SecondsLeft)
	}
	// E o expires_at continua no corpo, inalterado: ele é a verdade persistida,
	// e o painel ainda o usa (é dele que sai o horário absoluto).
	if !second.ExpiresAt.Equal(first.ExpiresAt) {
		t.Errorf("expires_at mudou entre duas leituras: %v vs %v", first.ExpiresAt, second.ExpiresAt)
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
	w := doJSON(t, h.ConfirmPendingChange, "POST", "/api/nftables/pending/confirm", confirmBody(t, h))
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
	}
	// A asserção que importa, e a única que enxerga o defeito de verdade (N-5):
	// a chain input VIVA não pode ter sobrado com um jump para uma chain cujo
	// grupo já saiu do banco. Percorrer os grupos que sobreviveram nunca
	// alcança esse caso — depois de uma reversão bem-sucedida não existe grupo
	// de input no banco para o laço visitar, e um jump órfão passaria
	// despercebido com a suíte inteira em verde.
	if jumps := jumpsIn(exec, nftables.InputChain); len(jumps) != 0 {
		t.Errorf("a chain input viva continua pulando para grupo nenhum depois da reversão: %v", jumps)
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

// ─── O que cada falha depois do arme desfaz ───────────────────────────────

// N-3. A ESCRITA NO BANCO que falha não mudou nada em lugar nenhum, e desfazer
// a janela aí não pode custar uma reescrita das chains vivas.
//
// A sonda do revisor: com o banco recusando o UPDATE de ToggleGroup (zero
// linhas alteradas), a mutação ainda emitia dez comandos de nft — `flush chain`
// da input e da forward seguidos da reconstrução —, porque o abort rodava a
// reversão inteira. Reescrever as chains de um firewall de produção por causa
// de um erro sem efeito nenhum é risco criado do nada.
func TestAFailedWriteDiscardsTheWindowWithoutTouchingTheFirewall(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)
	g := createGroupViaAPI(t, h, db, inputGroupBody)
	confirmWindow(t, h)

	// O banco recusando a escrita, como na sonda: um gatilho que aborta todo
	// UPDATE em firewall_groups.
	if _, err := db.Conn().Exec(
		`CREATE TRIGGER recusa_update BEFORE UPDATE ON firewall_groups
         BEGIN SELECT RAISE(ABORT, 'o banco recusou a escrita'); END`); err != nil {
		t.Fatalf("criar o gatilho: %v", err)
	}
	antes := len(exec.executed)

	w := doJSON(t, h.ToggleGroup, "POST", "/api/nftables/groups/toggle", `{"id":"`+g.ID+`","enabled":false}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("erro de banco é 500, obtive %d (%s)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "RAISE") || strings.Contains(w.Body.String(), "TRIGGER") {
		t.Errorf("o texto cru do banco não pode chegar à tela: %s", w.Body.String())
	}
	if depois := exec.executed[antes:]; len(depois) != 0 {
		t.Errorf("uma escrita que não mudou nada mandou %d comandos ao nft (a chain input e a forward foram reescritas à toa): %v",
			len(depois), depois)
	}
	if p := getPending(t, h); p != nil {
		t.Errorf("a janela armada por uma mutação que não chegou a valer tinha que ser apagada, não vencer em 90 segundos travando a edição: %+v", p)
	}
	if got := adminGroups(t, db)[0]; !got.Enabled {
		t.Errorf("nada podia ter mudado no banco: %+v", got)
	}
}

// N-4. A RECONCILIAÇÃO que falha é o outro ramo: a mudança já está no banco e
// pode estar pela metade no firewall vivo, então aí a reversão inteira é o que
// se quer. Quando ela DÁ CERTO, a resposta tem que dizer isso.
//
// Antes, esse caminho respondia o genérico "erro interno do servidor" — o
// operador não tinha como saber se a alteração valeu, valeu pela metade ou não
// valeu —, e a auditoria ficava com a linha da mutação (um nft.rule.add de uma
// regra que já não existe) sem nada dizendo que ela foi desfeita.
func TestAFailedApplyIsUndoneAndTheAnswerSaysSo(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)
	g := createGroupViaAPI(t, h, db, inputGroupBody)
	confirmWindow(t, h)
	// A chain do grupo passa no `nft -c` e é recusada no apply — a categoria de
	// falha que produz o `failures` de ReconcileGroups.
	exec.refuseApplyIn(g.ChainName)

	w := doJSON(t, h.CreateRule, "POST", "/api/nftables/rules",
		`{"group_id":"`+g.ID+`","action":"accept","proto":"tcp","dport":"22"}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("o apply falhou; esperava 500, obtive %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "estado anterior foi restaurado") {
		t.Errorf("a reversão deu certo e o operador precisa saber que o firewall ficou como estava; obtive %s", w.Body.String())
	}
	if p := getPending(t, h); p != nil {
		t.Errorf("a reversão concluiu; a janela não podia ter ficado: %+v", p)
	}
	rules, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("a regra que não pôde ser aplicada continuou no banco: %+v", rules)
	}
	// A linha compensatória da auditoria: sem ela o histórico afirma uma
	// alteração que nunca chegou a valer.
	logs, err := db.GetAuditLogs(50)
	if err != nil {
		t.Fatalf("GetAuditLogs: %v", err)
	}
	var add, undo bool
	for _, l := range logs {
		if l.Action == "nft.rule.add" {
			add = true
		}
		if l.Action == "nft.pending.revert" {
			undo = true
		}
	}
	if !add {
		t.Fatalf("a mutação tinha que ter deixado a linha dela na auditoria: %+v", logs)
	}
	if !undo {
		t.Errorf("a auditoria ficou com a criação da regra e nada dizendo que ela foi desfeita: %+v", logs)
	}
}

// ─── A janela em que se age é a que o operador viu ────────────────────────

// N-1. Confirmar cancela a reversão automática de uma mudança. Cancelar a de
// uma mudança que o operador NUNCA VIU é o oposto do que a janela existe para
// fazer — e é o que acontecia enquanto confirmar agisse sobre "a janela que
// estiver aberta" em vez de sobre a que o painel mostrou.
//
// O caminho é real num produto multi-admin: o operador abre a tela com a
// janela de A na faixa, e no segundo em que ele decide, A confirma (ou o prazo
// vence e outra mudança é aplicada). O clique dele passava a valer sobre a
// janela de B.
func TestConfirmingAWindowThatIsNoLongerTheOpenOneIsRefused(t *testing.T) {
	h, db := newGroupTestHandler(t)

	primeira := createGroupViaAPI(t, h, db, inputGroupBody)
	velha := getPending(t, h)
	if velha == nil {
		t.Fatalf("esperava a janela da primeira mudança")
	}
	confirmWindow(t, h) // a janela que o operador tinha na tela some

	// Outra mudança de escopo input entra no lugar — a janela agora é OUTRA.
	segunda := createGroupViaAPI(t, h, db,
		`{"name":"Outro acesso","scope":"input","cond_saddr":"10.0.0.0/24","fallthrough":"continue"}`)
	nova := getPending(t, h)
	if nova == nil || nova.ID == velha.ID {
		t.Fatalf("esperava uma janela nova, obtive %+v", nova)
	}

	w := doJSON(t, h.ConfirmPendingChange, "POST", "/api/nftables/pending/confirm", `{"id":"`+velha.ID+`"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("confirmar com um id obsoleto tinha que ser 409, obtive %d (%s)", w.Code, w.Body.String())
	}
	// E a janela da outra mudança continua de pé, com os 90 segundos dela: ela
	// não pode ter sido confirmada por um clique dirigido a outra coisa.
	ainda := getPending(t, h)
	if ainda == nil || ainda.ID != nova.ID {
		t.Fatalf("a janela da mudança que ninguém viu foi resolvida pelo clique errado: %+v", ainda)
	}
	if !strings.Contains(ainda.Summary, segunda.Name) {
		t.Errorf("a janela em aberto tinha que ser a da segunda mudança (%q): %q", segunda.Name, ainda.Summary)
	}
	if primeira.ID == segunda.ID {
		t.Fatal("os dois grupos do teste tinham que ser diferentes")
	}
}

// A mesma exigência para reverter: "Reverter agora" desfaz uma mudança. Se a
// janela já é outra, o clique desfaria a mudança de outra pessoa — e o operador
// leria "revertido" sobre a que ele queria desfazer, que continua valendo.
func TestRevertingAWindowThatIsNoLongerTheOpenOneIsRefused(t *testing.T) {
	h, db := newGroupTestHandler(t)

	createGroupViaAPI(t, h, db, inputGroupBody)
	velha := getPending(t, h)
	if velha == nil {
		t.Fatalf("esperava a janela da primeira mudança")
	}
	confirmWindow(t, h)
	createGroupViaAPI(t, h, db,
		`{"name":"Outro acesso","scope":"input","cond_saddr":"10.0.0.0/24","fallthrough":"continue"}`)

	w := doJSON(t, h.RevertPendingChange, "POST", "/api/nftables/pending/revert", `{"id":"`+velha.ID+`"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("reverter com um id obsoleto tinha que ser 409, obtive %d (%s)", w.Code, w.Body.String())
	}
	if len(adminGroups(t, db)) != 2 {
		t.Errorf("a mudança de outra janela foi desfeita pelo clique errado: %+v", adminGroups(t, db))
	}
}

// Sem id não dá para saber em qual janela o operador está agindo, e o servidor
// não escolhe por ele: 400 com a explicação, nunca "resolvo a que estiver
// aberta".
func TestConfirmAndRevertRequireTheWindowId(t *testing.T) {
	h, db := newGroupTestHandler(t)
	createGroupViaAPI(t, h, db, inputGroupBody)

	for _, c := range []struct {
		name string
		fn   http.HandlerFunc
		path string
	}{
		{"confirmar", h.ConfirmPendingChange, "/api/nftables/pending/confirm"},
		{"reverter", h.RevertPendingChange, "/api/nftables/pending/revert"},
	} {
		w := doJSON(t, c.fn, "POST", c.path, `{}`)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s sem id: esperava 400, obtive %d (%s)", c.name, w.Code, w.Body.String())
		}
	}
	if getPending(t, h) == nil {
		t.Error("nenhuma das duas chamadas sem id podia ter resolvido a janela")
	}
}

// ─── O beco sem saída da reversão que não reconcilia (N-2) ────────────────

// A sonda do revisor, numa máquina em que o reconcile continua quebrado (uma
// regra que o `nft -c` aprova e o apply recusa). Antes desta correção, TODA
// saída estava fechada:
//
//	mutação de escopo input:                 500 (o pendente fica, revertendo)
//	apagar a regra que quebra o reconcile:   409 "a reversão está em andamento"
//	desligar o grupo ruim:                   409 (idem)
//	confirmar:                               409 "a reversão já começou"
//	reverter agora:                          500 "não foi possível concluir"
//
// Reboot não ajudava (RevertPendingOnBoot falha igual e mantém o pendente), e a
// única saída era sqlite3 na máquina. Este teste percorre a sonda inteira e
// exige que a linha que importa — apagar a regra que quebra a reconciliação —
// passe.
func TestAFailedRevertDoesNotTrapTheOperator(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)

	// A máquina com defeito: um grupo de forward com uma regra que passa no
	// `nft -c` e é recusada no apply.
	lan := createGroupViaAPI(t, h, db, `{"name":"LAN","cond_saddr":"192.168.3.0/24","fallthrough":"continue"}`)
	quebra := createRuleViaAPI(t, h, db, `{"group_id":"`+lan.ID+`","action":"drop","saddr":"10.0.0.5"}`)
	exec.refuseApplyIn(lan.ChainName)

	// A mutação de escopo input falha no reconcile; a reversão é tentada na
	// hora e também não passa. O pendente fica, revertendo.
	w := doJSON(t, h.CreateGroup, "POST", "/api/nftables/groups", inputGroupBody)
	if w.Code == http.StatusOK {
		t.Fatalf("o reconcile falhou; a mutação não podia responder 200: %s", w.Body.String())
	}
	p := getPending(t, h)
	if p == nil || !p.Reverting {
		t.Fatalf("esperava o pendente em reversão depois da falha: %+v", p)
	}

	// As duas saídas da janela continuam fechadas — e é assim mesmo: confirmar
	// uma mudança cujo estado anterior já voltou ao banco seria dizer "fica
	// valendo" sobre o que já saiu de lá, e reverter de novo esbarra na mesma
	// máquina quebrada.
	if c := doJSON(t, h.ConfirmPendingChange, "POST", "/api/nftables/pending/confirm", `{"id":"`+p.ID+`"}`); c.Code != http.StatusConflict {
		t.Errorf("confirmar uma reversão em andamento: esperava 409, obtive %d (%s)", c.Code, c.Body.String())
	}
	if rv := doJSON(t, h.RevertPendingChange, "POST", "/api/nftables/pending/revert", `{"id":"`+p.ID+`"}`); rv.Code != http.StatusInternalServerError {
		t.Errorf("reverter com o nft ainda recusando: esperava 500, obtive %d (%s)", rv.Code, rv.Body.String())
	}

	// A saída que o operador precisa ter: apagar a regra que quebra a
	// reconciliação. É uma mutação de grupo de forward, e ela reconcilia
	// também — o banco já está no estado anterior, então ela é parte da
	// solução, não um risco.
	del := doJSON(t, h.DeleteRule, "DELETE", "/api/nftables/rules", `{"id":"`+quebra.ID+`"}`)
	if del.Code != http.StatusOK {
		t.Fatalf("o operador ficou sem saída: apagar a regra que quebra o reconcile deu %d (%s)", del.Code, del.Body.String())
	}

	// E o beco fechou de verdade: a reconciliação desta mutação cumpriu a
	// única pendência que restava à reversão, então o pendente sai do caminho
	// em vez de travar a próxima edição.
	if p := getPending(t, h); p != nil {
		t.Fatalf("o pendente da reversão já concluída continuou travando a edição: %+v", p)
	}
	// A mudança de escopo input não confirmada NÃO ficou valendo, nem no banco
	// nem no firewall vivo — a reversão foi de verdade.
	for _, g := range adminGroups(t, db) {
		if g.Scope == nftables.ScopeInput {
			t.Errorf("a mudança de input que falhou continuou no banco: %+v", g)
		}
	}
	if jumps := jumpsIn(exec, nftables.InputChain); len(jumps) != 0 {
		t.Errorf("a chain input viva ficou com jump para um grupo que não existe: %v", jumps)
	}
	// E a máquina voltou a aceitar edição normal.
	again := doJSON(t, h.CreateGroup, "POST", "/api/nftables/groups", `{"name":"Depois","fallthrough":"continue"}`)
	if again.Code != http.StatusOK {
		t.Fatalf("a edição continuou travada depois de tudo resolvido: %d (%s)", again.Code, again.Body.String())
	}
}

// A outra saída da mesma sonda: a mutação que o operador precisa fazer pode ser
// de ESCOPO INPUT (é comum: o grupo de input que ele acabou de mexer é
// justamente o que ele quer desligar). Ela arma a própria janela, e a janela da
// reversão já concluída no banco dá lugar a ela — nada se perde, porque o banco
// É o snapshot dela neste instante.
func TestAnInputMutationAlsoEscapesAStalledRevert(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)

	lan := createGroupViaAPI(t, h, db, `{"name":"LAN","cond_saddr":"192.168.3.0/24","fallthrough":"continue"}`)
	createRuleViaAPI(t, h, db, `{"group_id":"`+lan.ID+`","action":"drop","saddr":"10.0.0.5"}`)
	heal := exec.refuseApplyIn(lan.ChainName)

	w := doJSON(t, h.CreateGroup, "POST", "/api/nftables/groups", inputGroupBody)
	if w.Code == http.StatusOK {
		t.Fatalf("o reconcile falhou; a mutação não podia responder 200: %s", w.Body.String())
	}
	travada := getPending(t, h)
	if travada == nil || !travada.Reverting {
		t.Fatalf("esperava o pendente em reversão depois da falha: %+v", travada)
	}

	// A máquina volta ao normal e o operador aplica uma mudança de input.
	heal()
	nova := doJSON(t, h.CreateGroup, "POST", "/api/nftables/groups",
		`{"name":"Acesso novo","scope":"input","cond_saddr":"10.0.0.0/24","fallthrough":"continue"}`)
	if nova.Code != http.StatusOK {
		t.Fatalf("a mutação de input ficou sem saída: %d (%s)", nova.Code, nova.Body.String())
	}
	p := getPending(t, h)
	if p == nil {
		t.Fatalf("a mudança de input nova ficou sem rede de proteção")
	}
	if p.ID == travada.ID || p.Reverting {
		t.Fatalf("a janela em aberto tinha que ser a da mudança nova: %+v", p)
	}
	if !strings.Contains(p.Summary, "Acesso novo") {
		t.Errorf("a janela aberta descreve outra mudança: %q", p.Summary)
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

// ─── A escolha "só conexões novas" e a janela ─────────────────────────────

// Mudar o conn_state de um grupo de escopo input é mexer na chain que decide
// sobre o SSH e o painel: abre janela, como qualquer outra mutação que alcance
// a input. Aqui isso importa MAIS, não menos — é justamente a escolha em que a
// sessão do operador não cai, então ele testaria com uma conexão que sobreviveu
// e confirmaria um bloqueio que só morde na próxima reconexão. A janela é o que
// dá o tempo (e, com a Task 4, o aviso) para ele testar direito.
func TestChangingConnStateOfAnInputGroupOpensTheWindow(t *testing.T) {
	h, db := newGroupTestHandler(t)
	g := createGroupViaAPI(t, h, db, inputGroupBody)
	confirmWindow(t, h)

	w := doJSON(t, h.UpdateGroup, "PUT", "/api/nftables/groups",
		`{"id":"`+g.ID+`","name":"Acesso ao firewall","scope":"input","cond_saddr":"192.168.3.0/24","fallthrough":"continue","conn_state":"new"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("UpdateGroup: status %d, body %s", w.Code, w.Body.String())
	}
	if pendingOf(t, w) == nil {
		t.Errorf("restringir um grupo de input tinha que abrir a janela: %s", w.Body.String())
	}
	after := adminGroups(t, db)[0]
	if after.ConnState != nftables.ConnStateNew {
		t.Fatalf("a escolha não chegou ao banco: %+v", after)
	}
}

// E soltar de volta também abre: sair de "só conexões novas" faz o grupo
// voltar a derrubar o que já está de pé — inclusive a sessão do operador. Nos
// dois sentidos vale a regra deste mecanismo: na dúvida, abre.
//
// As duas asserções do fim NÃO são decoração, e a revisão provou por quê: sem
// elas, este teste continuava VERDE com o UpdateGroup ignorando b.ConnState
// por completo. Ele mediria só "editar um grupo de input abre janela" — que
// vale para qualquer edição, inclusive uma que não mudou nada — enquanto SOLTAR
// a restrição é justamente o sentido que volta a derrubar conexão viva, e por
// isso o que mais precisa da janela. Um teste que passa com a feature arrancada
// é pior que teste nenhum: dá sensação de cobertura onde não há.
func TestLooseningConnStateOfAnInputGroupAlsoOpensTheWindow(t *testing.T) {
	h, db, exec := newGroupTestHandlerNft(t)
	g := createGroupViaAPI(t, h, db,
		`{"name":"Acesso ao firewall","scope":"input","cond_saddr":"192.168.3.0/24","fallthrough":"continue","conn_state":"new"}`)
	confirmWindow(t, h)
	// O ponto de partida é real, e não suposto: a linha viva nasceu restrita.
	if line := jumpLineTo(t, exec, nftables.InputChain, g.ChainName); !strings.Contains(line, "ct state new") {
		t.Fatalf("o teste ia medir a soltura de uma restrição que nunca existiu: %q", line)
	}

	w := doJSON(t, h.UpdateGroup, "PUT", "/api/nftables/groups",
		`{"id":"`+g.ID+`","name":"Acesso ao firewall","scope":"input","cond_saddr":"192.168.3.0/24","fallthrough":"continue","conn_state":"any"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("UpdateGroup: status %d, body %s", w.Code, w.Body.String())
	}
	if pendingOf(t, w) == nil {
		t.Errorf("soltar um grupo de input tinha que abrir a janela: %s", w.Body.String())
	}
	// A soltura aconteceu de verdade — no banco e na chain input VIVA. Só com
	// as duas o teste guarda o caso que descreve.
	if after := adminGroups(t, db)[0]; after.ConnState != nftables.ConnStateAny {
		t.Fatalf("a soltura não chegou ao banco (mudei na tela e não aconteceu nada): %+v", after)
	}
	if line := jumpLineTo(t, exec, nftables.InputChain, g.ChainName); strings.Contains(line, "ct state") {
		t.Errorf("a restrição ficou no firewall vivo depois de ser desfeita: %q", line)
	}
}

// E o contrapeso: num grupo de forward a mesma edição não custa 90 segundos.
// Uma janela que abre em tudo é uma janela que o operador aprende a clicar sem
// ler.
func TestChangingConnStateOfAForwardGroupDoesNotOpenTheWindow(t *testing.T) {
	h, db := newGroupTestHandler(t)
	g := createGroupViaAPI(t, h, db, `{"name":"LAN","cond_saddr":"192.168.3.0/24","fallthrough":"continue"}`)

	w := doJSON(t, h.UpdateGroup, "PUT", "/api/nftables/groups",
		`{"id":"`+g.ID+`","name":"LAN","cond_saddr":"192.168.3.0/24","fallthrough":"continue","conn_state":"new"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("UpdateGroup: status %d, body %s", w.Code, w.Body.String())
	}
	if p := pendingOf(t, w); p != nil {
		t.Errorf("mutação de escopo forward não podia abrir janela: %+v", p)
	}
	if p := getPending(t, h); p != nil {
		t.Fatalf("GET devolveu janela aberta depois de uma mutação de forward: %+v", p)
	}
}

// ─── O aviso que torna esta feature aceitável (spec §5) ───────────────────
//
// Um grupo de escopo input restrito a "só conexões novas" que bloqueie o
// painel NÃO derruba a sessão do operador — é a promessa da feature. O teste
// de acesso dos 90 segundos, que existe justamente porque a sessão CAI quando
// alguém se tranca para fora, passa a mentir para essa combinação: ele testa
// na aba que já estava aberta, vê tudo funcionando, confirma, e descobre o
// bloqueio na próxima reconexão, quando não há mais reversão automática
// nenhuma.
//
// O sinalizador abaixo é o que a faixa usa para dizer isso com todas as
// letras. Sem ele a rede de proteção vira teatro, e é melhor não ter a
// feature.

// wantNewOnlyFlag confere o sinalizador nas DUAS pontas, e as duas importam:
// o corpo da própria mutação é o que faz a faixa aparecer no instante do
// salvar (o painel adota o pendente que veio no 200), e o GET é o que o poll
// de 3 s relê logo em seguida, sobrescrevendo o que estava na tela. Um
// sinalizador certo só numa delas é um aviso que pisca e some.
func wantNewOnlyFlag(t *testing.T, h *handlers.NftablesHandler, w *httptest.ResponseRecorder, want bool, what string) {
	t.Helper()
	p := pendingOf(t, w)
	if p == nil {
		t.Fatalf("%s: a mutação tinha que abrir a janela: %s", what, w.Body.String())
	}
	if p.NewConnectionsOnly != want {
		t.Errorf("%s: no corpo da mutação, new_connections_only=%v, queria %v (%s)",
			what, p.NewConnectionsOnly, want, w.Body.String())
	}
	g := getPending(t, h)
	if g == nil {
		t.Fatalf("%s: o GET tinha que devolver a janela aberta", what)
	}
	if g.NewConnectionsOnly != want {
		t.Errorf("%s: no GET /api/nftables/pending, new_connections_only=%v, queria %v", what, g.NewConnectionsOnly, want)
	}
}

// O caso central: criar um grupo de escopo input restrito a conexões novas.
func TestWindowOfANewOnlyInputGroupCarriesTheWarning(t *testing.T) {
	h, _, exec := newGroupTestHandlerNft(t)

	w := doJSON(t, h.CreateGroup, "POST", "/api/nftables/groups",
		`{"name":"Acesso ao firewall","scope":"input","cond_saddr":"192.168.3.0/24","fallthrough":"drop","conn_state":"new"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("CreateGroup: status %d, body %s", w.Code, w.Body.String())
	}
	// O ponto de partida é real, não suposto: a linha viva na chain input
	// nasceu com a restrição. Sem isto o teste poderia estar medindo o aviso
	// de uma restrição que nunca chegou ao firewall.
	var created storage.FirewallGroup
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode do grupo criado: %v (body %s)", err, w.Body.String())
	}
	if line := jumpLineTo(t, exec, nftables.InputChain, created.ChainName); !strings.Contains(line, "ct state new") {
		t.Fatalf("a restrição não chegou à chain input viva: %q", line)
	}

	wantNewOnlyFlag(t, h, w, true, "criação de grupo input restrito")
}

// E o contrapeso, que é o que impede o aviso de virar ruído: a janela de um
// grupo COMUM de escopo input não o mostra. Ali a sessão do operador cai
// mesmo, e o teste dos 90 segundos vale sozinho — dizer "a sua sessão atual
// não é afetada" seria falso, e na direção que mais dói.
func TestWindowOfAPlainInputGroupDoesNotCarryTheWarning(t *testing.T) {
	h, _ := newGroupTestHandler(t)

	w := doJSON(t, h.CreateGroup, "POST", "/api/nftables/groups", inputGroupBody)
	if w.Code != http.StatusOK {
		t.Fatalf("CreateGroup: status %d, body %s", w.Code, w.Body.String())
	}
	wantNewOnlyFlag(t, h, w, false, "criação de grupo input comum")
}

// O aviso é sobre ESTA mudança, não sobre o que já existia na máquina. Um
// grupo restrito que ninguém tocou não muda nada para quem está testando o
// acesso agora, e um aviso que aparece em toda janela é um aviso que o
// operador aprende a pular — que é exatamente o defeito que ele existe para
// não ter.
func TestAnUntouchedNewOnlyGroupDoesNotWarnOnSomeoneElsesWindow(t *testing.T) {
	h, db := newGroupTestHandler(t)
	createGroupViaAPI(t, h, db,
		`{"name":"Só conexões novas","scope":"input","cond_saddr":"192.168.50.0/24","fallthrough":"drop","conn_state":"new"}`)
	confirmWindow(t, h)

	// Outro grupo, comum, de escopo input: a janela é dele.
	w := doJSON(t, h.CreateGroup, "POST", "/api/nftables/groups", inputGroupBody)
	if w.Code != http.StatusOK {
		t.Fatalf("CreateGroup: status %d, body %s", w.Code, w.Body.String())
	}
	wantNewOnlyFlag(t, h, w, false, "grupo comum com um restrito já existente na máquina")
}

// SOLTAR a restrição (new → any) NÃO avisa: ali o grupo volta a derrubar o que
// já está de pé, a sessão do operador cai junto se for atingida, e o teste dos
// 90 segundos volta a valer sozinho. Avisar aqui diria "a sua sessão atual não
// é afetada" para a única edição desta feature que a afeta de novo.
func TestLooseningANewOnlyInputGroupDoesNotWarn(t *testing.T) {
	h, db := newGroupTestHandler(t)
	g := createGroupViaAPI(t, h, db,
		`{"name":"Acesso ao firewall","scope":"input","cond_saddr":"192.168.3.0/24","fallthrough":"drop","conn_state":"new"}`)
	confirmWindow(t, h)

	w := doJSON(t, h.UpdateGroup, "PUT", "/api/nftables/groups",
		`{"id":"`+g.ID+`","name":"Acesso ao firewall","scope":"input","cond_saddr":"192.168.3.0/24","fallthrough":"drop","conn_state":"any"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("UpdateGroup: status %d, body %s", w.Code, w.Body.String())
	}
	if after := adminGroups(t, db)[0]; after.ConnState != nftables.ConnStateAny {
		t.Fatalf("a soltura não chegou ao banco; o teste mediria outra coisa: %+v", after)
	}
	wantNewOnlyFlag(t, h, w, false, "soltura da restrição")
}

// O caso mais perigoso da feature, e o que um sinalizador ingênuo (só a linha
// do grupo) deixaria passar: a regra que bloqueia o painel é acrescentada
// DENTRO de um grupo restrito que já existia. A linha de jump do grupo não
// muda uma vírgula — o que muda é o que ele faz com quem entra nele —, e a
// sessão aberta do operador continua de pé afirmando que está tudo bem.
func TestARuleAddedInsideANewOnlyInputGroupCarriesTheWarning(t *testing.T) {
	h, db := newGroupTestHandler(t)
	g := createGroupViaAPI(t, h, db,
		`{"name":"Acesso ao firewall","scope":"input","cond_saddr":"192.168.3.0/24","fallthrough":"continue","conn_state":"new"}`)
	confirmWindow(t, h)

	w := doJSON(t, h.CreateRule, "POST", "/api/nftables/rules",
		`{"group_id":"`+g.ID+`","action":"drop","proto":"tcp","dport":"9997","description":"bloqueia o painel"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("CreateRule: status %d, body %s", w.Code, w.Body.String())
	}
	wantNewOnlyFlag(t, h, w, true, "regra nova dentro de um grupo input restrito")
}

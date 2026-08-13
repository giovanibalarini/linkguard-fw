package handlers

// Confirmar-ou-reverte pelo lado da API (Fase C2, spec §5) — a rede de
// proteção de internal/firewallrules ligada ao mundo exterior.
//
// Aqui moram as SAÍDAS da janela — confirmar e reverter — mais o GET que o
// painel lê para desenhar a faixa com a contagem regressiva, e o arme da
// janela pelas mutações de escopo input.
//
// A outra metade do mecanismo é a TRAVA (confirmWindowBlocks, em nftables.go):
// enquanto uma janela está aberta, nenhuma mutação de grupo ou regra é aceita
// (spec §5.3). As duas metades são inseparáveis, e nesta ordem: a trava só é
// aceitável porque as saídas existem — uma trava sem saída prenderia o
// operador dentro da janela, que é o oposto do objetivo.
//
// O que pode ABRIR uma janela é deliberadamente estreito: só mutação de grupo
// e de regra. O snapshot que a reversão restaura cobre `groups` e `rules` e
// mais nada (ver stateSnapshot em internal/firewallrules/confirm.go), enquanto
// as mesmas chains forward e input também são renderizadas a partir dos named
// sets de bloqueio, dos port forwards e do toggle de NTP. Uma mutação dessas
// que abrisse janela seria revertida pela METADE — o pior resultado possível
// aqui, porque o operador acredita que o estado anterior voltou inteiro.

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/auth"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// pendingView é a mudança pendente como o painel a vê. O Snapshot NÃO vem
// junto de propósito: é o estado anterior inteiro dos grupos e das regras,
// grande, sem uso na tela e desnecessariamente detalhado para quem tem apenas
// firewall.read num painel multi-admin.
//
// Reverting é o campo que separa os dois estados possíveis, e o painel PRECISA
// dos dois porque os botões disponíveis são outros em cada um:
//
//   - aguardando confirmação (Reverting=false): cabem "Confirmar" e "Reverter
//     agora";
//   - revertendo (Reverting=true): a reversão já começou, o estado anterior já
//     voltou ao banco e o que falta é o firewall vivo aceitar — não cabe
//     nenhum dos dois botões (ConfirmPending recusa), e o texto tem que dizer
//     que a reversão está em curso.
type pendingView struct {
	ID          string     `json:"id"`
	Summary     string     `json:"summary"`
	AppliedBy   string     `json:"applied_by"`
	ExpiresAt   time.Time  `json:"expires_at"`
	CreatedAt   time.Time  `json:"created_at"`
	Reverting   bool       `json:"reverting"`
	RevertingAt *time.Time `json:"reverting_at,omitempty"`
}

func newPendingView(p *storage.PendingChange) *pendingView {
	if p == nil {
		return nil
	}
	v := &pendingView{
		ID:        p.ID,
		Summary:   p.Summary,
		AppliedBy: p.AppliedBy,
		ExpiresAt: p.ExpiresAt,
		CreatedAt: p.CreatedAt,
		Reverting: p.Reverting(),
	}
	if p.Reverting() {
		at := p.RevertingAt
		v.RevertingAt = &at
	}
	return v
}

// pendingResponse é o corpo do GET. O campo é um ponteiro SEM omitempty: sem
// janela aberta o painel recebe `{"pending": null}`, uma resposta explícita, e
// não um objeto vazio que ele teria de adivinhar.
type pendingResponse struct {
	Pending *pendingView `json:"pending"`
}

// mutationResult é o corpo comum das mutações que já respondiam
// `{"status":"ok"}` — agora com o pendente recém-criado junto, quando a
// mutação abriu a janela. O campo é omitido quando não há janela, para que
// nenhum cliente antigo veja um campo novo onde antes não havia nada.
type mutationResult struct {
	Status  string       `json:"status"`
	Pending *pendingView `json:"pending,omitempty"`
}

func okResult(p *pendingView) mutationResult {
	return mutationResult{Status: "ok", Pending: p}
}

// createdGroupResult e createdRuleResult acrescentam o pendente à linha criada
// SEM mudar o formato que o painel já lê: o embutido é achatado pelo
// encoding/json, então todo campo do grupo/da regra continua no mesmo lugar.
type createdGroupResult struct {
	*storage.FirewallGroup
	Pending *pendingView `json:"pending,omitempty"`
}

type createdRuleResult struct {
	*storage.FirewallRule
	Pending *pendingView `json:"pending,omitempty"`
}

// PendingChange (GET /api/nftables/pending) devolve a janela em aberto, ou
// null quando não há nenhuma.
//
// Erro de leitura vira 500, e nunca "não há nada pendente": a faixa da
// contagem regressiva sumindo da tela por causa de um SELECT que falhou é o
// operador concluindo que já confirmou, no exato minuto em que confirmar é a
// única coisa que devolve o acesso dele. É a mesma razão de
// firewallrules.PendingChangeOrError não ter a forma "conveniente" que engolia
// o erro.
func (h *NftablesHandler) PendingChange(w http.ResponseWriter, r *http.Request) {
	p, err := h.fr.PendingChangeOrError()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pendingResponse{Pending: newPendingView(p)})
}

// ConfirmPendingChange (POST /api/nftables/pending/confirm) é o operador
// dizendo "ainda tenho acesso": a mudança passa a valer definitivamente e o
// firewall vivo não é tocado (ver firewallrules.ConfirmPending).
//
// O status do erro é escolhido pelo ESTADO, não pelo texto: não haver
// pendente, ou haver um cuja reversão já começou, é conflito do cliente com o
// estado do servidor (409) e a mensagem é nossa, escrita para o operador.
// Qualquer outra falha é do servidor (500) e vira a mensagem genérica — um
// erro de banco não pode virar 400 com SQL cru na tela.
func (h *NftablesHandler) ConfirmPendingChange(w http.ResponseWriter, r *http.Request) {
	p, err := h.fr.PendingChangeOrError()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if err := h.fr.ConfirmPending(r.Context()); err != nil {
		if p == nil || p.Reverting() {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "nft.pending.confirm", "pending:"+p.ID, p.Summary)
	writeJSON(w, http.StatusOK, okResult(nil))
}

// RevertPendingChange (POST /api/nftables/pending/revert) é o "Reverter agora":
// desfaz a mudança sem esperar os 90 segundos acabarem.
//
// A reversão que não conclui NÃO é um caminho perdido: o pendente fica no
// banco e o watchdog retoma sozinho (ver firewallrules.revert). É isso que a
// mensagem de erro diz — o operador precisa saber que ainda há alguém tentando
// devolver o acesso dele, e não que a reversão fracassou e acabou.
func (h *NftablesHandler) RevertPendingChange(w http.ResponseWriter, r *http.Request) {
	p, err := h.fr.PendingChangeOrError()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if p == nil {
		writeError(w, http.StatusConflict, "não há mudança aguardando confirmação")
		return
	}
	if err := h.fr.RevertPending(r.Context()); err != nil {
		slog.Error("a reversão pedida pelo operador não pôde ser concluída", "err", err, "resumo", p.Summary)
		writeError(w, http.StatusInternalServerError,
			"não foi possível concluir a reversão agora; a mudança continua pendente e o LinkGuard vai tentar de novo sozinho")
		return
	}
	auditAction(h.db, r, "nft.pending.revert", "pending:"+p.ID, p.Summary)
	saveNftSnapshot(r.Context(), h.db, h.svc)
	writeJSON(w, http.StatusOK, okResult(nil))
}

// pendingArm é o que uma mutação carrega entre "antes de escrever" e "depois
// de reconciliar" para armar a janela: o estado anterior e a frase que o
// operador vai ler na faixa. Nil quando a mutação não abre janela.
type pendingArm struct {
	snapshot string
	summary  string
}

// prepareConfirmWindow tira o snapshot do estado ANTERIOR, e é por isso que
// ela é chamada antes da escrita no banco — depois, o "estado anterior" já não
// existe em lugar nenhum para ser copiado.
//
// Devolve (nil, true) quando a mutação não envolve escopo input: é o caminho
// de toda mutação de tráfego atravessando, que não abre janela nenhuma.
// Falhar aqui aborta a mutação ANTES de aplicar qualquer coisa (500) — o
// oposto de aplicar a mudança arriscada e só então descobrir que não há para
// onde voltar.
func (h *NftablesHandler) prepareConfirmWindow(w http.ResponseWriter, needed bool, summary string) (*pendingArm, bool) {
	if !needed {
		return nil, true
	}
	snap, err := h.fr.SnapshotState()
	if err != nil {
		writeInternalError(w, err)
		return nil, false
	}
	return &pendingArm{snapshot: snap, summary: summary}, true
}

// armConfirmWindow grava o pendente depois de a mudança já ter sido aplicada e
// reconciliada, e devolve o que o painel mostra na faixa.
//
// Não conseguir armar é ERRO VISÍVEL (500), nunca um 200 silencioso: a
// alteração de escopo input já está valendo no firewall vivo e, sem o
// pendente, NÃO existe reversão automática. O operador que lesse "ok" acharia
// que tem 90 segundos de rede embaixo dele quando não tem nenhum — e essa é
// justamente a situação em que ele pode estar prestes a perder o acesso.
func (h *NftablesHandler) armConfirmWindow(w http.ResponseWriter, r *http.Request, arm *pendingArm) (*pendingView, bool) {
	if arm == nil {
		return nil, true
	}
	if err := h.fr.OpenConfirmWindow(r.Context(), arm.snapshot, actingUser(r), arm.summary); err != nil {
		slog.Error("a mudança de escopo input foi aplicada, mas a janela de confirmação NÃO pôde ser aberta: não há reversão automática para ela",
			"err", err, "resumo", arm.summary)
		writeError(w, http.StatusInternalServerError,
			"a alteração foi aplicada, mas a janela de confirmação não pôde ser aberta: NÃO há reversão automática. Confira agora se o acesso ao firewall continua funcionando e desfaça a alteração à mão se necessário.")
		return nil, false
	}
	p, err := h.fr.PendingChangeOrError()
	if err != nil {
		// A janela ESTÁ armada (OpenConfirmWindow gravou); o que falhou foi
		// reler o que acabou de ser gravado para desenhar a faixa. Falhar a
		// requisição aqui diria ao operador que a mudança não valeu — mentira,
		// e das perigosas: ela vale, e reverte sozinha em 90 segundos. O painel
		// busca o pendente pelo GET assim que a faixa monta.
		slog.Error("janela de confirmação aberta, mas não foi possível reler o pendente para a resposta", "err", err)
		return nil, true
	}
	return newPendingView(p), true
}

// actingUser é quem está fazendo a requisição, para o pendente e para a
// auditoria. "unknown" só acontece em caminho sem autenticação (teste); em
// produção toda rota destas passa pelo middleware de RBAC.
func actingUser(r *http.Request) string {
	if c := auth.ClaimsFromContext(r.Context()); c != nil {
		return c.Username
	}
	return "unknown"
}

// groupReachesInput diz se este grupo é alcançado na chain input — isto é, se
// mexer nele pode trancar o operador para fora da própria máquina.
//
// A pergunta é feita por GroupHostChain, e não pela coluna scope crua, porque
// é ela que decide de verdade onde o `jump` do grupo é escrito: grupo do
// sistema é sempre forward, qualquer que seja o valor da coluna, e escopo
// vazio (toda linha anterior à Fase C2) conta como forward. Ler a coluna
// direto aqui abriria janela para grupo do sistema com scope sujo e faria a
// resposta divergir do que o renderizador realmente faz.
func groupReachesInput(g storage.FirewallGroup) bool {
	return nftables.GroupHostChain(toStoredGroup(g)) == nftables.InputChain
}

// anyGroupReachesInput resolve os ids contra o banco e diz se ALGUM deles é um
// grupo de escopo input. Ids vazios ou que não existem são ignorados — quem
// valida existência é o handler, antes de chegar aqui.
//
// Falha de leitura devolve ok=false e já respondeu 500: na dúvida entre abrir
// e não abrir a janela, esta função não chuta "não abre". Uma janela a mais
// custa 90 segundos de espera ao operador; uma janela a menos custa o acesso
// dele.
func (h *NftablesHandler) anyGroupReachesInput(w http.ResponseWriter, ids ...string) (bool, bool) {
	groups, err := h.db.ListFirewallGroups()
	if err != nil {
		writeInternalError(w, err)
		return false, false
	}
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id != "" {
			want[id] = true
		}
	}
	for _, g := range groups {
		if want[g.ID] && groupReachesInput(g) {
			return true, true
		}
	}
	return false, true
}

// inputOrderChanged diz se a reordenação mexeu na posição de algum item que
// vive na chain input.
//
// `current` é a ordem de hoje (já ordenada por posição, como o banco devolve)
// e `next` é a lista pedida. O critério é largo de propósito: basta o ÍNDICE
// de um item de input mudar. O que realmente importa para a chain input é a
// ordem relativa entre os itens de input, mas distinguir os dois casos com
// precisão custaria um raciocínio a mais para economizar uma janela — e a
// regra deste componente é a oposta: na dúvida, abre.
func inputOrderChanged(current, next []string, isInput map[string]bool) bool {
	pos := make(map[string]int, len(current))
	for i, id := range current {
		pos[id] = i
	}
	for i, id := range next {
		if !isInput[id] {
			continue
		}
		if old, ok := pos[id]; !ok || old != i {
			return true
		}
	}
	return false
}

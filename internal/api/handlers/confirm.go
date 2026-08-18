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
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/auth"
	"github.com/giovanibalarini/linkguard-fw/internal/firewallrules"
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
//
// SecondsLeft é a contagem regressiva medida pelo relógio que DECIDE a hora de
// reverter — firewallrules.SecondsLeft, o mesmo desempate de windowExpired
// (monotônico enquanto a janela é deste processo, expires_at depois de um
// restart). Ele existe porque ExpiresAt sozinho obriga o painel a comparar um
// instante do servidor com o Date.now() da estação do operador: um relógio
// adiantado em 40 segundos mostra "45 s" quando restam 5, e o operador usa
// exatamente esse número para decidir se ainda dá tempo de testar o SSH antes de
// confirmar.
//
// M-2 da revisão final: este campo saía de `time.Until(expires_at)`, isto é, do
// relógio de PAREDE, enquanto quem reverte olha o deadline MONOTÔNICO. Numa
// máquina que É o servidor NTP da rede, um `makestep` do chrony fazia a
// contagem da tela e a reversão de verdade discordarem — e o comentário aqui
// afirmava que era "o mesmo relógio que o watchdog usa".
//
// Ele é RECALCULADO a cada resposta e não é gravado em lugar nenhum: um
// seconds_left persistido seria a contagem de quando a linha foi escrita. E
// ExpiresAt continua no corpo — é a verdade persistida, e é dela que este campo
// sai.
//
// NewConnectionsOnly é o que torna esta janela honesta para a escolha "só
// conexões novas" (spec §5), e é o único campo daqui que não descreve o
// pendente e sim o ESTADO que ele está protegendo. Ver newConnectionsOnly
// logo abaixo: a faixa que ele liga é a única coisa que separa o teste de 90
// segundos de um teatro, porque um grupo de escopo input restrito a
// `ct state new` não derruba a sessão do operador — ele testa na conexão que
// já estava de pé, vê tudo funcionando, confirma, e descobre o bloqueio na
// próxima reconexão, quando já não há rede de proteção nenhuma.
//
// SEM omitempty, de propósito: `false` é uma afirmação ("esta janela derruba
// a sua sessão se ela for atingida — o teste vale"), não a ausência de
// informação, e um cliente que não vê o campo não pode distinguir as duas.
type pendingView struct {
	ID                 string     `json:"id"`
	Summary            string     `json:"summary"`
	AppliedBy          string     `json:"applied_by"`
	ExpiresAt          time.Time  `json:"expires_at"`
	SecondsLeft        int        `json:"seconds_left"`
	CreatedAt          time.Time  `json:"created_at"`
	Reverting          bool       `json:"reverting"`
	RevertingAt        *time.Time `json:"reverting_at,omitempty"`
	NewConnectionsOnly bool       `json:"new_connections_only"`
}

// pendingView desenha a janela para o painel. É método do handler, e não uma
// função solta, por causa de um campo só: SecondsLeft tem que sair do serviço —
// é lá que mora o relógio que decide reverter (M-2).
func (h *NftablesHandler) pendingView(p *storage.PendingChange) *pendingView {
	if p == nil {
		return nil
	}
	v := &pendingView{
		ID:          p.ID,
		Summary:     p.Summary,
		AppliedBy:   p.AppliedBy,
		ExpiresAt:   p.ExpiresAt,
		SecondsLeft: h.fr.SecondsLeft(p),
		CreatedAt:   p.CreatedAt,
		Reverting:   p.Reverting(),
		// Calculado a cada resposta, como SecondsLeft, e pela mesma razão: ele
		// descreve o estado de AGORA, e o estado de agora muda (a reversão o
		// desfaz). Um valor gravado com a janela seria a resposta de quando a
		// linha foi escrita.
		NewConnectionsOnly: h.newConnectionsOnly(p.Snapshot),
	}
	if p.Reverting() {
		at := p.RevertingAt
		v.RevertingAt = &at
	}
	return v
}

// windowSnapshot é a parte do snapshot da janela que este arquivo lê: o estado
// ANTERIOR dos grupos e das regras, como firewallrules.stateSnapshot o
// serializa. Declarado aqui porque aquele tipo é privado do outro pacote, e o
// que se compara são os mesmos dois campos com as mesmas tags.
type windowSnapshot struct {
	Groups []storage.FirewallGroup `json:"groups"`
	Rules  []storage.FirewallRule  `json:"rules"`
}

// newConnectionsOnly diz se esta janela deixou valendo um grupo de escopo
// input restrito a "só conexões novas" — isto é, se o teste de acesso dos 90
// segundos MENTE para esta mudança (spec §5).
//
// A pergunta não é "existe algum grupo assim na máquina", e a diferença é o
// que separa o aviso de virar ruído: um grupo restrito que já estava lá e que
// esta mudança não tocou não muda nada para quem está testando agora, e um
// aviso que aparece em toda janela é um aviso que ninguém lê. A pergunta é
// "algum grupo restrito de input passou a valer, ou passou a valer DIFERENTE,
// por causa desta mudança" — o que se responde comparando o estado de agora
// com o snapshot que a própria janela guarda.
//
// Ela olha só para o lado de AGORA, e por isso SOLTAR a restrição (new → any)
// não liga o aviso: ali o grupo volta a derrubar o que já está de pé, a sessão
// do operador cai junto se for atingida, e o teste dos 90 segundos volta a ser
// verdade. Avisar seria dizer "a sua sessão atual não é afetada" para uma
// mudança que a afeta — o erro na direção perigosa.
//
// Erro de leitura devolve TRUE, e não false: sem saber, o mínimo honesto é
// mandar o operador testar com uma conexão nova. O custo disso é ele abrir um
// segundo SSH à toa; o custo do contrário é ele confirmar um bloqueio que a
// sessão aberta escondeu.
func (h *NftablesHandler) newConnectionsOnly(snapshot string) bool {
	only, err := h.newConnectionsOnlyOrError(snapshot)
	if err != nil {
		slog.Error("não foi possível decidir se esta janela é de um grupo restrito a conexões novas; a faixa vai avisar por precaução", "err", err)
		return true
	}
	return only
}

func (h *NftablesHandler) newConnectionsOnlyOrError(snapshot string) (bool, error) {
	var before windowSnapshot
	if err := json.Unmarshal([]byte(snapshot), &before); err != nil {
		return false, fmt.Errorf("snapshot da janela ilegível: %w", err)
	}
	groups, err := h.db.ListFirewallGroups()
	if err != nil {
		return false, fmt.Errorf("ler os grupos: %w", err)
	}
	rules, err := h.db.ListFirewallRules()
	if err != nil {
		return false, fmt.Errorf("ler as regras: %w", err)
	}
	was := newOnlyInputSignatures(before.Groups, before.Rules)
	for id, sig := range newOnlyInputSignatures(groups, rules) {
		if was[id] != sig {
			return true, nil
		}
	}
	return false, nil
}

// newOnlyInputSignatures resume, por grupo, TUDO o que decide o que um grupo
// de escopo input restrito a `ct state new` corta: a linha de jump dele
// (posição na chain, condição de entrada, escopo, a escolha de conexões e o
// que ele faz com o que sobrar) e as regras de dentro dele, na ordem.
//
// As regras entram porque elas são metade da resposta: acrescentar um
// `drop tcp dport 9997` DENTRO de um grupo restrito que já existia é o caso
// mais perigoso desta feature — a linha do grupo não muda uma vírgula, o
// painel passa a ser bloqueado para conexões novas, e a sessão do operador
// continua de pé mentindo que está tudo bem.
//
// Ficam de fora, de propósito: nome, descrição e carimbos de tempo. Renomear
// um grupo não muda uma linha do firewall, e UpdatedAt muda em toda edição —
// os dois diriam "mudou" onde nada mudou para quem está testando o acesso.
//
// Grupo desligado não entra: ele não põe linha nenhuma na chain, então não
// corta nada. É também o que faz DESLIGAR um grupo restrito não ligar o aviso.
func newOnlyInputSignatures(groups []storage.FirewallGroup, rules []storage.FirewallRule) map[string]string {
	byGroup := make(map[string][]storage.FirewallRule, len(groups))
	for _, r := range rules {
		byGroup[r.GroupID] = append(byGroup[r.GroupID], r)
	}
	out := make(map[string]string, len(groups))
	for _, g := range groups {
		if !g.Enabled || !groupReachesInput(g) {
			continue
		}
		if nftables.GroupConnState(firewallrules.ToStoredGroup(g)) != nftables.ConnStateNew {
			continue
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%d|%s|%s|%s|%s|%s|%s",
			g.Position, g.Scope, g.ConnState, g.CondIif, g.CondSaddr, g.CondDaddr, g.Fallthrough)
		for _, r := range byGroup[g.ID] {
			fmt.Fprintf(&b, "\n%s|%t|%d|%s|%s|%s|%s|%s|%s|%s",
				r.ID, r.Enabled, r.Position, r.Action, r.Iif, r.Oif, r.Saddr, r.Daddr, r.Proto, r.Dport)
		}
		out[g.ID] = b.String()
	}
	return out
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
	writeJSON(w, http.StatusOK, pendingResponse{Pending: h.pendingView(p)})
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
	id, ok := h.windowIDFromBody(w, r)
	if !ok {
		return
	}
	p, err := h.fr.PendingChangeOrError()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if err := h.fr.ConfirmPending(r.Context(), id); err != nil {
		// A classificação sai do PRÓPRIO erro (firewallrules.IsWindowConflict),
		// nunca do `p` lido lá em cima: entre a leitura e a chamada o estado
		// pode ter mudado, e o caso em que isso acontece é o que mais dói — o
		// operador aperta "Confirmar" um segundo depois do prazo, o watchdog já
		// reverteu, e ConfirmPending tem a mensagem certa para ele ("tarde
		// demais: a mudança %q foi revertida automaticamente porque..."). Com a
		// classificação pelo estado obsoleto, aquilo virava "erro interno do
		// servidor" e o operador não ficava sabendo que a mudança tinha sido
		// desfeita, no minuto em que essa é a informação que mais importa.
		if firewallrules.IsWindowConflict(err) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeInternalError(w, err)
		return
	}
	// A auditoria registra a janela que foi CONFIRMADA — o id que o cliente
	// mandou —, e o resumo só quando ele descreve essa mesma janela. `p` foi
	// lido antes da chamada e pode já ser outro pendente (ou nenhum): usá-lo
	// sem conferir registrava, no caso que mais dói, o resumo de uma mudança
	// diferente da que acabou de passar a valer para sempre.
	summary := ""
	if p != nil && p.ID == id {
		summary = p.Summary
	}
	auditAction(h.db, r, "nft.pending.confirm", "pending:"+id, summary)
	writeJSON(w, http.StatusOK, okResult(nil))
}

// windowIDFromBody lê o id da janela que o cliente está resolvendo. Ele é
// OBRIGATÓRIO em confirmar e em reverter, e é a única forma de as duas saídas
// agirem sobre a janela que o operador viu na tela em vez de sobre a que
// estiver aberta no instante da chamada.
//
// Sem ele, num painel multi-admin: A aplica uma mudança de escopo input, B
// confirma a janela de A achando que confirma a dele, e a rede de proteção de
// uma alteração que B nunca viu é cancelada. O id sai da mesma faixa que
// mostra a contagem regressiva (GET /api/nftables/pending), então o painel
// sempre o tem; um cliente de linha de comando faz o GET antes.
func (h *NftablesHandler) windowIDFromBody(w http.ResponseWriter, r *http.Request) (string, bool) {
	var b struct {
		ID string `json:"id"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return "", false
	}
	id := strings.TrimSpace(b.ID)
	if id == "" {
		writeError(w, http.StatusBadRequest,
			"informe o id da mudança pendente (o mesmo que a faixa do painel mostra, em GET /api/nftables/pending): sem ele esta ação agiria sobre a janela que estiver aberta, e não sobre a que você viu")
		return "", false
	}
	return id, true
}

// RevertPendingChange (POST /api/nftables/pending/revert) é o "Reverter agora":
// desfaz a mudança sem esperar os 90 segundos acabarem.
//
// A reversão que não conclui NÃO é um caminho perdido: o pendente fica no
// banco e o watchdog retoma sozinho (ver firewallrules.revert). É isso que a
// mensagem de erro diz — o operador precisa saber que ainda há alguém tentando
// devolver o acesso dele, e não que a reversão fracassou e acabou.
func (h *NftablesHandler) RevertPendingChange(w http.ResponseWriter, r *http.Request) {
	id, ok := h.windowIDFromBody(w, r)
	if !ok {
		return
	}
	p, err := h.fr.PendingChangeOrError()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if p == nil {
		writeError(w, http.StatusConflict, "não há mudança aguardando confirmação")
		return
	}
	if err := h.fr.RevertPending(r.Context(), id); err != nil {
		// Mesma simetria do handler de confirmar: a janela que fechou entre a
		// leitura e a chamada (o watchdog reverteu primeiro, ou outro admin
		// confirmou) é conflito de estado — 409 com a mensagem escrita para o
		// operador —, não 500 "erro interno do servidor" sobre algo que já
		// aconteceu do jeito que ele queria.
		if firewallrules.IsWindowConflict(err) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		slog.Error("a reversão pedida pelo operador não pôde ser concluída", "err", err, "resumo", p.Summary)
		writeError(w, http.StatusInternalServerError,
			"não foi possível concluir a reversão agora; a mudança continua pendente e o LinkGuard vai tentar de novo sozinho")
		return
	}
	auditAction(h.db, r, "nft.pending.revert", "pending:"+id, p.Summary)
	saveNftSnapshot(r.Context(), h.db, h.svc)
	writeJSON(w, http.StatusOK, okResult(nil))
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
	return nftables.GroupHostChain(firewallrules.ToStoredGroup(g)) == nftables.InputChain
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

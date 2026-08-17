package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// NftablesHandler exposes the native nftables ruleset and its backups. This
// replaces the legacy iptables handler — the firewall is managed via nft now.
type NftablesHandler struct {
	svc *nftables.Service
	db  *storage.DB
	fr  *firewallrules.Service
}

// NewNftablesHandler creates an NftablesHandler.
func NewNftablesHandler(svc *nftables.Service, db *storage.DB, fr *firewallrules.Service) *NftablesHandler {
	return &NftablesHandler{svc: svc, db: db, fr: fr}
}

// confirmWindowBlocks é a TRAVA do confirmar-ou-reverte (Fase C2, spec §5.3):
// devolve true — e já respondeu ao cliente — quando a mutação que está
// começando não pode acontecer porque há uma janela de confirmação em aberto.
//
// Por que travar: uma janela aberta significa que uma mudança está APLICADA e
// ainda não se provou boa, com o estado anterior guardado para voltar. Aceitar
// uma segunda mutação em cima dela faz "reverter ao estado anterior" perder a
// resposta — anterior a qual das duas? —, e o pendente é um só (a tabela aceita
// uma linha). O operador ficaria empilhando alteração arriscada sobre alteração
// que ainda não se provou boa, que é exatamente o que os 90 segundos existem
// para impedir.
//
// ONDE ela é chamada em toda mutação de grupo e de regra: depois da validação
// dos campos e antes de qualquer acesso ao banco. As duas metades da posição
// têm motivo:
//
//   - depois da validação porque ela mesma precisa LER o banco, e um corpo
//     inválido com o banco fora do ar tem que continuar respondendo 400 com o
//     que está errado nele (C-5), não 500 por causa do SELECT do pendente;
//   - antes de qualquer leitura ou escrita porque uma mutação recusada não
//     pode ter tocado em nada — nem no banco, nem no nft.
//
// O que ela NÃO é: a serialização. Ler o pendente aqui e armar a janela lá na
// frente são dois momentos distintos, e duas requisições simultâneas passam as
// duas por esta leitura. Quem serializa de verdade é o ARME (openConfirmWindow
// → OpenConfirmWindow, sob mutex e com a tabela de uma linha só), que devolve
// 409 à segunda antes de ela escrever qualquer coisa. Esta função existe para
// dar a recusa CEDO e com a mensagem completa — a mudança pendente, quem a
// aplicou —, e para cobrir a mutação que não abre janela nenhuma e por isso
// nunca chegaria ao arme.
//
// Erro de leitura do pendente TRAVA a mutação (fail closed) e vira 500. As
// duas metades importam: liberar a mutação por não conseguir ler o pendente
// seria a trava falhando justamente na hora em que ela existe para agir (é a
// mesma armadilha que fez firewallrules.PendingChangeOrError não ter a forma
// que engolia o erro), e devolver 400 com o texto cru do banco seria culpar o
// cliente por uma pane do servidor e vazar o erro interno para a tela.
//
// O que ela NÃO trava, e não pode travar: confirmar e reverter. São as duas
// saídas da janela, e uma trava larga demais prenderia o operador dentro dela
// — o oposto do objetivo. Também não trava o que não mexe em grupo nem em
// regra (bloqueios por host, port forwards, toggle de NTP): a spec §5.3 fala
// de mutação de grupo e de regra, e nenhuma dessas outras muda o que o
// snapshot da janela guarda, então nenhuma delas torna a reversão ambígua.
func (h *NftablesHandler) confirmWindowBlocks(w http.ResponseWriter, _ *http.Request) bool {
	p, err := h.fr.PendingChangeOrError()
	if err != nil {
		writeInternalError(w, err)
		return true
	}
	if p == nil {
		return false
	}
	if p.Reverting() {
		// Estado "revertendo": a reversão já restaurou o estado anterior no
		// BANCO e o que falta é o firewall vivo aceitar.
		//
		// Aqui a trava LIBERA, e essa é a diferença entre um mecanismo de
		// segurança e um beco sem saída (N-2). O banco é a verdade deste
		// produto e o nftables é o resultado renderizado, reconstruído a cada
		// boot: se o banco já está no estado anterior, o trabalho da reversão
		// terminou na camada que manda, e toda mutação seguinte TAMBÉM
		// reconcilia — ela é parte da solução, não um risco. Travando, uma
		// máquina cuja reconciliação falha (uma regra que o `nft -c` aprova e o
		// apply recusa) prendia o operador sem saída nenhuma: não dava para
		// apagar a regra que quebra o reconcile, nem desligar o grupo, nem
		// confirmar (recusado), nem reverter (falha pelo mesmo motivo), e o
		// reboot repetia tudo. A única saída era sqlite3 na máquina.
		//
		// Quem prova que a reversão terminou no banco é RevertSettled, e é ele
		// que compara linha por linha — a marca de "revertendo" sozinha não
		// basta como prova.
		settled, err := h.fr.RevertSettled(p)
		if err != nil {
			// Não deu para PROVAR que a reversão terminou: fail closed, como o
			// erro de leitura acima e pelo mesmo motivo.
			writeInternalError(w, err)
			return true
		}
		if settled {
			return false
		}
		writeError(w, http.StatusConflict, fmt.Sprintf(
			"a reversão da mudança %q está em andamento e o estado anterior ainda não voltou por completo ao banco; espere ela concluir antes de alterar grupos ou regras",
			p.Summary))
		return true
	}
	writeError(w, http.StatusConflict, fmt.Sprintf(
		"há uma mudança de firewall aguardando confirmação (%q, aplicada por %s): confirme ou reverta antes de aplicar outra",
		p.Summary, p.AppliedBy))
	return true
}

// Ruleset returns the full live nftables ruleset.
func (h *NftablesHandler) Ruleset(w http.ResponseWriter, r *http.Request) {
	rs, err := h.svc.Ruleset(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ruleset": rs})
}

// Overview returns every chain of `table inet linkguard` and its rules —
// handle, raw expression, counters (when present), and origin
// classification (managed vs. the admin's own, plus which control owns a
// managed rule) — the structured view behind the unified Firewall overview
// page (design spec §3). Read-only.
//
// As chains dos grupos ganham um passo a mais do que a simples leitura do
// nft (Fase C1, design spec §4.1): uma regra desativada mora só no banco,
// nunca no nft, então um ListRuleset puro a omitiria em silêncio.
// MergeGroups intercala a lista completa do banco (na ordem de posição) com
// a chain viva de cada grupo, e a regra desativada continua aparecendo — sem
// handle, sem contador, honestamente marcada, nunca escondida ("mostrar
// tudo, mentir sobre nada").
//
// I-3: até esta tarefa esse passo só existia para a chain user_rules
// (MergeUserRules). A migração da Fase C1 apagou a user_rules e levou as
// regras para dentro dos grupos: o merge deixou de rodar em qualquer chain,
// e as regras desativadas simplesmente sumiram da única tela que mostra o
// firewall inteiro — enquanto as chains grp_ apareciam cruas.
func (h *NftablesHandler) Overview(w http.ResponseWriter, r *http.Request) {
	chains, err := h.svc.ListRuleset(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if chains == nil {
		chains = []nftables.ChainInfo{}
	}

	groups, err := h.fr.StoredGroups()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	byName, forward := indexChains(chains)
	merged := make(map[string]nftables.ChainInfo, len(groups))
	for _, v := range nftables.MergeGroups(groups, byName, forward) {
		merged[v.ChainName] = v.Rules
	}
	for i := range chains {
		if m, ok := merged[chains[i].Name]; ok {
			chains[i] = m
		}
	}

	// Nomeia, na descrição de cada jump para um grupo, o nome que o admin deu
	// a ele — ApplyGroupNames é a única coisa aqui que sabe de grupos;
	// ListRuleset/MergeGroups acima não precisam (nem devem) saber.
	groupNames := make(map[string]string, len(groups))
	for _, g := range groups {
		groupNames[g.ChainName] = g.Name
	}
	nftables.ApplyGroupNames(chains, groupNames)

	writeJSON(w, http.StatusOK, chains)
}

// indexChains prepara o que MergeGroups precisa do ruleset vivo: cada chain
// por nome, e a forward em separado (é nela que mora o jump que prova que um
// grupo está mesmo valendo). Uma forward ausente vira a chain vazia — ou
// seja, "nenhum grupo aplicado" —, jamais um erro que esconderia a lista
// inteira do admin: sem forward realmente não há grupo em vigor.
func indexChains(chains []nftables.ChainInfo) (map[string]nftables.ChainInfo, nftables.ChainInfo) {
	byName := make(map[string]nftables.ChainInfo, len(chains))
	forward := nftables.ChainInfo{Name: nftables.ForwardChain, Rules: []nftables.ChainRule{}}
	for _, c := range chains {
		byName[c.Name] = c
		if c.Name == nftables.ForwardChain {
			forward = c
		}
	}
	return byName, forward
}

// Managed returns the editable element-level view (host_wan map + sets).
func (h *NftablesHandler) Managed(w http.ResponseWriter, r *http.Request) {
	m, err := h.svc.Managed(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

// WanHost adds (POST) or removes (DELETE) a host IP in the host_wan map.
func (h *NftablesHandler) WanHost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP   string `json:"ip"`
		Mark string `json:"mark"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ip := strings.TrimSpace(body.IP)
	if net.ParseIP(ip) == nil {
		writeError(w, http.StatusBadRequest, "invalid IP address")
		return
	}
	var err error
	if r.Method == http.MethodDelete {
		_, err = h.svc.DelWanHost(r.Context(), ip)
		auditAction(h.db, r, "nft.wan-host.del", "host_wan:"+ip, "")
	} else {
		_, err = h.svc.AddWanHost(r.Context(), ip, strings.TrimSpace(body.Mark))
		auditAction(h.db, r, "nft.wan-host.add", "host_wan:"+ip, body.Mark)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	saveNftSnapshot(r.Context(), h.db, h.svc)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Blocklist adds (POST) or removes (DELETE) a destination CIDR/IP in the set.
func (h *NftablesHandler) Blocklist(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CIDR string `json:"cidr"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	cidr := strings.TrimSpace(body.CIDR)
	if !validCIDRorIP(cidr) {
		writeError(w, http.StatusBadRequest, "invalid CIDR or IP")
		return
	}
	var err error
	if r.Method == http.MethodDelete {
		_, err = h.svc.DelBlocklist(r.Context(), cidr)
		auditAction(h.db, r, "nft.blocklist.del", cidr, "")
	} else {
		_, err = h.svc.AddBlocklist(r.Context(), cidr)
		auditAction(h.db, r, "nft.blocklist.add", cidr, "")
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	saveNftSnapshot(r.Context(), h.db, h.svc)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ─── The admin's own rules (Phase B, design spec §4.1) ───────────────────
//
// These rules live in the DB now, identified by a stable id — not nft's
// handle, which changes every time the chain is rebuilt. Every mutation
// below writes the DB first, then calls reconcile() so the live user_rules
// chain is re-rendered immediately: the panel must never show a state the
// firewall isn't actually in.

// maxRuleDescriptionLen bounds the free-text "why this rule exists" field —
// generous enough for a real explanation, small enough that a request body
// can't be used to stuff an unbounded blob into the DB on every save.
const maxRuleDescriptionLen = 500

// firewallRulesResponse wraps the admin's rules with the persisted outcome
// of the most recent user_rules reconcile (C-3, design spec §4.1) — apply
// failures happen on the boot path too, invisible to any HTTP status code,
// so ApplyStatus is loaded from the same setting firewallrules.Service.
// Reconcile writes after every call, handler-triggered or not (see
// firewallrules.Service.ApplyStatus's doc comment). ApplyStatus is nil,
// never a synthetic "ok", when Reconcile has never run at all — "unknown"
// must never be presented as "known good".
type firewallRulesResponse struct {
	Rules       []storage.FirewallRule     `json:"rules"`
	ApplyStatus *firewallrules.ApplyStatus `json:"apply_status,omitempty"`
}

// ListRules returns the admin's rules, ordered by position, together with
// the last reconcile's apply status — the one signal that tells the admin
// whether what's configured is actually what's in effect (FEATURES.md's
// delivery rule).
func (h *NftablesHandler) ListRules(w http.ResponseWriter, r *http.Request) {
	rules, err := h.db.ListFirewallRules()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if rules == nil {
		rules = []storage.FirewallRule{}
	}
	writeJSON(w, http.StatusOK, firewallRulesResponse{
		Rules:       rules,
		ApplyStatus: h.fr.LastApplyStatus(),
	})
}

type firewallRuleBody struct {
	ID          string `json:"id"`
	GroupID     string `json:"group_id"`
	Action      string `json:"action"`
	Iif         string `json:"iif"`
	Oif         string `json:"oif"`
	Saddr       string `json:"saddr"`
	Daddr       string `json:"daddr"`
	Proto       string `json:"proto"`
	Dport       string `json:"dport"`
	Description string `json:"description"`
}

func (b firewallRuleBody) fields() nftables.RuleFields {
	return nftables.RuleFields{
		Action: strings.TrimSpace(b.Action), Iif: strings.TrimSpace(b.Iif), Oif: strings.TrimSpace(b.Oif),
		Saddr: strings.TrimSpace(b.Saddr), Daddr: strings.TrimSpace(b.Daddr),
		Proto: strings.TrimSpace(b.Proto), Dport: strings.TrimSpace(b.Dport),
	}
}

// validateFirewallRuleBody reuses nftables.ValidateRuleFields — the exact
// check ReconcileUserRules/AddUserRule already apply before a field reaches
// the nft argv — instead of the old handler-local check that only looked at
// saddr/daddr and let a malformed interface or port through to be rejected
// later (or worse, silently dropped by the reconcile's own skip-and-log).
func validateFirewallRuleBody(b firewallRuleBody) string {
	if err := nftables.ValidateRuleFields(b.fields()); err != nil {
		return err.Error()
	}
	if len(b.Description) > maxRuleDescriptionLen {
		return fmt.Sprintf("descrição muito longa (máx. %d caracteres)", maxRuleDescriptionLen)
	}
	return ""
}

// checkPendingRules is C-1's second layer: before any DB write, it asks nft
// itself (via a parse-only `nft -c` dry run) whether the firewall that would
// result from this mutation is actually acceptable. mutate receives the
// admin's current rules and returns the candidate set the DB would hold
// right after the in-progress change, without touching anything.
// Field-level validation (validateFirewallRuleBody/ValidateRuleFields)
// already catches most bad input, but not everything nft itself would
// reject — this is the same mechanism the design spec picks for Phase C's
// own pre-flight, so nft's rejection reaches the admin as a 400 with nft's
// own message, before the DB (and the live chain) ever changes.
//
// Fase C1 — o que se valida aqui são os GRUPOS (CheckPendingGroups), não
// mais a chain user_rules (CheckPending). Não é preferência de estilo: a
// migração desta fase apagou a user_rules do ruleset, e o script que
// CheckUserRules monta começa por `flush chain inet linkguard user_rules`.
// Verificado ao vivo no nft (Debian 13), dentro de `nft -c -f` um flush de
// chain inexistente falha com "No such file or directory" — ou seja, todo
// POST/PUT de regra e todo "reativar" passaria a devolver 400 com a
// mensagem crua do nft, enquanto apagar e reordenar continuariam
// funcionando. CheckGroups valida as chains dos grupos (precedidas do `add
// chain` que salva o grupo ainda não gravado) e a forward, que é
// exatamente o que Reconcile renderiza logo depois.
func (h *NftablesHandler) checkPendingRules(w http.ResponseWriter, r *http.Request, mutate func([]storage.FirewallRule) []storage.FirewallRule) bool {
	current, err := h.db.ListFirewallRules()
	if err != nil {
		writeInternalError(w, err)
		return false
	}
	candidate, err := h.fr.StoredGroupsWithRules(mutate(current))
	if err != nil {
		writeInternalError(w, err)
		return false
	}
	if err := h.fr.CheckPendingGroups(r.Context(), candidate); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return false
	}
	return true
}

// findRule devolve a linha da regra pelo id, ou 400 se ela não existe — o
// mesmo status que UpdateFirewallRule já devolvia para um id que não bate
// com nada, só que antes de qualquer escrita.
func (h *NftablesHandler) findRule(w http.ResponseWriter, id string) (storage.FirewallRule, bool) {
	rules, err := h.db.ListFirewallRules()
	if err != nil {
		writeInternalError(w, err)
		return storage.FirewallRule{}, false
	}
	for _, row := range rules {
		if row.ID == id {
			return row, true
		}
	}
	writeError(w, http.StatusBadRequest, fmt.Sprintf("regra %q não encontrada", id))
	return storage.FirewallRule{}, false
}

// requireGroup resolves the group a rule is being written into, rejecting
// anything that doesn't name an existing one. Since Phase C1 a rule only
// exists in the firewall inside a group's chain: a row with a group_id that
// matches nothing is dropped by the reconcile with a slog.Warn (see
// firewallrules.StoredGroupsWithRules) — it stays on screen and is absent
// from nft, which is precisely the false confidence this panel exists to
// eliminate. Refusing it here, before the write, is the only place that can
// still tell the admin.
//
// Um grupo do sistema é recusado pela mesma razão, e o estrago é ainda mais
// calado: o conteúdo dele é o named set, não uma chain de regras do admin.
// CheckGroups pula grupo de sistema, ReconcileGroups pula nos passos 1 e 2 e
// MergeGroups devolve Rules vazio para ele — cada camada certa isoladamente,
// e o efeito somado é que o pré-voo `nft -c` ACEITA, o reconcile devolve nil
// (a tela mostra apply "ok") e nenhum comando emitido contém a regra. Ela
// fica no banco, ausente do nft e invisível em toda tela. No PUT é pior: uma
// regra que estava valendo desaparece do firewall com HTTP 200.
func (h *NftablesHandler) requireGroup(w http.ResponseWriter, groupID string) bool {
	id := strings.TrimSpace(groupID)
	if id == "" {
		writeError(w, http.StatusBadRequest, "a regra precisa pertencer a um grupo (group_id)")
		return false
	}
	groups, err := h.db.ListFirewallGroups()
	if err != nil {
		writeInternalError(w, err)
		return false
	}
	for _, g := range groups {
		if g.ID != id {
			continue
		}
		if nftables.IsSystemGroup(g.Kind) {
			writeError(w, http.StatusBadRequest, fmt.Sprintf(
				"%q é um grupo do sistema: o conteúdo dele são os endereços bloqueados, não regras — uma regra colocada aqui nunca chegaria ao firewall. Escolha um grupo seu.",
				g.Name))
			return false
		}
		return true
	}
	writeError(w, http.StatusBadRequest, fmt.Sprintf("grupo %q não encontrado", id))
	return false
}

// CreateRule adds a new rule, always appended after every existing one.
func (h *NftablesHandler) CreateRule(w http.ResponseWriter, r *http.Request) {
	var b firewallRuleBody
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if msg := validateFirewallRuleBody(b); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if !h.requireGroup(w, b.GroupID) {
		return
	}
	groupID := strings.TrimSpace(b.GroupID)
	f := b.fields()
	row := &storage.FirewallRule{
		GroupID: groupID,
		Action:  f.Action, Iif: f.Iif, Oif: f.Oif,
		Saddr: f.Saddr, Daddr: f.Daddr, Proto: f.Proto, Dport: f.Dport,
		Description: strings.TrimSpace(b.Description),
	}
	// C-1 layer 2: validate the resulting chain with nft itself before
	// anything is written — CreateFirewallRule always appends, so the
	// candidate is simply every current rule plus this new one, enabled.
	candidateRow := storage.FirewallRule{Enabled: true, GroupID: groupID,
		Action: f.Action, Iif: f.Iif, Oif: f.Oif,
		Saddr: f.Saddr, Daddr: f.Daddr, Proto: f.Proto, Dport: f.Dport}
	// Uma regra dentro de um grupo de escopo input é escrita na chain que
	// decide sobre o SSH e o painel desta máquina: é ela que exige a rede de
	// proteção dos 90 segundos (Fase C2, spec §5). A resposta é resolvida no
	// pré-voo — que pode falhar — e só LIDA no Window(), que não pode.
	var inGroup bool

	out, ok := h.applyGuarded(w, r, mutation{
		preflight: func(ctx context.Context) error {
			if err := h.preflightRules(ctx, func(current []storage.FirewallRule) []storage.FirewallRule {
				return append(append([]storage.FirewallRule{}, current...), candidateRow)
			}); err != nil {
				return err
			}
			var err error
			inGroup, err = h.groupsReachInput(groupID)
			return err
		},
		window: func() (bool, string) {
			return inGroup, "criação de uma regra em grupo de escopo input"
		},
		write: func() error { return h.db.CreateFirewallRule(row) },
		// I-2: audita a mutação do BANCO, não só um apply bem-sucedido — uma
		// reconciliação que falhe depois ainda precisa deixar rastro do que
		// foi escrito.
		audit: func() (string, string, string) {
			return "nft.rule.add", "user_rules:" + row.ID, b.Action
		},
	})
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, createdRuleResult{FirewallRule: row, Pending: h.pendingViewOf(out)})
}

// UpdateRule edits a rule's content in place, by id — its position and
// enabled state are untouched (see ReorderRules/ToggleRule for those).
func (h *NftablesHandler) UpdateRule(w http.ResponseWriter, r *http.Request) {
	var b firewallRuleBody
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(b.ID) == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}
	if msg := validateFirewallRuleBody(b); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	// C-2: UpdateFirewallRule escreve `SET group_id=?`, então montar a linha
	// sem GroupID ZERAVA o grupo da regra a cada edição pelo painel — a
	// reconciliação a descartava com um slog.Warn (regra órfã não tem chain
	// onde ser renderizada), ela sumia do firewall e continuava na tela.
	// Perda silenciosa, sem undo. O grupo é o da linha existente; o corpo só
	// pode trocá-lo por outro que exista de verdade (é assim que o painel
	// move uma regra de grupo).
	// Trava do confirmar-ou-reverte, depois da validação dos campos e antes
	// de tocar no banco — ver confirmWindowBlocks (spec §5.3).
	if h.confirmWindowBlocks(w, r) {
		return
	}
	existing, found := h.findRule(w, b.ID)
	if !found {
		return
	}
	groupID := existing.GroupID
	if id := strings.TrimSpace(b.GroupID); id != "" && id != groupID {
		if !h.requireGroup(w, id) {
			return
		}
		groupID = id
	}
	f := b.fields()
	row := &storage.FirewallRule{
		ID: b.ID, GroupID: groupID, Action: f.Action, Iif: f.Iif, Oif: f.Oif,
		Saddr: f.Saddr, Daddr: f.Daddr, Proto: f.Proto, Dport: f.Dport,
		Description: strings.TrimSpace(b.Description),
	}
	// C-1 layer 2: candidate = current rules with this one's fields
	// replaced in place (position/enabled untouched, same as the DB write
	// UpdateFirewallRule itself performs).
	ok := h.checkPendingRules(w, r, func(current []storage.FirewallRule) []storage.FirewallRule {
		out := make([]storage.FirewallRule, len(current))
		for i, c := range current {
			if c.ID == b.ID {
				c.GroupID = groupID
				c.Action, c.Iif, c.Oif = f.Action, f.Iif, f.Oif
				c.Saddr, c.Daddr, c.Proto, c.Dport = f.Saddr, f.Daddr, f.Proto, f.Dport
			}
			out[i] = c
		}
		return out
	})
	if !ok {
		return
	}
	// Os dois grupos contam: o de onde a regra sai e o para onde ela vai. Mover
	// uma regra PARA um grupo de input é ganhar poder sobre o acesso ao
	// firewall; tirá-la de lá muda a chain input do mesmo jeito.
	inGroup, ok := h.anyGroupReachesInput(w, existing.GroupID, groupID)
	if !ok {
		return
	}
	win, ok := h.openConfirmWindow(w, r, inGroup, "edição de uma regra em grupo de escopo input")
	if !ok {
		return
	}
	// Erro de banco é 500: o id já foi resolvido por findRule e os campos já
	// passaram por ValidateRuleFields, então o que sobra é pane do servidor — e
	// o 400 com o texto cru levava a mensagem interna do SQLite para a tela.
	if err := h.db.UpdateFirewallRule(row); err != nil {
		h.discardArmedWindow(w, r, win, err)
		return
	}
	auditAction(h.db, r, "nft.rule.update", "user_rules:"+b.ID, b.Action)
	if !h.reconcileArmed(w, r, win) {
		return
	}
	writeJSON(w, http.StatusOK, okResult(win.view))
}

// DeleteRule removes a rule permanently, by id.
func (h *NftablesHandler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID string `json:"id"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(b.ID) == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}
	// Trava do confirmar-ou-reverte, depois da validação dos campos e antes
	// de tocar no banco — ver confirmWindowBlocks (spec §5.3).
	if h.confirmWindowBlocks(w, r) {
		return
	}
	// A linha é resolvida ANTES de ser apagada porque é ela que diz em qual
	// grupo a regra mora — depois do DELETE não há mais como saber se o que
	// acabou de sair do firewall era da chain input. Id inexistente continua
	// sendo 400, como o DELETE do storage já respondia.
	existing, found := h.findRule(w, b.ID)
	if !found {
		return
	}
	inGroup, ok := h.anyGroupReachesInput(w, existing.GroupID)
	if !ok {
		return
	}
	win, ok := h.openConfirmWindow(w, r, inGroup, "remoção de uma regra em grupo de escopo input")
	if !ok {
		return
	}
	// Id inexistente já morreu em findRule; o que chega aqui é pane do banco,
	// que é 500 e não 400 com o texto cru dele.
	if err := h.db.DeleteFirewallRule(b.ID); err != nil {
		h.discardArmedWindow(w, r, win, err)
		return
	}
	auditAction(h.db, r, "nft.rule.del", "user_rules:"+b.ID, "")
	if !h.reconcileArmed(w, r, win) {
		return
	}
	writeJSON(w, http.StatusOK, okResult(win.view))
}

// ToggleRule enables or disables a rule without deleting it — the
// appliance-style capability the whole DB-backed model exists for (design
// spec §4.1). A disabled rule keeps every field intact; it simply stops
// being rendered into nft until re-enabled.
func (h *NftablesHandler) ToggleRule(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(b.ID) == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}
	// Trava do confirmar-ou-reverte, depois da validação dos campos e antes
	// de tocar no banco — ver confirmWindowBlocks (spec §5.3).
	if h.confirmWindowBlocks(w, r) {
		return
	}
	// Mesma resolução do DeleteRule, e pela mesma razão: só a linha existente
	// diz em qual grupo a regra mora. Vem ANTES do pré-voo porque um id que não
	// existe não merece um dry run inteiro de `nft -c` para ser recusado.
	existing, found := h.findRule(w, b.ID)
	if !found {
		return
	}
	// C-1 layer 2: re-enabling a rule can newly introduce it into the
	// rendered chain (a disabled rule is never checked while disabled — see
	// ValidateRuleFields at create/update time, which normally already
	// caught anything invalid, but a stale or hand-edited row must not
	// reach nft unchecked). Disabling never needs a check: removing a rule
	// from the chain cannot make nft reject it.
	if b.Enabled {
		ok := h.checkPendingRules(w, r, func(current []storage.FirewallRule) []storage.FirewallRule {
			out := make([]storage.FirewallRule, len(current))
			for i, c := range current {
				if c.ID == b.ID {
					c.Enabled = true
				}
				out[i] = c
			}
			return out
		})
		if !ok {
			return
		}
	}
	inGroup, ok := h.anyGroupReachesInput(w, existing.GroupID)
	if !ok {
		return
	}
	summary := "desativação de uma regra em grupo de escopo input"
	if b.Enabled {
		summary = "ativação de uma regra em grupo de escopo input"
	}
	win, ok := h.openConfirmWindow(w, r, inGroup, summary)
	if !ok {
		return
	}
	if err := h.db.SetFirewallRuleEnabled(b.ID, b.Enabled); err != nil {
		h.discardArmedWindow(w, r, win, err)
		return
	}
	action := "nft.rule.disable"
	if b.Enabled {
		action = "nft.rule.enable"
	}
	auditAction(h.db, r, action, "user_rules:"+b.ID, "")
	if !h.reconcileArmed(w, r, win) {
		return
	}
	writeJSON(w, http.StatusOK, okResult(win.view))
}

// ReorderRules sets the evaluation order for every one of the admin's rules
// in a single request. ids must be exactly the current set of rule ids —
// neither more nor fewer: a partial list would silently strand the missing
// rules at their old positions (possibly colliding with the new ones), and
// an id LinkGuard doesn't recognise is rejected outright rather than
// ignored, so a stale client can never quietly corrupt the order.
func (h *NftablesHandler) ReorderRules(w http.ResponseWriter, r *http.Request) {
	var b struct {
		IDs []string `json:"ids"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// Trava do confirmar-ou-reverte, depois da validação dos campos e antes
	// de tocar no banco — ver confirmWindowBlocks (spec §5.3).
	if h.confirmWindowBlocks(w, r) {
		return
	}
	current, err := h.db.ListFirewallRules()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if len(b.IDs) != len(current) {
		writeError(w, http.StatusBadRequest, "a lista de reordenação precisa conter exatamente as regras atuais, sem faltar nem sobrar nenhuma")
		return
	}
	currentSet := make(map[string]bool, len(current))
	for _, row := range current {
		currentSet[row.ID] = true
	}
	seen := make(map[string]bool, len(b.IDs))
	for _, id := range b.IDs {
		if !currentSet[id] {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("regra %q não encontrada", id))
			return
		}
		if seen[id] {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("id %q repetido na lista de reordenação", id))
			return
		}
		seen[id] = true
	}
	// Reordenar regras muda quem decide primeiro dentro da chain do grupo — e,
	// num grupo de escopo input, quem decide primeiro sobre o SSH e o painel.
	// Mesmo critério largo de ReorderGroups: basta o índice de uma regra de
	// grupo input mudar.
	groups, err := h.db.ListFirewallGroups()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	inputGroup := make(map[string]bool, len(groups))
	for _, g := range groups {
		if groupReachesInput(g) {
			inputGroup[g.ID] = true
		}
	}
	currentIDs := make([]string, len(current))
	isInput := make(map[string]bool, len(current))
	for i, row := range current {
		currentIDs[i] = row.ID
		isInput[row.ID] = inputGroup[row.GroupID]
	}
	win, ok := h.openConfirmWindow(w, r, inputOrderChanged(currentIDs, b.IDs, isInput),
		"reordenação das regras (há regra em grupo de escopo input)")
	if !ok {
		return
	}
	if err := h.db.ReorderFirewallRules(b.IDs); err != nil {
		h.discardArmedWindow(w, r, win, err)
		return
	}
	auditAction(h.db, r, "nft.rule.reorder", "user_rules", fmt.Sprintf("%d regras", len(b.IDs)))
	if !h.reconcileArmed(w, r, win) {
		return
	}
	writeJSON(w, http.StatusOK, okResult(win.view))
}

func validCIDRorIP(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// Backup snapshots the current nftables ruleset into the database.
func (h *NftablesHandler) Backup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Label string `json:"label"`
	}
	_ = decodeJSON(r, &body)
	if body.Label == "" {
		body.Label = "nft-" + time.Now().Format("2006-01-02T15:04:05")
	}
	rs, err := h.svc.Save(r.Context())
	if err != nil {
		writeInternalError(w, fmt.Errorf("failed to read nft ruleset: %w", err))
		return
	}
	backup := &storage.IptablesBackup{Label: body.Label, Rules: rs}
	if err := h.db.CreateIptablesBackup(backup); err != nil {
		writeInternalError(w, fmt.Errorf("failed to store backup: %w", err))
		return
	}
	auditAction(h.db, r, "nft.backup", "ruleset", body.Label)
	writeJSON(w, http.StatusCreated, backup)
}

// ListBackups returns stored ruleset backups.
func (h *NftablesHandler) ListBackups(w http.ResponseWriter, r *http.Request) {
	backups, err := h.db.GetIptablesBackups(20)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if backups == nil {
		backups = []storage.IptablesBackup{}
	}
	writeJSON(w, http.StatusOK, backups)
}

// Rollback restores a stored ruleset snapshot via nft.
//
// Este é o endpoint de mutação que reescreve de uma vez toda a tabela
// `inet linkguard`, e é a operação que mais briga com uma reversão em
// andamento: um rollback disparado enquanto o watchdog tenta restaurar o estado
// anterior escreve por cima do que ele acabou de impor.
//
// M-3 da revisão final: por isso ele consulta confirmWindowBlocks, como toda
// mutação de grupo e regra. Ele continua não ABRINDO janela (não mexe em grupo
// nem em regra do banco, e o snapshot da janela não cobre o que ele restaura),
// mas recusá-lo enquanto uma janela corre custa ao operador esperar 90 segundos
// e evita que ele desfaça por baixo a rede de proteção de outra pessoa. O estado
// "revertendo" com o banco já restaurado LIBERA sozinho (RevertSettled), então
// isto não cria beco: a saída do operador cuja reconciliação não passa continua
// existindo.
//
// O `flush ruleset` que o Service.Restore emitia — a dívida conhecida deste
// projeto — deixou de existir: o restore agora é escopado à tabela
// `inet linkguard` (ver nftables.Service.Restore). Duas consequências para quem
// lê este handler:
//
//   - um snapshot que não contenha a nossa tabela é RECUSADO em vez de
//     restaurar o vazio (nftables.ErrNoLinkguardTable);
//   - o que o snapshot guardou de tabelas de terceiros continua guardado (o
//     backup é o dump inteiro do `nft list ruleset`) e não é mais aplicado. Isso
//     é intencional: reimpor a versão antiga da tabela do Docker é dano, não
//     restauração.
func (h *NftablesHandler) Rollback(w http.ResponseWriter, r *http.Request) {
	var body struct {
		BackupID string `json:"backup_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// Depois de ler o corpo e antes de qualquer acesso ao banco, exatamente como
	// nas dez mutações de grupo e regra (ver confirmWindowBlocks).
	if h.confirmWindowBlocks(w, r) {
		return
	}
	backups, err := h.db.GetIptablesBackups(100)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	var target *storage.IptablesBackup
	for i := range backups {
		if backups[i].ID == body.BackupID {
			target = &backups[i]
			break
		}
	}
	if target == nil {
		writeError(w, http.StatusNotFound, "backup not found")
		return
	}
	// A trava é lida DE NOVO aqui, imediatamente antes da escrita (issue #20a).
	//
	// A leitura lá de cima continua existindo (recusar antes de ler o banco é o
	// que ela faz de melhor), mas ela sozinha era o mesmo TOCTOU das dez
	// mutações: consultada no topo, com a escrita — um `nft -f` que reescreve a
	// tabela `inet linkguard` inteira — acontecendo bem depois. Uma janela
	// armada nesse intervalo era atropelada.
	//
	// Aqui a correção não pode ser a das dez mutações. Lá a reversão confere o
	// estado e desfaz só o delta da própria janela, porque o que a mutação
	// escreveu está no BANCO, em grupos e regras, que é o que o snapshot cobre.
	// O rollback não escreve linha nenhuma no banco: ele impõe um ruleset ao nft,
	// e o snapshot da janela não cobre nada disso (nem host_wan, nem os named
	// sets, nem os port forwards). Não há delta para preservar — o que protege a
	// janela alheia é recusar, e o preço é o operador esperar os 90 segundos.
	if h.confirmWindowBlocks(w, r) {
		return
	}
	out, err := h.svc.Restore(r.Context(), target.Rules)
	if err != nil {
		// Um snapshot sem a nossa tabela não é pane do servidor: é um snapshot
		// que não serve para este botão — gravado antes de a tabela existir, ou
		// vindo de um backup de outra máquina. O 500 genérico ("erro interno do
		// servidor") mandaria o operador procurar defeito no LinkGuard em vez de
		// escolher outro snapshot.
		if errors.Is(err, nftables.ErrNoLinkguardTable) {
			slog.Warn("rollback recusado: o snapshot escolhido não contém a tabela do LinkGuard", "snapshot", target.Label)
			writeError(w, http.StatusBadRequest, fmt.Sprintf(
				"o snapshot %q não contém a tabela `inet linkguard` e por isso não pode ser restaurado; nada foi alterado no firewall",
				target.Label))
			return
		}
		// Mesma família de recusa, e pela mesma razão de não ser 500: o snapshot
		// é que não serve, o LinkGuard está são. Aqui o que ele traz é uma chain
		// `input` com política restritiva — o LinkGuard nunca gera isso, então a
		// linha foi editada à mão ou veio de outra máquina. Aplicá-la trancaria o
		// operador para fora de um firewall que ele só alcança pela rede.
		if errors.Is(err, nftables.ErrInputPolicyNotAccept) {
			slog.Warn("rollback recusado: a chain input do snapshot tem política restritiva", "snapshot", target.Label, "err", err)
			writeError(w, http.StatusBadRequest, fmt.Sprintf(
				"o snapshot %q não pode ser restaurado: %s", target.Label, err.Error()))
			return
		}
		writeInternalError(w, fmt.Errorf("rollback failed: %w", err))
		return
	}
	auditAction(h.db, r, "nft.rollback", "ruleset", target.Label)
	// I-1: Restore writes the snapshot straight into nft via `nft -f`,
	// bypassing the DB-authoritative model entirely (design spec §4.1) — a
	// bare rollback would leave user_rules holding whatever the snapshot
	// happened to contain, disagreeing with the DB's own rule rows (their
	// stable ids no longer map to any live handle) until the *next*,
	// unrelated mutation silently re-renders over it. Reconciling here
	// makes the DB win immediately, exactly like every other mutation.
	//
	// What this means for the snapshot's own user_rules content: it is
	// discarded. A rollback restores every OTHER piece of live state the
	// snapshot captured (host_wan, blocklist, blocked_hosts,
	// prerouting_dnat, the structural chains) verbatim, but user_rules ends
	// up exactly what the DB says right now, not what was in the snapshot
	// at backup time — consistent with "the DB is the source of truth for
	// the admin's rules", but worth knowing before relying on a rollback to
	// also undo a rule change.
	//
	// E a falha desta reconciliação NÃO é mais um WARN com 200 na tela. Era: o
	// operador via "Ruleset restaurado.", e o firewall vivo tinha ficado sendo o
	// conteúdo do snapshot — as regras que o painel mostra, que moram no banco,
	// não tinham entrado. Um rollback que responde "pronto" e deixa o firewall
	// diferente do que a tela afirma é a mesma mentira que este projeto vem
	// eliminando (a mesma classe do Persist mudo, §10 da validação em VM).
	//
	// Por que 500 e não uma reversão automática, como em abortArmedWindow: aqui
	// não há estado anterior guardado para voltar (o rollback não abre janela, e
	// o snapshot da janela não cobre o que ele restaura). O que cabe é dizer com
	// precisão o que ficou valendo, para o operador decidir — restaurar outro
	// snapshot, corrigir o que impede a reconciliação, ou salvar qualquer
	// alteração de regra, que reconcilia de novo.
	if err := h.fr.Reconcile(r.Context()); err != nil {
		slog.Error("o rollback restaurou o snapshot, mas as regras do banco não puderam ser reaplicadas por cima dele",
			"err", err, "snapshot", target.Label)
		// O snapshot vivo é atualizado ANTES de responder mesmo neste caminho: o
		// firewall MUDOU, e a cópia que um bootstrap futuro restauraria tem que
		// descrever o que está valendo de verdade, não o estado anterior.
		saveNftSnapshot(r.Context(), h.db, h.svc)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf(
			"o snapshot %q foi restaurado no firewall, mas as regras do banco não puderam ser reaplicadas por cima dele: o que está valendo agora é o conteúdo do snapshot, que pode não corresponder ao que o painel mostra. Veja o motivo no journal e salve qualquer alteração de regra para reconciliar de novo.",
			target.Label))
		return
	}
	saveNftSnapshot(r.Context(), h.db, h.svc)
	writeJSON(w, http.StatusOK, map[string]interface{}{"message": "rollback completed", "output": out})
}

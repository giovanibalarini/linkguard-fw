package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/giovanibalarini/linkguard-fw/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// ─── Grupos de regras (Fase C1, design spec §2) ──────────────────────────
//
// Um grupo é uma chain própria no nft (grp_<hex>), alcançada a partir da
// forward por `<condição de entrada> counter jump grp_xxxx`. Ligar e
// desligar o grupo é pôr e tirar esse jump: a chain e as regras de dentro
// continuam guardadas.
//
// Toda mutação aqui segue a mesma ordem, herdada da Fase B e não
// negociável: validar os campos → perguntar ao próprio nft, com um dry run
// `nft -c` (CheckPendingGroups), se o firewall que resultaria disto é
// aceitável → ARMAR a janela de confirmação, quando a mudança envolve escopo
// input (openConfirmWindow) → só então gravar no banco → reconciliar →
// atualizar o snapshot. Nada chega ao banco antes de o nft aceitar, porque uma
// linha gravada que o nft recusa é o painel afirmando uma proteção que não
// existe.
//
// O arme vem ANTES da escrita, e não depois do reconcile (Fase C2, revisão):
// assim o snapshot é o estado anterior de verdade, uma segunda requisição
// simultânea é recusada antes de tocar no firewall, e qualquer passo seguinte
// que falhe cai na rede de proteção em vez de deixar uma regra de escopo input
// valendo sem reversão automática. Todo caminho de erro depois do arme desfaz
// a janela: discardArmedWindow quando a escrita no banco falhou (nada mudou em
// lugar nenhum, então basta apagar o pendente) e abortArmedWindow quando foi a
// reconciliação que falhou (a mudança pode estar pela metade no firewall vivo,
// e aí a reversão inteira é o que se quer).

// groupBody é o corpo aceito na criação e na edição de um grupo.
//
// Não existe campo de nome de chain, e isso é deliberado: o ChainName é
// derivado do id pelo SERVIDOR (nftables.GroupChainName) e vai inteiro para
// o argv do `nft`. Aceitá-lo do cliente seria injeção de comando — a mesma
// porta que reIface e ValidMark fecham nos geradores de internal/nftables.
// Um `chain_name` no corpo é silenciosamente ignorado por não existir aqui.
//
// Scope é o campo que a Fase C2 acrescenta, e é o que decide em qual chain o
// grupo é alcançado: "forward" (ou vazio, que é toda linha anterior à Fase C2)
// para tráfego ATRAVESSANDO o firewall, "input" para tráfego DESTINADO a ele —
// SSH, painel, DNS, Samba. Um valor que não seja um desses três é recusado por
// ValidateGroup: normalizá-lo para forward colocaria na chain de tráfego
// atravessando um grupo escrito para outra coisa.
//
// ConnState é o campo desta entrega, e decide PARA QUAIS CONEXÕES o grupo
// vale: "any" (ou vazio, que é toda linha anterior a ele) derruba na hora o
// que casar com a condição, "new" só alcança conexões NOVAS — a linha do jump
// ganha `ct state new` e a transferência que já estava correndo segue até
// terminar. Como o escopo, um valor fora dessa lista é recusado por
// ValidateGroup em vez de normalizado: um "established" gravado por um cliente
// confuso viraria "any" na renderização, e a tela diria uma coisa enquanto o
// firewall faz outra.
type groupBody struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	CondSaddr   string `json:"cond_saddr"`
	CondDaddr   string `json:"cond_daddr"`
	CondIif     string `json:"cond_iif"`
	Fallthrough string `json:"fallthrough"`
	Scope       string `json:"scope"`
	ConnState   string `json:"conn_state"`
}

func (b groupBody) trimmed() groupBody {
	return groupBody{
		ID:          strings.TrimSpace(b.ID),
		Name:        strings.TrimSpace(b.Name),
		CondSaddr:   strings.TrimSpace(b.CondSaddr),
		CondDaddr:   strings.TrimSpace(b.CondDaddr),
		CondIif:     strings.TrimSpace(b.CondIif),
		Fallthrough: strings.TrimSpace(b.Fallthrough),
		Scope:       strings.TrimSpace(b.Scope),
		ConnState:   strings.TrimSpace(b.ConnState),
	}
}

// groupsResponse é a listagem de grupos com o resultado da última
// reconciliação, exatamente como firewallRulesResponse faz para as regras:
// "configurado" e "em vigor" são coisas diferentes, e o painel precisa das
// duas para não afirmar uma proteção que o kernel não está fazendo.
type groupsResponse struct {
	Groups      []nftables.GroupView       `json:"groups"`
	ApplyStatus *firewallrules.ApplyStatus `json:"apply_status,omitempty"`
}

// ListGroups devolve todos os grupos do admin com a visão honesta de cada
// um: se o jump está mesmo na forward viva (Applied), o contador de quanto
// tráfego entrou ali, e as regras de dentro já pareadas com o firewall —
// inclusive as desativadas, que só existem no banco (nftables.MergeGroups).
func (h *NftablesHandler) ListGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := h.fr.StoredGroups()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	chains, err := h.svc.ListRuleset(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	byName, forward := indexChains(chains)
	writeJSON(w, http.StatusOK, groupsResponse{
		Groups:      nftables.MergeGroups(groups, byName, forward),
		ApplyStatus: h.fr.LastApplyStatus(),
	})
}

// checkPendingGroups é o pré-voo de toda mutação de GRUPO: mutate recebe os
// grupos como o banco os lê hoje e devolve o conjunto COMPLETO que existiria
// logo após a escrita pretendida — CheckGroups valida cada chain e a forward
// que as alcança de uma vez só, que é a mesma renderização que Reconcile
// aplica de verdade em seguida.
func (h *NftablesHandler) checkPendingGroups(w http.ResponseWriter, r *http.Request, mutate func([]nftables.StoredGroup) []nftables.StoredGroup) bool {
	current, err := h.fr.StoredGroups()
	if err != nil {
		writeInternalError(w, err)
		return false
	}
	if err := h.fr.CheckPendingGroups(r.Context(), mutate(current)); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return false
	}
	return true
}

// findGroup devolve a linha do grupo pelo id, ou 400 se ele não existe —
// mesma escolha de status de UpdateRule/DeleteRule para um id que não bate
// com nada: é um cliente desatualizado, não uma falha do servidor.
func (h *NftablesHandler) findGroup(w http.ResponseWriter, id string) (storage.FirewallGroup, bool) {
	groups, err := h.db.ListFirewallGroups()
	if err != nil {
		writeInternalError(w, err)
		return storage.FirewallGroup{}, false
	}
	for _, g := range groups {
		if g.ID == id {
			return g, true
		}
	}
	writeError(w, http.StatusBadRequest, fmt.Sprintf("grupo %q não encontrado", id))
	return storage.FirewallGroup{}, false
}

// CreateGroup cria um grupo, sempre no fim da ordem de avaliação e já
// ligado. O id é do servidor e o nome da chain é derivado dele.
func (h *NftablesHandler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	var b groupBody
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	b = b.trimmed()

	// C-5: validar ANTES de qualquer leitura do banco. A ordem obrigatória
	// começa em "validar os campos", e ler os grupos primeiro não era só
	// trabalho jogado fora numa requisição que já nasce inválida: com o banco
	// fora do ar, um corpo inválido virava 500 e o admin não ficava sabendo
	// que o problema era o que ele mandou. Nada em ValidateGroup depende da
	// posição, que é a única coisa aqui que precisa da leitura.
	id := uuid.NewString()
	row := &storage.FirewallGroup{
		ID:          id,
		Name:        b.Name,
		ChainName:   nftables.GroupChainName(id),
		Enabled:     true,
		CondSaddr:   b.CondSaddr,
		CondDaddr:   b.CondDaddr,
		CondIif:     b.CondIif,
		Fallthrough: b.Fallthrough,
		Scope:       b.Scope,
		ConnState:   b.ConnState,
	}
	if err := nftables.ValidateGroup(toStoredGroup(*row)); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Trava do confirmar-ou-reverte, depois da validação dos campos e antes
	// de tocar no banco — ver confirmWindowBlocks (spec §5.3).
	if h.confirmWindowBlocks(w, r) {
		return
	}
	current, err := h.fr.StoredGroups()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	row.Position = nextGroupPosition(current)
	candidate := toStoredGroup(*row)
	// O candidato é o conjunto COMPLETO que existiria depois desta criação —
	// é assim que o dry run valida também a forward, reconstruída a partir de
	// todos os grupos de uma vez.
	if err := h.fr.CheckPendingGroups(r.Context(), append(append([]nftables.StoredGroup{}, current...), candidate)); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// A janela é armada AQUI, com a mudança ainda não aplicada: o snapshot é o
	// estado anterior de verdade, e a partir desta linha todo caminho de erro
	// passa por abortArmedWindow (ver openConfirmWindow).
	win, ok := h.openConfirmWindow(w, r, groupReachesInput(*row), fmt.Sprintf("criação do grupo %q (escopo input)", row.Name))
	if !ok {
		return
	}
	if err := h.db.CreateFirewallGroup(row); err != nil {
		h.discardArmedWindow(w, r, win, err)
		return
	}
	auditAction(h.db, r, "nft.group.add", row.ChainName+":"+row.ID, row.Name)
	if !h.reconcileArmed(w, r, win) {
		return
	}
	writeJSON(w, http.StatusOK, createdGroupResult{FirewallGroup: row, Pending: win.view})
}

// UpdateGroup edita o conteúdo de um grupo (nome, condição de entrada e o
// que fazer com o que sobrar). Chain, posição e estado ligado/desligado não
// se tocam aqui — são de ReorderGroups e ToggleGroup, e o nome da chain não
// é editável por ninguém (renomear a chain de um grupo com regras dentro
// deixaria as regras órfãs no firewall).
func (h *NftablesHandler) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	var b groupBody
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	b = b.trimmed()
	if b.ID == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}
	// Trava do confirmar-ou-reverte, depois da validação dos campos e antes
	// de tocar no banco — ver confirmWindowBlocks (spec §5.3).
	if h.confirmWindowBlocks(w, r) {
		return
	}
	existing, found := h.findGroup(w, b.ID)
	if !found {
		return
	}
	// Renomear ou dar condição de entrada a um grupo do sistema não faz
	// sentido: o nome é o que ele é, e o conteúdo dele é a lista de membros
	// do named set, não regras alcançadas por uma condição. O que o admin
	// pode fazer com ele — reordenar e ligar/desligar — tem endpoint próprio.
	if nftables.IsSystemGroup(existing.Kind) {
		writeError(w, http.StatusBadRequest,
			"este é um grupo do sistema: o nome e a condição de entrada dele não são editáveis; use reordenar ou ligar/desligar")
		return
	}

	row := existing
	row.Name, row.CondSaddr, row.CondDaddr = b.Name, b.CondSaddr, b.CondDaddr
	row.CondIif, row.Fallthrough = b.CondIif, b.Fallthrough
	// Escopo ausente no corpo é "mantenha o que está gravado", nunca "volte
	// para forward". Um cliente antigo (ou qualquer chamada que não conheça o
	// campo) rebaixaria em silêncio um grupo de input para forward, movendo as
	// regras dele para outra chain e aplicando-as a um tráfego que ninguém
	// pediu — com HTTP 200 e nada na tela mudando. Para tirar um grupo da chain
	// input o cliente manda "forward" explicitamente, que é o que a tela faz.
	if b.Scope != "" {
		row.Scope = b.Scope
	}
	// Mesmo contrato para a escolha "toda conexão" × "só conexões novas", e
	// pela mesma razão, com o sinal trocado: ausente é "mantenha o que está
	// gravado", nunca "volte para toda conexão". Um cliente antigo devolveria
	// à marreta um grupo que o operador restringiu de propósito — afrouxando o
	// firewall com HTTP 200 e nada na tela mudando. Para soltar o grupo, o
	// cliente manda "any" explicitamente, que é o que a tela faz.
	if b.ConnState != "" {
		row.ConnState = b.ConnState
	}
	if err := nftables.ValidateGroup(toStoredGroup(row)); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ok := h.checkPendingGroups(w, r, func(current []nftables.StoredGroup) []nftables.StoredGroup {
		out := make([]nftables.StoredGroup, len(current))
		for i, g := range current {
			if g.ID == b.ID {
				g.Name, g.CondSaddr, g.CondDaddr = row.Name, row.CondSaddr, row.CondDaddr
				g.CondIif, g.Fallthrough = row.CondIif, row.Fallthrough
				// O escopo entra no candidato porque é ele que decide em qual
				// chain o jump é renderizado: validar o conjunto com o escopo
				// antigo seria validar outra coisa que não a que vai ser
				// aplicada — exatamente o que o pré-voo existe para não fazer.
				g.Scope = row.Scope
				// E a escolha de conexões pela mesma razão: ela muda a LINHA
				// que vai ser escrita (`ct state new` no jump). Validar o
				// conjunto sem ela seria dar o pré-voo por bom para outra
				// linha que não a que será aplicada.
				g.ConnState = row.ConnState
			}
			out[i] = g
		}
		return out
	})
	if !ok {
		return
	}
	// Os DOIS lados da edição contam: o grupo que JÁ era de input (mexer nele
	// pode trancar o acesso) e o que está PASSANDO a ser (é aí que ele ganha
	// esse poder). Sair de input para forward também abre janela — não custa
	// nada além de 90 segundos, e "na dúvida, abre" é a regra deste mecanismo.
	win, ok := h.openConfirmWindow(w, r, groupReachesInput(existing) || groupReachesInput(row),
		fmt.Sprintf("edição do grupo %q (escopo input)", row.Name))
	if !ok {
		return
	}
	// Falha do banco aqui é falha do SERVIDOR (500), não do cliente: o id já
	// foi resolvido por findGroup e os campos já passaram por ValidateGroup, de
	// modo que o que sobra é uma pane — e o 400 com o texto cru punha a
	// mensagem interna do SQLite na tela do operador.
	if err := h.db.UpdateFirewallGroup(&row); err != nil {
		h.discardArmedWindow(w, r, win, err)
		return
	}
	auditAction(h.db, r, "nft.group.update", row.ChainName+":"+row.ID, row.Name)
	if !h.reconcileArmed(w, r, win) {
		return
	}
	writeJSON(w, http.StatusOK, okResult(win.view))
}

// DeleteGroup remove o grupo E as regras de dentro dele (na mesma transação,
// storage.DeleteFirewallGroup): uma regra órfã continuaria aparecendo no
// painel sem chain nenhuma onde ser renderizada.
//
// Sem pré-voo `nft -c`, pela mesma razão de DeleteRule: tirar um jump da
// forward e apagar uma chain não é algo que o nft possa recusar por sintaxe
// — o que pode falhar é a remoção da chain ainda referenciada, e disso cuida
// a ordem dos passos de ReconcileGroups.
func (h *NftablesHandler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID string `json:"id"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	id := strings.TrimSpace(b.ID)
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}
	// Trava do confirmar-ou-reverte, depois da validação dos campos e antes
	// de tocar no banco — ver confirmWindowBlocks (spec §5.3).
	if h.confirmWindowBlocks(w, r) {
		return
	}
	// C-6: resolver o id aqui, como UpdateGroup e ToggleGroup fazem, em vez de
	// deixar o storage responder pelo "não encontrado". Enquanto o banco
	// responde, dá no mesmo; quando ele não responde, a assimetria aparece —
	// os irmãos devolvem 500 (falha do servidor, que é o que é) e este
	// devolvia 400 com o texto cru do erro de banco, culpando o cliente por
	// uma pane do servidor e vazando a mensagem interna para a tela.
	g, found := h.findGroup(w, id)
	if !found {
		return
	}
	// Apagar um grupo do sistema não é "perder um grupo": as duas linhas de
	// bloqueio são o que faz a chain forward ainda descartar tráfego de host
	// e destino bloqueados. Sem uma delas, a reconciliação passa a abortar em
	// toda passada — para não renderizar uma forward sem proteção, calada — e
	// o firewall inteiro fica em modo somente-leitura. Pior: não há caminho de
	// volta pelo painel, porque CreateGroup sempre grava kind=admin. A
	// recuperação seria sqlite3 na máquina.
	if nftables.IsSystemGroup(g.Kind) {
		writeError(w, http.StatusBadRequest,
			"este é um grupo do sistema e não pode ser removido; para desativá-lo, use o botão de ligar/desligar")
		return
	}
	win, ok := h.openConfirmWindow(w, r, groupReachesInput(g), fmt.Sprintf("remoção do grupo %q (escopo input)", g.Name))
	if !ok {
		return
	}
	// C-6, a outra metade: com o id já resolvido por findGroup, o que restar de
	// erro aqui é pane do servidor. O 400 com o texto cru do banco — a mesma
	// assimetria que este handler dizia ter corrigido — sobrevivia neste ramo.
	if err := h.db.DeleteFirewallGroup(id); err != nil {
		h.discardArmedWindow(w, r, win, err)
		return
	}
	auditAction(h.db, r, "nft.group.del", id, "")
	if !h.reconcileArmed(w, r, win) {
		return
	}
	writeJSON(w, http.StatusOK, okResult(win.view))
}

// ToggleGroup liga e desliga um grupo inteiro de uma vez — desligar é tirar
// o jump da forward; a chain e as regras de dentro continuam guardadas,
// prontas para quando o grupo voltar (spec §2.1).
func (h *NftablesHandler) ToggleGroup(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	id := strings.TrimSpace(b.ID)
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}
	// Trava do confirmar-ou-reverte, depois da validação dos campos e antes
	// de tocar no banco — ver confirmWindowBlocks (spec §5.3).
	if h.confirmWindowBlocks(w, r) {
		return
	}
	g, found := h.findGroup(w, id)
	if !found {
		return
	}
	// Só religar precisa de pré-voo: é o que acrescenta um jump (e, com ele,
	// a condição de entrada do grupo) à forward. Desligar apenas remove
	// linhas, e remover linha o nft não recusa.
	if b.Enabled {
		ok := h.checkPendingGroups(w, r, func(current []nftables.StoredGroup) []nftables.StoredGroup {
			out := make([]nftables.StoredGroup, len(current))
			for i, g := range current {
				if g.ID == id {
					g.Enabled = true
				}
				out[i] = g
			}
			return out
		})
		if !ok {
			return
		}
	}
	// Desligar um grupo de input não pode trancar ninguém (a chain nasce e
	// permanece com policy accept, então tirar linhas dela só libera), mas
	// abre janela do mesmo jeito: religar depois é o caminho perigoso, e "na
	// dúvida, abre" custa 90 segundos contra o risco de errar o julgamento.
	summary := fmt.Sprintf("desativação do grupo %q (escopo input)", g.Name)
	if b.Enabled {
		summary = fmt.Sprintf("ativação do grupo %q (escopo input)", g.Name)
	}
	win, ok := h.openConfirmWindow(w, r, groupReachesInput(g), summary)
	if !ok {
		return
	}
	if err := h.db.SetFirewallGroupEnabled(id, b.Enabled); err != nil {
		h.discardArmedWindow(w, r, win, err)
		return
	}
	action := "nft.group.disable"
	if b.Enabled {
		action = "nft.group.enable"
	}
	auditAction(h.db, r, action, id, "")
	if !h.reconcileArmed(w, r, win) {
		return
	}
	writeJSON(w, http.StatusOK, okResult(win.view))
}

// ReorderGroups define, numa requisição só, a ordem em que os grupos são
// avaliados na forward. ids precisa ser exatamente o conjunto atual — nem
// mais, nem menos: ReorderFirewallGroups grava o índice de cada id que
// existe e deixa os demais onde estavam, então uma lista parcial produz
// posições DUPLICADAS em silêncio, e a ordem de avaliação de um firewall
// passa a depender do desempate do ORDER BY. Um id desconhecido é recusado
// em vez de ignorado, para que um cliente desatualizado não corrompa a
// ordem sem ninguém ver. É a mesma recusa de ReorderRules, pela mesma razão.
func (h *NftablesHandler) ReorderGroups(w http.ResponseWriter, r *http.Request) {
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
	current, err := h.db.ListFirewallGroups()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if len(b.IDs) != len(current) {
		writeError(w, http.StatusBadRequest,
			"a lista de reordenação precisa conter exatamente os grupos atuais, sem faltar nem sobrar nenhum")
		return
	}
	currentSet := make(map[string]bool, len(current))
	for _, g := range current {
		currentSet[g.ID] = true
	}
	seen := make(map[string]bool, len(b.IDs))
	for _, id := range b.IDs {
		if !currentSet[id] {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("grupo %q não encontrado", id))
			return
		}
		if seen[id] {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("id %q repetido na lista de reordenação", id))
			return
		}
		seen[id] = true
	}
	// A ordem dos grupos de input é a ordem de avaliação da chain input, e
	// trocá-la muda qual regra decide primeiro sobre o SSH e o painel. Abre
	// janela quando o ÍNDICE de algum grupo de input muda — critério de
	// propósito mais largo do que "a ordem relativa entre os de input mudou".
	// currentIDs sai da lista já ordenada por posição que o banco devolveu.
	currentIDs := make([]string, len(current))
	isInput := make(map[string]bool, len(current))
	for i, g := range current {
		currentIDs[i] = g.ID
		isInput[g.ID] = groupReachesInput(g)
	}
	win, ok := h.openConfirmWindow(w, r, inputOrderChanged(currentIDs, b.IDs, isInput),
		"reordenação dos grupos (há grupo de escopo input entre eles)")
	if !ok {
		return
	}
	if err := h.db.ReorderFirewallGroups(b.IDs); err != nil {
		h.discardArmedWindow(w, r, win, err)
		return
	}
	auditAction(h.db, r, "nft.group.reorder", "forward", fmt.Sprintf("%d grupos", len(b.IDs)))
	if !h.reconcileArmed(w, r, win) {
		return
	}
	writeJSON(w, http.StatusOK, okResult(win.view))
}

// nextGroupPosition põe o grupo novo no fim da ordem de avaliação, com a
// mesma conta de CreateFirewallRule (maior posição + 1, não o tamanho da
// lista): depois de uma remoção as posições ficam com buracos, e usar o
// tamanho reaproveitaria um número já ocupado — dois grupos empatados numa
// chain onde a ordem é o que decide quem vence.
func nextGroupPosition(current []nftables.StoredGroup) int {
	next := 0
	for _, g := range current {
		if g.Position >= next {
			next = g.Position + 1
		}
	}
	return next
}

// toStoredGroup converte uma linha do banco na visão de internal/nftables
// para validá-la ou renderizá-la. Sem as regras de dentro: quem valida um
// grupo aqui está mexendo no grupo, não no conteúdo dele (a montagem
// completa, com as regras, é firewallrules.StoredGroups).
func toStoredGroup(g storage.FirewallGroup) nftables.StoredGroup {
	return nftables.StoredGroup{
		ID: g.ID, Name: g.Name, ChainName: g.ChainName, Position: g.Position,
		Enabled: g.Enabled, CondSaddr: g.CondSaddr, CondDaddr: g.CondDaddr,
		CondIif: g.CondIif, Fallthrough: g.Fallthrough, Kind: g.Kind, Scope: g.Scope,
		ConnState: g.ConnState,
	}
}

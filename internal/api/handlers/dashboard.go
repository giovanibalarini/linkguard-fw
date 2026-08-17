package handlers

import (
	"github.com/giovanibalarini/linkguard-fw/internal/dashboard"
	"net/http"

	"github.com/giovanibalarini/linkguard-fw/internal/auth"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// DashboardHandler serve o layout do painel — os widgets que cada admin
// escolheu e onde ele os pôs (spec §4.1). Não existe rota para ler ou escrever
// o painel DE OUTRO usuário: o dono é sempre o usuário autenticado da própria
// requisição, e é por isso que o id nunca vem do corpo nem da URL.
type DashboardHandler struct {
	db *storage.DB
}

func NewDashboardHandler(db *storage.DB) *DashboardHandler {
	return &DashboardHandler{db: db}
}

// LayoutRequest é o corpo do PUT: a lista inteira que ESTE usuário enxerga,
// como ela ficou depois do arrasto. Não é o layout inteiro dele — o que está
// gravado fora da permissão de quem chama não passa por aqui e não é apagado
// (veja SaveLayout).
type LayoutRequest struct {
	Items []dashboard.LayoutItem `json:"items"`
}

// LayoutResponse é o que o painel lê. Available é o catálogo que ESTE usuário
// pode ver — o frontend usa a lista para montar o "adicionar widget" sem
// oferecer nada que só saberia mostrar um 403.
type LayoutResponse struct {
	Items     []dashboard.LayoutItem `json:"items"`
	Available []string               `json:"available"`
}

// GetLayout devolve o painel do usuário autenticado, já sem os widgets que ele
// não tem permissão de ver. Quem nunca salvou nada recebe o layout de fábrica.
func (h *DashboardHandler) GetLayout(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	items, err := h.db.GetDashboardLayout(claims.UserID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	h.respondLayout(w, claims.UserID, items)
}

// SaveLayout grava o painel do usuário autenticado.
//
// CONTRATO — leia antes de mexer, porque é contra-intuitivo: este PUT **não
// substitui o layout inteiro**. Ele substitui SÓ O QUE O CHAMADOR ENXERGA. Os
// itens já gravados cujo widget está fora da permissão dele são fundidos de
// volta, e sobrevivem ao arrasto.
//
// O motivo é uma perda silenciosa de dados: o GET já devolve o layout filtrado
// por permissão, e a tela manda de volta exatamente o que leu. Um admin sem
// hosts.read recebia o layout SEM os widgets de host e, no primeiro arrasto,
// gravava a lista reduzida por cima da linha. Quando o hosts.read fosse
// concedido depois, os widgets não voltavam: o catálogo os oferecia de novo,
// mas a POSIÇÃO que o admin tinha montado já não existia mais. O que o usuário
// não pode ver, ele não pode nem apagar sem querer.
//
// A fusão não é porta de entrada: item que o chamador não pode ver é descartado
// do corpo antes de qualquer coisa (mergeWithInvisibleStored), então ninguém
// injeta widget fora da própria permissão fingindo "preservar" o que já existia.
//
// Item que aponta para widget inexistente é descartado item a item, e o resto é
// gravado — inclusive aqui, na escrita. Um 400 travaria o operador: bastaria uma
// aba antiga aberta, com um widget que a versão nova removeu, para que nenhum
// arrasto conseguisse mais ser salvo. Corpo que não é JSON continua sendo 400,
// porque aí não há layout nenhum para gravar.
func (h *DashboardHandler) SaveLayout(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var body LayoutRequest
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}
	if len(body.Items) > dashboard.MaxItems {
		writeError(w, http.StatusBadRequest, "layout com itens demais")
		return
	}
	perms, err := h.db.GetUserPermissions(claims.UserID)
	if err != nil {
		// Erro de banco é 500, nunca 400: o cliente não fez nada errado, e a
		// mensagem crua traria SQL e detalhe do driver para dentro da resposta.
		writeInternalError(w, err)
		return
	}
	// O que já estava gravado. Quem nunca salvou nada recebe aqui o layout de
	// fábrica, e é o que queremos: o padrão inclui top_talkers, que exige
	// hosts.read, e o primeiro arrasto de quem não tem essa permissão também
	// não pode ser o que apaga esse widget do painel dele.
	stored, err := h.db.GetDashboardLayout(claims.UserID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	items := dashboard.Sanitize(mergeWithInvisibleStored(perms, body.Items, stored))
	if err := h.db.SaveDashboardLayout(claims.UserID, items); err != nil {
		writeInternalError(w, err)
		return
	}
	h.respondLayoutWithPerms(w, perms, items)
}

// mergeWithInvisibleStored funde o layout que o chamador mandou com os itens já
// gravados que ele não pode ver.
//
// Duas regras, e as duas importam:
//
//  1. Do corpo só entra o que o chamador ENXERGA. É isso que impede o PUT de
//     gravar (ou ressuscitar) widget fora da permissão de quem está chamando.
//  2. Do gravado só entra o que o chamador NÃO enxerga. O que ele enxerga é
//     dele: se ele tirou um widget do painel, o widget sai mesmo — a fusão não
//     pode desfazer uma remoção deliberada.
//
// POSIÇÃO: o item invisível volta com o x/y/w/h que estava GRAVADO, sem
// recolocação. A posição gravada é justamente o que esta correção existe para
// não perder ("os widgets voltam onde estavam"), e recolocar ao fim jogaria o
// widget para o rodapé do painel na hora em que a permissão fosse concedida —
// perda silenciosa igual, só mais discreta. A sobreposição que isso pode criar
// com os itens recém-arrastados não é problema de quem grava: a grade do
// frontend (web/src/lib/grid.ts) já resolve colisão e compacta para cima a cada
// leitura, e é a mesma passada que ela roda ao abrir qualquer layout salvo.
//
// Como as duas listas são partilhadas por VISIBILIDADE do widget, nenhum nome
// pode sair dos dois lados: não há item duplicado a desempatar.
func mergeWithInvisibleStored(perms map[string]bool, incoming, stored []dashboard.LayoutItem) []dashboard.LayoutItem {
	out := make([]dashboard.LayoutItem, 0, len(incoming)+len(stored))
	for _, it := range incoming {
		if canSeeWidget(perms, it.Widget) {
			out = append(out, it)
		}
	}
	for _, it := range stored {
		if !canSeeWidget(perms, it.Widget) {
			out = append(out, it)
		}
	}
	return out
}

// ResetLayout apaga o painel do usuário, que volta ao layout de fábrica — o
// "Restaurar padrão" da spec §6, para quem se perdeu arrastando. Devolve já o
// padrão para o painel redesenhar sem uma segunda ida ao servidor.
func (h *DashboardHandler) ResetLayout(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := h.db.DeleteDashboardLayout(claims.UserID); err != nil {
		writeInternalError(w, err)
		return
	}
	h.respondLayout(w, claims.UserID, dashboard.Default())
}

// respondLayout filtra por permissão e responde. Widget que o usuário não pode
// ver não volta no layout e não aparece no catálogo: o painel abre sem ele, sem
// erro e sem buraco (spec §4.1).
func (h *DashboardHandler) respondLayout(w http.ResponseWriter, userID string, items []dashboard.LayoutItem) {
	perms, err := h.db.GetUserPermissions(userID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	h.respondLayoutWithPerms(w, perms, items)
}

// respondLayoutWithPerms é a mesma resposta para quem já leu as permissões do
// usuário — o SaveLayout precisa delas para fundir, e uma segunda consulta ao
// banco no meio da mesma requisição poderia responder com uma permissão
// diferente da que decidiu a gravação.
func (h *DashboardHandler) respondLayoutWithPerms(w http.ResponseWriter, perms map[string]bool, items []dashboard.LayoutItem) {
	visible := make([]dashboard.LayoutItem, 0, len(items))
	for _, it := range items {
		if canSeeWidget(perms, it.Widget) {
			visible = append(visible, it)
		}
	}
	available := make([]string, 0, len(dashboard.Catalog))
	for _, wd := range dashboard.Catalog {
		if canSeeWidget(perms, wd.Name) {
			available = append(available, wd.Name)
		}
	}
	writeJSON(w, http.StatusOK, LayoutResponse{Items: visible, Available: available})
}

// canSeeWidget resolve a permissão de um widget contra as do usuário. Widget
// desconhecido nunca é visível — é a mesma decisão da leitura do banco, aqui
// para o caso de o catálogo mudar entre uma consulta e outra.
func canSeeWidget(perms map[string]bool, widget string) bool {
	perm, ok := dashboard.Permission(widget)
	if !ok {
		return false
	}
	if perm == "" {
		return true
	}
	return perms[perm]
}

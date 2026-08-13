package handlers

import (
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

// LayoutRequest é o corpo do PUT: a lista inteira, como ela ficou depois do
// arrasto. O layout é sempre gravado por completo, nunca item a item.
type LayoutRequest struct {
	Items []storage.LayoutItem `json:"items"`
}

// LayoutResponse é o que o painel lê. Available é o catálogo que ESTE usuário
// pode ver — o frontend usa a lista para montar o "adicionar widget" sem
// oferecer nada que só saberia mostrar um 403.
type LayoutResponse struct {
	Items     []storage.LayoutItem `json:"items"`
	Available []string             `json:"available"`
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
	if len(body.Items) > storage.DashboardMaxItems {
		writeError(w, http.StatusBadRequest, "layout com itens demais")
		return
	}
	items := storage.SanitizeDashboardLayout(body.Items)
	if err := h.db.SaveDashboardLayout(claims.UserID, items); err != nil {
		// Erro de banco é 500, nunca 400: o cliente não fez nada errado, e a
		// mensagem crua traria SQL e detalhe do driver para dentro da resposta.
		writeInternalError(w, err)
		return
	}
	h.respondLayout(w, claims.UserID, items)
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
	h.respondLayout(w, claims.UserID, storage.DefaultDashboardLayout())
}

// respondLayout filtra por permissão e responde. Widget que o usuário não pode
// ver não volta no layout e não aparece no catálogo: o painel abre sem ele, sem
// erro e sem buraco (spec §4.1).
func (h *DashboardHandler) respondLayout(w http.ResponseWriter, userID string, items []storage.LayoutItem) {
	perms, err := h.db.GetUserPermissions(userID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	visible := make([]storage.LayoutItem, 0, len(items))
	for _, it := range items {
		if canSeeWidget(perms, it.Widget) {
			visible = append(visible, it)
		}
	}
	available := make([]string, 0, len(storage.DashboardWidgets))
	for _, wd := range storage.DashboardWidgets {
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
	perm, ok := storage.DashboardWidgetPermission(widget)
	if !ok {
		return false
	}
	if perm == "" {
		return true
	}
	return perms[perm]
}

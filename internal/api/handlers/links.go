package handlers

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/routes"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// LinksHandler handles WAN link CRUD requests.
type LinksHandler struct {
	svc    *links.Service
	db     *storage.DB
	nftSvc *nftables.Service
	// routeSvc é opcional: um handler construído sem ele continua
	// reconciliando NAT e contabilidade, só não mexe em rota. É o que mantém
	// os testes que constroem o handler à mão funcionando.
	routeSvc *routes.Service
}

// NewLinksHandler creates the handler. nftSvc is needed because changing a
// link's interface must also rebuild the firewall's NAT rule — before
// 2026-08-10 nothing did, so an edited link left the masquerade rule
// pointing at the previous interface.
func NewLinksHandler(svc *links.Service, db *storage.DB, nftSvc *nftables.Service, routeSvc *routes.Service) *LinksHandler {
	return &LinksHandler{svc: svc, db: db, nftSvc: nftSvc, routeSvc: routeSvc}
}

// reconcileWANDerived rebuilds everything que deriva da lista de WANs
// habilitadas: a regra de masquerade e a contabilidade por host (#112). As
// duas leem a MESMA lista, e por isso mudam juntas — deixar uma fora daqui
// significa que ela só acompanharia a mudança no próximo boot.
//
// Foi o que aconteceu com a contabilidade: reconciliada só na subida, ela
// nunca aparecia numa instalação nova (que nasce sem link nenhum) até alguém
// reiniciar o serviço. A bateria G do vm-validate.sh pegou isso.
//
// Best-effort: a falha é registrada (e aparece no vigia de NAT) mas nunca
// derruba a operação de link que o admin acabou de fazer.
func (h *LinksHandler) reconcileWANDerived(ctx context.Context) {
	if h.nftSvc == nil {
		return
	}
	ifaces, err := enabledWANInterfaces(h.db)
	if err != nil {
		slog.Warn("não foi possível carregar links para reconciliar as regras derivadas das WANs", "err", err)
		return
	}
	if err := h.nftSvc.ReconcileMasquerade(ctx, ifaces); err != nil {
		slog.Warn("não foi possível reconciliar a regra de NAT após mudança de link", "err", err)
	}
	if err := h.nftSvc.EnsureAccounting(ctx, ifaces); err != nil {
		slog.Warn("não foi possível reconciliar a contabilidade por host após mudança de link", "err", err)
	}
	if err := h.nftSvc.EnsureMSSClamp(ctx, ifaces); err != nil {
		slog.Warn("não foi possível reconciliar o ajuste de MSS após mudança de link", "err", err)
	}

	// O roteamento de retorno (#120) também deriva da lista de WANs, e mais
	// diretamente que os outros dois: trocar a interface ou o gateway de um
	// link muda o caminho de volta dele. Sem reconciliar aqui, a tabela do link
	// continuaria apontando para o gateway antigo — e a resposta iria para o
	// vazio, em silêncio.
	todos, err := h.db.GetLinks()
	if err != nil {
		slog.Warn("não foi possível carregar links para reconciliar o roteamento de retorno", "err", err)
		return
	}
	caminhos := links.WANPaths(todos)
	marcas := make([]nftables.WANMark, 0, len(caminhos))
	rotas := make([]routes.ReplyRoute, 0, len(caminhos))
	for _, c := range caminhos {
		marcas = append(marcas, nftables.WANMark{Interface: c.Interface, Mark: c.Mark})
		rotas = append(rotas, routes.ReplyRoute{
			Interface: c.Interface, Gateway: c.Gateway, Table: c.Table, Mark: c.MarkHex(),
		})
	}
	if err := h.nftSvc.EnsureConnMark(ctx, marcas); err != nil {
		slog.Warn("não foi possível reconciliar a marcação de conexão após mudança de link", "err", err)
	}
	if h.routeSvc != nil {
		if err := h.routeSvc.EnsureReplyRouting(ctx, rotas); err != nil {
			slog.Warn("não foi possível reconciliar o roteamento de retorno após mudança de link", "err", err)
		}
	}
}

// List returns all links.
func (h *LinksHandler) List(w http.ResponseWriter, r *http.Request) {
	ls, err := h.svc.List()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if ls == nil {
		ls = []storage.Link{}
	}
	writeJSON(w, http.StatusOK, ls)
}

// Get returns a single link.
func (h *LinksHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	l, err := h.svc.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, l)
}

// Create inserts a new link.
func (h *LinksHandler) Create(w http.ResponseWriter, r *http.Request) {
	var l storage.Link
	if err := decodeJSON(r, &l); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.svc.Create(&l); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.reconcileWANDerived(r.Context())
	writeJSON(w, http.StatusCreated, l)
}

// Update modifies an existing link.
func (h *LinksHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existing, err := h.svc.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	var updated storage.Link
	if err := decodeJSON(r, &updated); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	updated.ID = existing.ID
	updated.CreatedAt = existing.CreatedAt

	if err := h.svc.Update(&updated); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.reconcileWANDerived(r.Context())
	writeJSON(w, http.StatusOK, updated)
}

// Delete removes a link.
func (h *LinksHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.svc.Get(id); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if err := h.svc.Delete(id); err != nil {
		writeInternalError(w, err)
		return
	}
	h.reconcileWANDerived(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

// AutoDetect discovers WAN interfaces from system routes and syncs them to DB.
func (h *LinksHandler) AutoDetect(w http.ResponseWriter, r *http.Request) {
	res, err := h.svc.DiscoverAndSyncWANLinks()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	h.reconcileWANDerived(r.Context())
	writeJSON(w, http.StatusOK, res)
}

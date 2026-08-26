package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/qos"
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
	// fluxos reconcilia o registro de conversa por host (#115). Opcional, como
	// routeSvc: um handler construído sem ele continua reconciliando o resto.
	//
	// É INTERFACE, e não o *hostflows.Servico, para links.go não ganhar mais um
	// pacote interno — o teto por arquivo do TestPackageBoundary existe
	// justamente para a camada HTTP não acumular domínio sem ninguém notar.
	fluxos reconciliadorDeFluxos
	// domainRouting recompõe estágio efetivo e mark após qualquer mudança na
	// configuração da WAN, inclusive quando o runtime nft não foi injetado em
	// um teste ou numa instalação degradada.
	domainRouting domainRoutingReconciler
	qosSvc        qosService
	qosLocker     qosInterfaceLocker
}

var (
	errQosCleanup     = errors.New("qos cleanup failed")
	errQosLinkChanged = errors.New("link changed during request")
)

// reconciliadorDeFluxos é o que o handler de links precisa do registro de
// conversa: quando a lista de WANs muda, a regra que escopa a medição por
// interface fica com o nome antigo — a medição calada, com cara de ligada, que
// é o mesmo defeito que a #112 já teve na contabilidade.
type reconciliadorDeFluxos interface {
	Reconciliar(ctx context.Context, wans []string) error
}

// SetFluxos liga o registro de conversa ao handler de links.
func (h *LinksHandler) SetFluxos(r reconciliadorDeFluxos) { h.fluxos = r }

func (h *LinksHandler) SetDomainRouting(r domainRoutingReconciler) { h.domainRouting = r }

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
	if h.domainRouting != nil {
		// A intenção por domínio é publicada por último: uma edição de table_id
		// não pode começar a marcar pacotes antes de connmark e policy routing
		// terem sido reconstruídos. O defer também cobre o runtime nft ausente.
		defer func() {
			if err := h.domainRouting.Reconcile(ctx); err != nil {
				slog.Warn("não foi possível reconciliar os alvos por domínio após mudança de link", "err", err)
			}
		}()
	}
	h.reconcileQos(ctx)
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

	// O registro de conversa (#115) escopa a medição pela lista de WANs, igual
	// à contabilidade: sem reconciliar aqui, uma interface renomeada deixa o
	// nome antigo na regra e a medição para de registrar sem dizer nada.
	if h.fluxos != nil {
		if err := h.fluxos.Reconciliar(ctx, ifaces); err != nil {
			slog.Warn("não foi possível reconciliar o registro de conversa após mudança de link", "err", err)
		}
	}

	// A proteção de entrada da chain input (#119) casa por `iifname` das WANs:
	// se ela não for reconstruída aqui, uma interface renomeada deixa o nome
	// antigo na regra — a proteção calada, com cara de ligada.
	if err := h.nftSvc.ReconcileInputProtection(ctx); err != nil {
		slog.Warn("não foi possível reconciliar a proteção de entrada das WANs após mudança de link", "err", err)
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
	// A regra de domínio usa a MESMA lista de WANPath/marks do connmark e das
	// tabelas de policy routing. Derivar por outra consulta permitiria que
	// `dom_wan` marcasse para uma tabela que o caminho de volta não conhece.
	if err := h.nftSvc.ReconcileStructuralChains(ctx, marcas...); err != nil {
		slog.Warn("não foi possível reconciliar o direcionamento por domínio após mudança de link", "err", err)
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
	// QoS has its own apply-before-persist endpoint. Generic link creation
	// must not silently persist a configuration that was never validated or
	// applied to the kernel.
	l.QoSEnabled = false
	l.QoSUploadMbps = 0
	l.QoSDownloadMbps = 0
	l.QoSInteractive = false
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

	update := func(ops qos.InterfaceOperations) error {
		current, err := h.db.GetLink(id)
		if err != nil {
			return err
		}
		if current == nil || current.Interface != existing.Interface {
			return errQosLinkChanged
		}
		updated.ID = current.ID
		updated.CreatedAt = current.CreatedAt
		updated.QoSEnabled = current.QoSEnabled
		updated.QoSUploadMbps = current.QoSUploadMbps
		updated.QoSDownloadMbps = current.QoSDownloadMbps
		updated.QoSInteractive = current.QoSInteractive

		cleanupRequired := h.qosSvc != nil && current.QoSEnabled &&
			(current.Interface != updated.Interface || !updated.Enabled)
		oldQoS := qosConfigFromLink(current)
		oldQoS.Enabled = current.Enabled && current.QoSEnabled
		apply := func(cfg qos.Config) (qos.State, error) {
			if ops != nil {
				return ops.Apply(r.Context(), cfg)
			}
			return h.qosSvc.Apply(r.Context(), cfg)
		}
		if cleanupRequired {
			if _, err := apply(qos.Config{Interface: current.Interface}); err != nil {
				return fmt.Errorf("%w: disable QoS before link update: %v", errQosCleanup, err)
			}
		}
		if err := h.svc.Update(&updated); err != nil {
			if cleanupRequired {
				if _, restoreErr := apply(oldQoS); restoreErr != nil {
					return fmt.Errorf("%w: update link: %v; restore QoS: %v", qos.ErrCompensationFailed, err, restoreErr)
				}
			}
			return err
		}
		return nil
	}
	var updateErr error
	if h.qosLocker != nil {
		updateErr = h.qosLocker.WithInterfaceLock(r.Context(), existing.Interface, update)
	} else {
		updateErr = update(nil)
	}
	if updateErr != nil {
		if errors.Is(updateErr, qos.ErrCompensationFailed) {
			slog.Error("link update failed and QoS rollback also failed; reconciling from fresh link state", "link_id", id, "interface", existing.Interface, "err", updateErr)
			repairCtx, cancel := emergencyQosReconcileContext(r.Context())
			h.reconcileQos(repairCtx)
			cancel()
			writeInternalError(w, updateErr)
			return
		}
		if errors.Is(updateErr, errQosLinkChanged) {
			writeError(w, http.StatusConflict, "link changed during update; retry")
			return
		}
		if errors.Is(updateErr, errQosCleanup) {
			writeInternalError(w, updateErr)
			return
		}
		writeError(w, http.StatusBadRequest, updateErr.Error())
		return
	}
	h.reconcileWANDerived(r.Context())
	writeJSON(w, http.StatusOK, updated)
}

// Delete removes a link.
func (h *LinksHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existing, err := h.svc.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	remove := func(ops qos.InterfaceOperations) error {
		current, err := h.db.GetLink(id)
		if err != nil {
			return err
		}
		if current == nil || current.Interface != existing.Interface {
			return errQosLinkChanged
		}
		cleanupRequired := h.qosSvc != nil && current.QoSEnabled
		oldQoS := qosConfigFromLink(current)
		oldQoS.Enabled = current.Enabled && current.QoSEnabled
		apply := func(cfg qos.Config) (qos.State, error) {
			if ops != nil {
				return ops.Apply(r.Context(), cfg)
			}
			return h.qosSvc.Apply(r.Context(), cfg)
		}
		if cleanupRequired {
			if _, err := apply(qos.Config{Interface: current.Interface}); err != nil {
				return fmt.Errorf("%w: disable QoS before link delete: %v", errQosCleanup, err)
			}
		}
		if err := h.svc.Delete(id); err != nil {
			if cleanupRequired {
				if _, restoreErr := apply(oldQoS); restoreErr != nil {
					return fmt.Errorf("%w: delete link: %v; restore QoS: %v", qos.ErrCompensationFailed, err, restoreErr)
				}
			}
			return err
		}
		return nil
	}
	var removeErr error
	if h.qosLocker != nil {
		removeErr = h.qosLocker.WithInterfaceLock(r.Context(), existing.Interface, remove)
	} else {
		removeErr = remove(nil)
	}
	if removeErr != nil {
		if errors.Is(removeErr, qos.ErrCompensationFailed) {
			slog.Error("link delete failed and QoS rollback also failed; reconciling from fresh link state", "link_id", id, "interface", existing.Interface, "err", removeErr)
			repairCtx, cancel := emergencyQosReconcileContext(r.Context())
			h.reconcileQos(repairCtx)
			cancel()
			writeInternalError(w, removeErr)
			return
		}
		if errors.Is(removeErr, errQosLinkChanged) {
			writeError(w, http.StatusConflict, "link changed during delete; retry")
			return
		}
		writeInternalError(w, removeErr)
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

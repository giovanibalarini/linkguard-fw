package handlers

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-fw/internal/qos"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

type qosService interface {
	Apply(context.Context, qos.Config) (qos.State, error)
	ApplyAndPersist(context.Context, qos.Config, qos.Config, func() error) (qos.State, error)
	Observe(context.Context, string) (qos.State, error)
	MeasureBeforeAfter(context.Context, qos.Config) (qos.Comparison, error)
}

// QosHandler exposes per-link queue-control configuration and measurements.
type QosHandler struct {
	svc qosService
	db  *storage.DB
}

// NewQosHandler creates a QoS handler.
func NewQosHandler(svc qosService, db *storage.DB) *QosHandler {
	return &QosHandler{svc: svc, db: db}
}

var errQosLinkNotFound = errors.New("link not found")

type qosUpdateRequest struct {
	Enabled      bool `json:"enabled"`
	UploadMbps   int  `json:"upload_mbps"`
	DownloadMbps int  `json:"download_mbps"`
	Interactive  bool `json:"interactive"`
}

type qosGetResponse struct {
	Desired  qos.Config `json:"desired"`
	Observed qos.State  `json:"observed"`
}

// Get returns the desired QoS configuration persisted for one link.
func (h *QosHandler) Get(w http.ResponseWriter, r *http.Request) {
	link, err := h.loadLink(chi.URLParam(r, "id"))
	if err != nil {
		h.writeLinkError(w, err)
		return
	}
	cfg := qosConfigFromLink(link)
	if err := cfg.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	observed, err := h.svc.Observe(r.Context(), link.Interface)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, qosGetResponse{Desired: cfg, Observed: observed})
}

// Update applies QoS before persisting the requested configuration.
func (h *QosHandler) Update(w http.ResponseWriter, r *http.Request) {
	link, err := h.loadLink(chi.URLParam(r, "id"))
	if err != nil {
		h.writeLinkError(w, err)
		return
	}

	var request qosUpdateRequest
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	desired := qos.Config{
		Interface:    link.Interface,
		Enabled:      request.Enabled,
		UploadMbps:   request.UploadMbps,
		DownloadMbps: request.DownloadMbps,
		Interactive:  request.Interactive,
	}
	if err := desired.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	applyConfig := desired
	applyConfig.Enabled = link.Enabled && desired.Enabled
	rollback := qosConfigFromLink(link)
	rollback.Enabled = link.Enabled && rollback.Enabled
	state, err := h.svc.ApplyAndPersist(r.Context(), applyConfig, rollback, func() error {
		return h.db.UpdateLinkQoS(link.ID, link.Interface, desired.Enabled, desired.UploadMbps, desired.DownloadMbps, desired.Interactive)
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusConflict, "link changed during QoS update; retry")
			return
		}
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "qos.update", "link", link.ID)
	writeJSON(w, http.StatusOK, state)
}

// Test measures a link before and after reapplying its persisted QoS config.
func (h *QosHandler) Test(w http.ResponseWriter, r *http.Request) {
	link, err := h.loadLink(chi.URLParam(r, "id"))
	if err != nil {
		h.writeLinkError(w, err)
		return
	}
	desired := qosConfigFromLink(link)
	if err := desired.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	desired.Enabled = link.Enabled && desired.Enabled
	comparison, err := h.svc.MeasureBeforeAfter(r.Context(), desired)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "qos.test", "link", link.ID)
	writeJSON(w, http.StatusOK, comparison)
}

func (h *QosHandler) loadLink(id string) (*storage.Link, error) {
	link, err := h.db.GetLink(id)
	if err != nil {
		return nil, err
	}
	if link == nil {
		return nil, errQosLinkNotFound
	}
	return link, nil
}

func (h *QosHandler) writeLinkError(w http.ResponseWriter, err error) {
	if errors.Is(err, errQosLinkNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeInternalError(w, err)
}

func qosConfigFromLink(link *storage.Link) qos.Config {
	return qos.Config{
		Interface:    link.Interface,
		Enabled:      link.QoSEnabled,
		UploadMbps:   link.QoSUploadMbps,
		DownloadMbps: link.QoSDownloadMbps,
		Interactive:  link.QoSInteractive,
	}
}

// SetQosService enables QoS reconciliation after link mutations.
func (h *LinksHandler) SetQosService(svc qosService) {
	h.qosSvc = svc
	if locker, ok := svc.(qosInterfaceLocker); ok {
		h.qosLocker = locker
	}
}

func (h *LinksHandler) reconcileQos(ctx context.Context) {
	if h.qosSvc == nil {
		return
	}
	links, err := h.db.GetLinks()
	if err != nil {
		slog.Warn("não foi possível carregar links para reconciliar QoS", "err", err)
		return
	}
	for _, link := range links {
		if link.Enabled && link.QoSEnabled {
			if _, err := h.qosSvc.Apply(ctx, qosConfigFromLink(&link)); err != nil {
				slog.Warn("não foi possível aplicar QoS após mudança de link", "link_id", link.ID, "interface", link.Interface, "err", err)
			}
			continue
		}
		if _, err := h.qosSvc.Apply(ctx, qos.Config{Interface: link.Interface}); err != nil {
			slog.Warn("não foi possível remover QoS stale após mudança de link", "link_id", link.ID, "interface", link.Interface, "err", err)
		}
	}
}

func (h *LinksHandler) disableQosInterface(ctx context.Context, iface string) {
	if h.qosSvc == nil || iface == "" {
		return
	}
	if _, err := h.qosSvc.Apply(ctx, qos.Config{Interface: iface}); err != nil {
		slog.Warn("não foi possível remover QoS da interface anterior do link", "interface", iface, "err", err)
	}
}

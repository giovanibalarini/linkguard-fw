package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-fw/internal/qos"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

type qosService interface {
	Apply(context.Context, qos.Config) (qos.State, error)
	ApplyAndPersist(context.Context, qos.Config, qos.Config, func() error) (qos.State, error)
	ApplyCurrent(context.Context, string, func() (qos.Config, error)) (qos.State, error)
	ApplyCurrentAndPersist(context.Context, string, func() (qos.ApplyPlan, error)) (qos.State, error)
	Observe(context.Context, string) (qos.State, error)
	MeasureBeforeAfter(context.Context, qos.Config) (qos.Comparison, error)
	MeasureCurrentBeforeAfter(context.Context, string, func() (qos.Config, error)) (qos.Comparison, error)
}

type qosInterfaceLocker interface {
	WithInterfaceLock(context.Context, string, func(qos.InterfaceOperations) error) error
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
var errQosInvalidConfig = errors.New("invalid persisted QoS configuration")

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

	state, err := h.svc.ApplyCurrentAndPersist(r.Context(), link.Interface, func() (qos.ApplyPlan, error) {
		current, err := h.db.GetLink(link.ID)
		if err != nil {
			return qos.ApplyPlan{}, err
		}
		if current == nil {
			return qos.ApplyPlan{}, errQosLinkNotFound
		}
		if current.Interface != link.Interface {
			return qos.ApplyPlan{}, fmt.Errorf("%w: %q became %q", qos.ErrStaleInterface, link.Interface, current.Interface)
		}
		desired.Interface = current.Interface
		if err := desired.Validate(); err != nil {
			return qos.ApplyPlan{}, err
		}
		applyConfig := desired
		applyConfig.Enabled = current.Enabled && desired.Enabled
		rollback := qosConfigFromLink(current)
		rollback.Enabled = current.Enabled && rollback.Enabled
		return qos.ApplyPlan{
			Config:   applyConfig,
			Rollback: rollback,
			Persist: func() error {
				return h.db.UpdateLinkQoSIfCurrent(link.ID, current.Interface, current.Enabled, current.UpdatedAt,
					desired.Enabled, desired.UploadMbps, desired.DownloadMbps, desired.Interactive)
			},
		}, nil
	})
	if err != nil {
		if errors.Is(err, errQosLinkNotFound) {
			h.writeLinkError(w, err)
			return
		}
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, qos.ErrStaleInterface) {
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
	comparison, err := h.svc.MeasureCurrentBeforeAfter(r.Context(), link.Interface, func() (qos.Config, error) {
		current, err := h.db.GetLink(link.ID)
		if err != nil {
			return qos.Config{}, err
		}
		if current == nil {
			return qos.Config{}, errQosLinkNotFound
		}
		if current.Interface != link.Interface {
			return qos.Config{}, fmt.Errorf("%w: %q became %q", qos.ErrStaleInterface, link.Interface, current.Interface)
		}
		desired := qosConfigFromLink(current)
		if err := desired.Validate(); err != nil {
			return qos.Config{}, fmt.Errorf("%w: %v", errQosInvalidConfig, err)
		}
		desired.Enabled = current.Enabled && desired.Enabled
		return desired, nil
	})
	if err != nil {
		if errors.Is(err, errQosLinkNotFound) {
			h.writeLinkError(w, err)
			return
		}
		if errors.Is(err, qos.ErrStaleInterface) {
			writeError(w, http.StatusConflict, "link changed during QoS test; retry")
			return
		}
		if errors.Is(err, errQosInvalidConfig) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
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
	h.qosSvc = nil
	h.qosLocker = nil
	if isNilQosService(svc) {
		return
	}
	h.qosSvc = svc
	if locker, ok := svc.(qosInterfaceLocker); ok {
		h.qosLocker = locker
	}
}

func isNilQosService(svc qosService) bool {
	if svc == nil {
		return true
	}
	v := reflect.ValueOf(svc)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	default:
		return false
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
	for pass := 0; pass < 2; pass++ {
		moved := false
		for _, snapshot := range links {
			changedInterface := false
			_, err := h.qosSvc.ApplyCurrent(ctx, snapshot.Interface, func() (qos.Config, error) {
				current, err := h.db.GetLink(snapshot.ID)
				if err != nil {
					return qos.Config{}, err
				}
				if current == nil {
					return qos.Config{Interface: snapshot.Interface}, nil
				}
				if current.Interface != snapshot.Interface {
					changedInterface = true
					return qos.Config{Interface: snapshot.Interface}, nil
				}
				return effectiveQosConfig(current), nil
			})
			if changedInterface {
				moved = true
			}
			if err != nil {
				slog.Warn("não foi possível reconciliar QoS após mudança de link", "link_id", snapshot.ID, "interface", snapshot.Interface, "err", err)
			}
		}
		if !moved {
			return
		}
		links, err = h.db.GetLinks()
		if err != nil {
			slog.Warn("não foi possível recarregar links para reconciliar QoS", "err", err)
			return
		}
	}
}

func effectiveQosConfig(link *storage.Link) qos.Config {
	if !link.Enabled || !link.QoSEnabled {
		return qos.Config{Interface: link.Interface}
	}
	return qosConfigFromLink(link)
}

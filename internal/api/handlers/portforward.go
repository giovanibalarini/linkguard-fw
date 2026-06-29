package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

const portForwardKey = "port_forwards"

// PortForwardHandler manages external→internal port forwarding (DNAT). The list
// is persisted as JSON in settings and rendered into the nftables DNAT chain on
// every change.
type PortForwardHandler struct {
	db  *storage.DB
	nft *nftables.Service
}

// NewPortForwardHandler creates a PortForwardHandler.
func NewPortForwardHandler(db *storage.DB, nft *nftables.Service) *PortForwardHandler {
	return &PortForwardHandler{db: db, nft: nft}
}

func (h *PortForwardHandler) load() []nftables.PortForward {
	var list []nftables.PortForward
	if raw, _ := h.db.GetSetting(portForwardKey); raw != "" {
		_ = json.Unmarshal([]byte(raw), &list)
	}
	if list == nil {
		list = []nftables.PortForward{}
	}
	return list
}

func (h *PortForwardHandler) save(list []nftables.PortForward) error {
	out, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return h.db.SetSetting(portForwardKey, string(out))
}

// List returns all configured port forwards.
func (h *PortForwardHandler) List(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.load())
}

// Upsert creates or updates a port forward, then re-applies the DNAT chain.
func (h *PortForwardHandler) Upsert(w http.ResponseWriter, r *http.Request) {
	var pf nftables.PortForward
	if err := decodeJSON(r, &pf); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	pf.Name = strings.TrimSpace(pf.Name)
	pf.DestIP = strings.TrimSpace(pf.DestIP)
	pf.Proto = strings.ToLower(strings.TrimSpace(pf.Proto))

	list := h.load()
	if pf.ID == "" {
		pf.ID = uuid.NewString()
		list = append(list, pf)
	} else {
		found := false
		for i := range list {
			if list[i].ID == pf.ID {
				list[i] = pf
				found = true
				break
			}
		}
		if !found {
			list = append(list, pf)
		}
	}

	if err := h.apply(r, list); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	auditAction(h.db, r, "upsert", "portforward", pf.Name)
	writeJSON(w, http.StatusOK, list)
}

// Delete removes a port forward by id and re-applies the DNAT chain.
func (h *PortForwardHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id é obrigatório")
		return
	}
	list := h.load()
	out := make([]nftables.PortForward, 0, len(list))
	for _, pf := range list {
		if pf.ID != id {
			out = append(out, pf)
		}
	}
	if err := h.apply(r, out); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	auditAction(h.db, r, "delete", "portforward", id)
	writeJSON(w, http.StatusOK, out)
}

// apply renders the list into nftables first; only on success is it persisted,
// so a malformed entry never leaves the stored list and the live ruleset out of
// sync.
func (h *PortForwardHandler) apply(r *http.Request, list []nftables.PortForward) error {
	if err := h.nft.ApplyPortForwards(r.Context(), list); err != nil {
		return err
	}
	return h.save(list)
}

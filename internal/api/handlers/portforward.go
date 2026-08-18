package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
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
	// fr reconcilia as chains construídas a partir do banco (forward e input).
	//
	// O encaminhamento escreve só a chain de DNAT (prerouting_dnat), e por isso
	// funciona hoje: com a forward em `policy accept`, o pacote traduzido passa
	// por política. No dia em que a forward tiver política restritiva (#78), a
	// liberação correspondente tem de existir na forward — e ela só aparece
	// numa reconciliação, que este caminho nunca disparava (issue #82).
	//
	// Pode ser nil: o construtor antigo é mantido para os testes que só
	// exercitam o DNAT, e nesse caso a reconciliação é pulada com log.
	fr firewallReconciler
}

// firewallReconciler é a fatia de firewallrules.Service que este handler usa.
// Interface, e não o tipo concreto, para o pacote de handlers não ganhar mais
// uma dependência larga — a fronteira da issue #27 vigia exatamente isso.
type firewallReconciler interface {
	Reconcile(ctx context.Context) error
}

// NewPortForwardHandler creates a PortForwardHandler.
func NewPortForwardHandler(db *storage.DB, nft *nftables.Service) *PortForwardHandler {
	return &PortForwardHandler{db: db, nft: nft}
}

// WithReconciler liga o reconciliador. Separado do construtor porque
// firewallrules.Service é montado depois do handler no boot.
func (h *PortForwardHandler) WithReconciler(fr firewallReconciler) *PortForwardHandler {
	h.fr = fr
	return h
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
	if err := h.save(list); err != nil {
		return err
	}

	// Reconcilia DEPOIS de salvar, e não antes: a reconciliação renderiza a
	// partir do que está no banco, então rodá-la antes do save reconstruiria a
	// forward com a lista ANTIGA — o oposto do que se quer (issue #82).
	//
	// Falha aqui não desfaz o encaminhamento: o DNAT já está aplicado e salvo, e
	// derrubar a operação inteira por causa da reconciliação deixaria o admin
	// sem o recurso que ele acabou de configurar. O erro vira log, e a próxima
	// reconciliação — a próxima mutação de regra, ou o próximo boot — alcança.
	if h.fr != nil {
		if err := h.fr.Reconcile(r.Context()); err != nil {
			slog.Error("encaminhamento aplicado, mas a reconciliação das chains falhou; a liberação correspondente pode não estar em vigor até a próxima reconciliação",
				"err", err)
		}
	} else {
		slog.Warn("encaminhamento aplicado sem reconciliação: nenhum reconciliador ligado a este handler")
	}

	saveNftSnapshot(r.Context(), h.db, h.nft)
	return nil
}

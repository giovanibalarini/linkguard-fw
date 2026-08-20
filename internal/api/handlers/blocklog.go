package handlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/giovanibalarini/linkguard-fw/internal/blocklog"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// BlockLogSettingKey é onde mora a escolha do admin de registrar bloqueios.
// Exportada porque o boot (cmd/linkguard-fw) lê a mesma chave para ligar a
// fonte do nftables — duas cópias da string seriam duas verdades.
const BlockLogSettingKey = "firewall_log_blocks"

// BlockLogEnabled lê a opção. Ausente é desligado, que é o estado de toda
// máquina anterior a esta entrega.
func BlockLogEnabled(db *storage.DB) (bool, error) {
	raw, err := db.GetSetting(BlockLogSettingKey)
	if err != nil {
		return false, err
	}
	return raw == "1", nil
}

// BlockLogHandler expõe o registro do que o firewall descartou (#122).
type BlockLogHandler struct {
	db  *storage.DB
	svc *blocklog.Service
	nft *nftables.Service
	fr  reconciler
}

// reconciler é o pedaço do firewallrules.Service que este handler usa: ligar
// ou desligar o registro muda as REGRAS, então precisa reconciliar.
type reconciler interface {
	Reconcile(ctx context.Context) error
}

// NewBlockLogHandler cria o handler.
func NewBlockLogHandler(db *storage.DB, svc *blocklog.Service, nft *nftables.Service, fr reconciler) *BlockLogHandler {
	return &BlockLogHandler{db: db, svc: svc, nft: nft, fr: fr}
}

// Status devolve se o registro está ligado.
func (h *BlockLogHandler) Status(w http.ResponseWriter, r *http.Request) {
	on, err := BlockLogEnabled(h.db)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": on})
}

// SetStatus liga ou desliga o registro e reconcilia as regras.
//
// A reconciliação acontece AQUI e não numa tarefa de fundo: sem ela, a opção
// ficaria gravada e o firewall continuaria sem registrar — o admin marcaria a
// caixa, receberia 200, e a tela de bloqueios seguiria vazia sem explicação.
func (h *BlockLogHandler) SetStatus(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	valor := "0"
	if b.Enabled {
		valor = "1"
	}
	if err := h.db.SetSetting(BlockLogSettingKey, valor); err != nil {
		writeInternalError(w, err)
		return
	}
	if h.fr != nil {
		if err := h.fr.Reconcile(r.Context()); err != nil {
			// A opção já está gravada; o que falhou foi aplicá-la agora. Dizer
			// isso é melhor que fingir sucesso — no próximo boot ela vale.
			writeError(w, http.StatusInternalServerError,
				"opção salva, mas não foi possível aplicar agora: "+err.Error())
			return
		}
	}
	auditAction(h.db, r, "firewall.block_log", "firewall", valor)
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": b.Enabled})
}

// Entries devolve os descartes recentes.
func (h *BlockLogHandler) Entries(w http.ResponseWriter, r *http.Request) {
	limite, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entradas, err := h.svc.Recent(r.Context(), limite, r.URL.Query().Get("q"))
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if entradas == nil {
		entradas = []blocklog.Entry{}
	}
	on, _ := BlockLogEnabled(h.db)
	// O estado da opção vai junto: lista vazia com o registro DESLIGADO é
	// "ninguém pediu para registrar"; lista vazia com ele ligado é "nada foi
	// bloqueado". A tela precisa saber a diferença para não dizer a errada.
	writeJSON(w, http.StatusOK, map[string]any{"enabled": on, "entries": entradas})
}

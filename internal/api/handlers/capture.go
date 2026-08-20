package handlers

import (
	"fmt"
	"net/http"

	"github.com/giovanibalarini/linkguard-fw/internal/pktcapture"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// CaptureHandler expõe a captura de pacotes sob demanda (issue #114).
//
// Toda ação aqui entra no log de auditoria, inclusive o download. Não é
// formalidade: capturar tráfego alheio, mesmo só o cabeçalho, é poder de
// vigilância dentro do produto, e a rastreabilidade de quem usou faz parte da
// feature — não é um extra que se acrescenta depois.
type CaptureHandler struct {
	svc *pktcapture.Service
	db  *storage.DB
}

// NewCaptureHandler cria o handler.
func NewCaptureHandler(svc *pktcapture.Service, db *storage.DB) *CaptureHandler {
	return &CaptureHandler{svc: svc, db: db}
}

// Start dispara uma captura.
func (h *CaptureHandler) Start(w http.ResponseWriter, r *http.Request) {
	var p pktcapture.Params
	if err := decodeJSON(r, &p); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	c, err := h.svc.Start(p, actingUser(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// O filtro vai para a auditoria junto: "fulano capturou" sem dizer o que
	// filtrou não responde a pergunta que se faz ao ler auditoria depois.
	auditAction(h.db, r, "traffic.capture.start", "traffic",
		fmt.Sprintf("%s %ds %s", c.Interface, c.DurationSec, c.FilterExpr))
	writeJSON(w, http.StatusOK, c)
}

// Status devolve a captura atual ou a última, mais se o tcpdump existe na
// máquina — a tela precisa das duas coisas para saber o que oferecer.
func (h *CaptureHandler) Status(w http.ResponseWriter, r *http.Request) {
	c := h.svc.Status()
	resp := map[string]any{
		"available": h.svc.Available(r.Context()),
		"limits": map[string]int{
			"max_duration_sec": pktcapture.MaxDurationSec,
			"max_packets":      pktcapture.MaxPackets,
			"snaplen":          pktcapture.SnapLen,
			"file_ttl_sec":     int(pktcapture.FileTTL.Seconds()),
		},
	}
	if c == nil {
		resp["state"] = "idle"
	} else {
		resp["capture"] = c
		resp["state"] = c.State
	}
	writeJSON(w, http.StatusOK, resp)
}

// Stop aborta a captura em andamento.
func (h *CaptureHandler) Stop(w http.ResponseWriter, r *http.Request) {
	h.svc.Stop()
	auditAction(h.db, r, "traffic.capture.stop", "traffic", "")
	writeJSON(w, http.StatusOK, map[string]bool{"stopped": true})
}

// Download entrega o .pcap da captura corrente.
//
// O identificador NÃO vem da URL de propósito: há uma captura por vez, então o
// servidor já sabe qual é. Parâmetro de caminho aqui seria uma superfície de
// travessia de diretório sem nenhum ganho de funcionalidade.
func (h *CaptureHandler) Download(w http.ResponseWriter, r *http.Request) {
	c := h.svc.Status()
	if c == nil || !c.HasFile {
		writeError(w, http.StatusNotFound, "não há arquivo de captura disponível")
		return
	}
	path, ok := h.svc.FilePath(c.ID)
	if !ok {
		// Chega aqui quando o TTL venceu entre a tela carregar e o clique.
		writeError(w, http.StatusNotFound, "o arquivo da captura expirou")
		return
	}
	auditAction(h.db, r, "traffic.capture.download", "traffic", c.ID)
	name := "linkguard-" + c.ID + ".pcap"
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	http.ServeFile(w, r, path)
}

// Install instala o tcpdump sob demanda.
func (h *CaptureHandler) Install(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.Install(r.Context()); err != nil {
		writeInternalError(w, fmt.Errorf("falha ao instalar tcpdump: %w", err))
		return
	}
	auditAction(h.db, r, "traffic.capture.install", "traffic", "tcpdump")
	writeJSON(w, http.StatusOK, map[string]string{"status": "instalado"})
}

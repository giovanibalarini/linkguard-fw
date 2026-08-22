package handlers

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/metrics"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// A rota de métricas por aparelho (issue #118).
//
// SEPARADA DO /metrics DE PROPÓSITO. Aquele é aberto — sem sessão, sem token —
// e a suíte de validação exige que ele responda pela WAN, porque fechar a porta
// do painel é tranca. Publicar endereço físico e consumo por aparelho ali seria
// um endpoint público de inventário da rede do cliente.
//
// Aqui o acesso é por TOKEN, que é o que um coletor sabe usar: o Prometheus tem
// `bearer_token` no scrape_config, uma linha. E é opt-in de verdade: sem token
// configurado, a rota responde 404 — não "não autorizado", que confirmaria que
// ela existe e convidaria a tentar.

// MetricasHostTokenKey é onde o token vive.
const MetricasHostTokenKey = "metrics_host_token"

// MetricasHostHandler serve as séries por aparelho.
type MetricasHostHandler struct {
	db      *storage.DB
	porHost *metrics.PorHost
}

// NewMetricasHostHandler cria o handler.
func NewMetricasHostHandler(db *storage.DB, p *metrics.PorHost) *MetricasHostHandler {
	return &MetricasHostHandler{db: db, porHost: p}
}

// Servir responde as séries, se o token conferir.
func (h *MetricasHostHandler) Servir(w http.ResponseWriter, r *http.Request) {
	token, err := h.db.GetSetting(MetricasHostTokenKey)
	if err != nil || strings.TrimSpace(token) == "" {
		// 404, e não 403: sem token configurado o recurso não existe. Responder
		// "não autorizado" confirmaria que há algo ali e convidaria a insistir.
		http.NotFound(w, r)
		return
	}
	enviado := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	// Comparação de tempo constante: um `==` aqui vaza o prefixo correto pelo
	// tempo de resposta, e este token dá acesso ao inventário da rede.
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(enviado)), []byte(strings.TrimSpace(token))) != 1 {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "token inválido", http.StatusUnauthorized)
		return
	}
	if h.porHost == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(h.porHost.Exposicao()))
}

// DefinirToken grava (ou apaga) o token da rota de métricas por aparelho.
//
// SEM ISTO A FEATURE NÃO TEM COMO SER LIGADA — e eu entreguei a #118 sem esta
// rota, o que a bateria U mostrou ao não conseguir configurar o token de jeito
// nenhum. Um recurso opt-in sem caminho para o opt-in é um recurso desligado
// com trabalho extra.
//
// Token vazio APAGA: é assim que se desliga, e o desligamento tem de ser tão
// alcançável quanto o ligamento.
func (h *MetricasHostHandler) DefinirToken(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	t := strings.TrimSpace(b.Token)
	if t != "" && len(t) < 16 {
		// Este token dá acesso ao inventário da rede. Um token curto é pior que
		// nenhum: ele dá a sensação de proteção e cede a um laço de tentativas.
		writeError(w, http.StatusBadRequest, "o token precisa de pelo menos 16 caracteres: ele dá acesso à lista de aparelhos da rede")
		return
	}
	if err := h.db.SetSetting(MetricasHostTokenKey, t); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "metrics.host.token", "metrics", map[bool]string{true: "definido", false: "removido"}[t != ""])
	writeJSON(w, http.StatusOK, map[string]bool{"configurado": t != ""})
}

// EstadoToken diz se há token, sem devolvê-lo.
func (h *MetricasHostHandler) EstadoToken(w http.ResponseWriter, r *http.Request) {
	t, err := h.db.GetSetting(MetricasHostTokenKey)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"configurado": strings.TrimSpace(t) != ""})
}

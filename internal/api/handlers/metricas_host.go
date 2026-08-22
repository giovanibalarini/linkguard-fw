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

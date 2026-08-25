package handlers

import (
	"fmt"
	"net/http"

	"github.com/giovanibalarini/linkguard-fw/internal/hostflows"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/validate"
)

// O registro de conversa por host (#115).
//
// EM ARQUIVO PRÓPRIO pelo mesmo motivo do dnsmapa.go: domínio novo vai para
// arquivo novo, e o traffic.go já carrega o histórico por aparelho e o ranking
// de consumo.
//
// POR QUE UMA LEITURA AUDITADA, sendo que nenhuma outra leitura do produto é.
// Hoje só duas mutações escrevem no log de auditoria. Esta consulta é a
// primeira LEITURA a escrever, e é o caso que justifica a exceção: o que ela
// devolve é com quem cada aparelho da rede falou — numa PME, o histórico de
// navegação de cada funcionário. Uma permissão diz quem PODE olhar; só o
// registro diz quem OLHOU. Sem ele, o cliente não tem como responder à única
// pergunta que importa no dia em que alguém reclamar, e o produto vira passivo
// de LGPD para quem o instalou.
type FluxosHandler struct {
	svc *hostflows.Servico
	db  *storage.DB
}

// NewFluxosHandler cria o handler.
func NewFluxosHandler(svc *hostflows.Servico, db *storage.DB) *FluxosHandler {
	return &FluxosHandler{svc: svc, db: db}
}

// Consultar devolve com quem um host falou na janela.
//
// O parâmetro ip é opcional: vazio devolve a rede inteira. O que vai para a
// auditoria é a consulta COM O ALVO dentro — "fulano consultou os destinos de
// 192.168.3.50" é o registro útil; "fulano abriu uma tela" não é.
//
// A auditoria é gravada ANTES da resposta e sem depender do resultado: uma
// consulta que falhou por erro de leitura ainda foi uma consulta feita, e um
// registro que só anota as bem-sucedidas é um registro que se pode driblar.
func (h *FluxosHandler) Consultar(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip != "" && !validate.IPv4(ip) {
		// IPv4 e não net.ParseIP, pela mesma razão da #152: a medição é
		// ipv4_addr, então um endereço IPv6 aqui nunca casaria com tupla
		// nenhuma e a tela responderia "este aparelho não falou com
		// ninguém" — uma afirmação falsa sobre a rede.
		writeError(w, http.StatusBadRequest, "ip inválido: o registro de conversa desta fase é IPv4")
		return
	}
	limite := clampLimit(r.URL.Query().Get("limit"), hostflows.LimitePadrao, hostflows.LimiteMaximo)

	alvo := ip
	if alvo == "" {
		alvo = "rede inteira"
	}
	auditAction(h.db, r, "traffic.flows.read", alvo, "consulta de destinos por host")

	resp, err := h.svc.Consultar(r.Context(), ip, limite)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// GetConfig devolve a configuração do registro e os limites que o servidor
// aceita.
//
// Os limites vão junto de propósito: uma tela que carrega a própria cópia do
// mínimo e do máximo diverge no dia em que um deles muda, e passa a oferecer ao
// admin um valor que o servidor silenciosamente troca por outro.
func (h *FluxosHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.svc.Config()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config":        cfg,
		"janela_minima": nftables.FlowsJanelaMinima,
		"janela_maxima": nftables.FlowsJanelaMaxima,
		"teto_minimo":   nftables.FlowsTetoMinimo,
		"teto_maximo":   nftables.FlowsTetoMaximo,
	})
}

// SetConfig grava a escolha do admin e aplica no kernel.
//
// APLICAR ZERA A JANELA, e a tela precisa avisar ANTES: trocar o timeout de um
// set nft exige derrubá-lo e recriá-lo (ver hostflows.SalvarConfig). Não é
// limitação desta implementação, é o que o nft oferece.
//
// Devolve a configuração EFETIVA, não a que chegou: os valores são limitados no
// servidor, e responder o que o cliente mandou faria a tela mostrar 999999
// minutos onde o kernel aplicou 1440.
func (h *FluxosHandler) SetConfig(w http.ResponseWriter, r *http.Request) {
	var cfg nftables.FlowsConfig
	if err := decodeJSON(r, &cfg); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	wans, err := enabledWANInterfaces(h.db)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if err := h.svc.SalvarConfig(r.Context(), cfg, wans); err != nil {
		writeInternalError(w, err)
		return
	}
	aplicada, err := h.svc.Config()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "traffic.flows.config", "registro de conversa",
		fmt.Sprintf("ligado=%t janela=%dmin teto=%d", aplicada.Ligado, aplicada.JanelaMinutos, aplicada.Teto))
	writeJSON(w, http.StatusOK, aplicada)
}

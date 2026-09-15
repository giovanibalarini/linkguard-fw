package handlers

import "net/http"

// O uplink implícito na tela (#uplink).
//
// POR QUE UM ENDPOINT PRÓPRIO, E NÃO UMA LINHA EM /api/links. A tela de Links
// lista o que o admin cadastrou. O uplink implícito não é cadastro: não tem
// linha em `links`, não tem id, não tem TableID, não tem monitor nem failover,
// e nada nele pode ser editado ou apagado. Devolvê-lo junto da lista faria a
// tela oferecer as ações de link sobre uma coisa que não é link — e, pior,
// convidaria a próxima pessoa a "só criar a linha para simplificar", que é
// exatamente a armadilha que cmd/linkguard-fw/uplink.go existe para não cair.
//
// SOMENTE LEITURA, e sem rota de escrita nenhuma: o que se muda aqui é a
// realidade da máquina, não um registro.
type UplinkView struct {
	// Interface é a placa por onde esta máquina sai. "" quando não se sabe.
	Interface string `json:"interface"`
	// PathMTU é o que o CAMINHO suporta, não o que a placa anuncia. 0 =
	// desconhecido, e a tela tem de dizer "desconhecida" em vez de "0".
	PathMTU int `json:"path_mtu"`
	// Implicito diz que isto saiu da plataforma, e não do cadastro.
	Implicito bool `json:"implicit"`
	// Origem é "platform", "link" ou "none". Redundante com Implicito de
	// propósito: a tela precisa distinguir "veio do cadastro" de "não há
	// uplink nenhum", e um booleano falso não separa os dois.
	Origem string `json:"source"`
	// Plataforma é o que a detecção diz ("oci", "onprem", "unknown"). É o que
	// permite ao operador contestar o veredito sem ler log.
	Plataforma string `json:"platform"`
}

// As três origens possíveis de um uplink.
const (
	UplinkOrigemPlataforma = "platform"
	UplinkOrigemLink       = "link"
	UplinkOrigemNenhuma    = "none"
)

// UplinkHandler serve o uplink efetivo desta máquina.
//
// A FONTE ENTRA COMO FUNÇÃO, pelo mesmo motivo de SetFluxos e SetDomainRouting:
// quem sabe responder isto é cmd/linkguard-fw, que tem o instantâneo da
// plataforma E o banco, e a camada HTTP não pode importar internal/platform
// para descobrir sozinha. Lida a cada requisição, nunca capturada no boot —
// cadastrar um link muda a resposta, e a tela tem de ver a mudança na próxima
// atualização, sem reiniciar nada.
type UplinkHandler struct{ fonte func() UplinkView }

// NewUplinkHandler cria o handler. Fonte nil responde "não sei", que é o
// zero-value permissivo de sempre: um binário que esqueça de ligar a fonte
// mostra a tela sem o cartão, e não uma tela quebrada.
func NewUplinkHandler(fonte func() UplinkView) *UplinkHandler {
	return &UplinkHandler{fonte: fonte}
}

func (h *UplinkHandler) Get(w http.ResponseWriter, r *http.Request) {
	if h.fonte == nil {
		writeJSON(w, http.StatusOK, UplinkView{Origem: UplinkOrigemNenhuma, Plataforma: "unknown"})
		return
	}
	writeJSON(w, http.StatusOK, h.fonte())
}

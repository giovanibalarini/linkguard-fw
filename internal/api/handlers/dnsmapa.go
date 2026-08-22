package handlers

import (
	"net/http"

	"github.com/giovanibalarini/linkguard-fw/internal/dnstap"
)

// O mapa endereço → nome (issue #116).
//
// EM ARQUIVO PRÓPRIO POR CAUSA DE UMA GUARDA, e a guarda estava certa. O
// netsvc.go bateu no teto de pacotes internos por arquivo
// (TestPackageBoundary), que existe para a camada HTTP não voltar a inchar sem
// ninguém notar. Levantar o teto seria a saída fácil; o que ele está pedindo é
// que domínio novo vá para arquivo novo.

// mapaDeDominios é o que o handler precisa do mapa, e existe como interface
// LOCAL para o netsvc.go não ter de importar internal/dnstap só por causa de um
// campo — era isso que estourava o teto de pacotes internos por arquivo.
type mapaDeDominios interface {
	Estado() dnstap.Estado
	Amostra(n int) []dnstap.Entrada
}

// SetDNSMapa liga o mapa endereço → nome. Opcional: um binário sem coletor de
// dnstap continua respondendo a tela com "desligado".
func (h *NetsvcHandler) SetDNSMapa(m mapaDeDominios) { h.dnsMapa = m }

// MapaDeDominios devolve o que o produto aprendeu de endereço → nome (#116).
//
// Sem isto, todo destino em toda tela é número: o registro de fluxo mostraria
// 142.250.x.x e o admin não conseguiria ler a própria rede.
//
// O ESTADO VEM JUNTO, e não é enfeite: o mapa tem teto, e quando ele enche o
// mais antigo sai. Sem dizer isso, um endereço ausente parece "nunca foi
// consultado" quando pode ser "foi, e saiu para caber outro" — e quem diagnostica
// tira a conclusão errada com a tela concordando.
func (h *NetsvcHandler) MapaDeDominios(w http.ResponseWriter, r *http.Request) {
	if h.dnsMapa == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ligado":  false,
			"estado":  dnstap.Estado{},
			"amostra": []any{},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ligado":  h.getConfig().DNSTapEnabled,
		"estado":  h.dnsMapa.Estado(),
		"amostra": h.dnsMapa.Amostra(200),
	})
}

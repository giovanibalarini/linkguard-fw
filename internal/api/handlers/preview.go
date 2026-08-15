package handlers

import (
	"net/http"

	"github.com/giovanibalarini/linkguard-fw/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// A pré-visualização é renderizada AQUI, pelo mesmo código que monta a linha
// que vai para o kernel, e não remontada em TypeScript no navegador.
//
// Enquanto o frontend tinha a sua própria cópia, os dois lados carregavam um
// comentário dizendo que a ordem dos campos não era estética — e nada verificava
// que continuavam iguais. A divergência seria assintomática: nenhum teste
// falharia, nenhum log registraria, nenhum apply daria erro. A tela afirmaria
// que a regra faz X enquanto o kernel recebe Y, num painel em que uma regra
// errada corta o SSH do operador.
//
// São endpoints de leitura pura: não tocam banco nem nftables, só renderizam o
// que foi submetido.

// PreviewRule devolve a linha nft que a regra submetida geraria.
func (h *NftablesHandler) PreviewRule(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Action string `json:"action"`
		Iif    string `json:"iif"`
		Oif    string `json:"oif"`
		Saddr  string `json:"saddr"`
		Daddr  string `json:"daddr"`
		Proto  string `json:"proto"`
		Dport  string `json:"dport"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	rendered, err := nftables.RenderRule(nftables.RuleFields{
		Action: b.Action, Iif: b.Iif, Oif: b.Oif,
		Saddr: b.Saddr, Daddr: b.Daddr, Proto: b.Proto, Dport: b.Dport,
	})
	if err != nil {
		// Campo inválido não é erro de servidor: a tela mostra o motivo no
		// lugar da linha, enquanto o operador ainda está digitando.
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"rendered": rendered})
}

// PreviewGroup devolve a linha de jump que o grupo submetido geraria na chain
// hospedeira.
func (h *NftablesHandler) PreviewGroup(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ChainName   string `json:"chain_name"`
		CondIif     string `json:"cond_iif"`
		CondSaddr   string `json:"cond_saddr"`
		CondDaddr   string `json:"cond_daddr"`
		Kind        string `json:"kind"`
		Scope       string `json:"scope"`
		ConnState   string `json:"conn_state"`
		Fallthrough string `json:"fallthrough"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	// Um grupo ainda não salvo não tem chain_name; a tela mostra o placeholder
	// que o backend também usaria, em vez de o render falhar.
	chain := b.ChainName
	if chain == "" {
		chain = "grp_…"
	}
	rendered, err := nftables.RenderGroupJump(firewallrules.ToStoredGroup(storage.FirewallGroup{
		ChainName: chain, CondIif: b.CondIif, CondSaddr: b.CondSaddr, CondDaddr: b.CondDaddr,
		Kind: b.Kind, Scope: b.Scope, ConnState: b.ConnState, Fallthrough: b.Fallthrough,
	}))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"rendered": rendered})
}

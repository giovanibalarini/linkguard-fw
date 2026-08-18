package handlers

// A postura do firewall: liberar por padrão ou bloquear por padrão (issue #78).
//
// Esta é a mudança mais perigosa que o produto sabe fazer, e por isso ela passa
// pelo MESMO caminho das outras dez mutações (firewallrules.ApplyGuarded, issue
// #20): validar, trava, pré-voo `nft -c`, armar a janela de 90 segundos, gravar,
// auditar, reconciliar — com reversão automática se ninguém confirmar.
//
// Ela declara Window() = true SEMPRE. As outras mutações perguntam se alcançam a
// chain input; esta É a chain input. Não existe troca de postura que não mereça
// a rede.

import (
	"net/http"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

type policyResponse struct {
	Policy string `json:"policy"`
	// Pending descreve a janela aberta, quando a troca acabou de ser aplicada.
	Pending *pendingView `json:"pending,omitempty"`
}

// GetInputPolicy devolve a postura atual.
func (h *NftablesHandler) GetInputPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := h.fr.InputPolicy()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, policyResponse{Policy: string(p)})
}

// SetInputPolicy troca a postura, sob a janela de confirmação.
func (h *NftablesHandler) SetInputPolicy(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Policy string `json:"policy"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	nova := nftables.Policy(b.Policy)

	atual, err := h.fr.InputPolicy()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if atual == nova {
		// Sem mudança, sem janela. Armar uma janela para uma troca que não
		// muda nada trancaria a edição do firewall por 90 segundos à toa — e
		// pediria ao operador que confirmasse o acesso que ele nunca perdeu.
		writeJSON(w, http.StatusOK, policyResponse{Policy: string(atual)})
		return
	}

	out, ok := h.applyGuarded(w, r, mutation{
		validate: func() error {
			if !nova.Valid() {
				return errPolicyInvalida(b.Policy)
			}
			return nil
		},
		// Sem preflight próprio: reconcileGroups já valida a chain input INTEIRA
		// com o mesmo renderizador, e a política agora faz parte dele. Um
		// pré-voo daqui validaria a mesma coisa duas vezes.
		window: func() (bool, string) {
			// SEMPRE. As outras mutações perguntam se alcançam a input; esta é
			// a input.
			if nova == nftables.PolicyDrop {
				return true, "mudança da postura do firewall para BLOQUEAR por padrão"
			}
			return true, "mudança da postura do firewall para liberar por padrão"
		},
		write: func() error { return h.fr.SetInputPolicy(nova) },
		audit: func() (string, string, string) {
			return "nft.policy.set", "input", string(atual) + " → " + string(nova)
		},
	})
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, policyResponse{
		Policy:  string(nova),
		Pending: h.pendingViewOf(out),
	})
}

func errPolicyInvalida(v string) error {
	return &policyInvalidaErr{v}
}

type policyInvalidaErr struct{ v string }

func (e *policyInvalidaErr) Error() string {
	return "postura inválida: use \"accept\" (liberar por padrão) ou \"drop\" (bloquear por padrão); veio " + e.v
}

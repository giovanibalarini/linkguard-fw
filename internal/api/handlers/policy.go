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
	// Policy é a postura do tráfego destinado ao PRÓPRIO firewall.
	Policy string `json:"policy"`
	// Forward é a postura do tráfego que ATRAVESSA o firewall — a que responde
	// "esse aparelho não sai para a internet" (issue #92).
	Forward string `json:"forward"`
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
	fw, err := h.fr.ForwardPolicy()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, policyResponse{Policy: string(p), Forward: string(fw)})
}

// SetInputPolicy troca a postura, sob a janela de confirmação.
func (h *NftablesHandler) SetInputPolicy(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Policy string `json:"policy"`
		// Chain escolhe a postura: "forward" (o que atravessa) ou "input" (o que
		// chega ao próprio firewall). Vazio é forward, porque é o que o admin
		// quer dizer em 9 de cada 10 vezes que fala em "bloquear tudo" — blindar
		// o acesso à própria caixa é a decisão rara e deliberada.
		Chain string `json:"chain"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	nova := nftables.Policy(b.Policy)
	forward := b.Chain != "input"

	ler := h.fr.InputPolicy
	gravar := h.fr.SetInputPolicy
	qual := "para o próprio firewall"
	if forward {
		ler = h.fr.ForwardPolicy
		gravar = h.fr.SetForwardPolicy
		qual = "que atravessa o firewall"
	}

	atual, err := ler()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if atual == nova {
		// Sem mudança, sem janela. Armar uma janela para uma troca que não
		// muda nada trancaria a edição do firewall por 90 segundos à toa — e
		// pediria ao operador que confirmasse o acesso que ele nunca perdeu.
		h.GetInputPolicy(w, r)
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
			// SEMPRE, para as duas chains. As outras mutações perguntam se
			// alcançam a chain input; uma troca de postura MUDA a chain inteira,
			// e a da forward derruba a rede toda se estiver errada.
			verbo := "liberar"
			if nova == nftables.PolicyDrop {
				verbo = "BLOQUEAR"
			}
			return true, "mudança da postura do tráfego " + qual + " para " + verbo + " por padrão"
		},
		write: func() error { return gravar(nova) },
		audit: func() (string, string, string) {
			alvo := "input"
			if forward {
				alvo = "forward"
			}
			return "nft.policy.set", alvo, string(atual) + " → " + string(nova)
		},
	})
	if !ok {
		return
	}
	// A resposta é montada com o que ACABOU de ser gravado, e a outra chain é
	// relida. Um erro de leitura aqui não vira 500: a mutação já foi aplicada e
	// confirmada, e responder erro faria a tela reverter o que está valendo na
	// máquina. O campo sai vazio, e o poll seguinte o preenche.
	resp := policyResponse{Pending: h.pendingViewOf(out)}
	if forward {
		resp.Forward = string(nova)
		if p, err := h.fr.InputPolicy(); err == nil {
			resp.Policy = string(p)
		}
	} else {
		resp.Policy = string(nova)
		if p, err := h.fr.ForwardPolicy(); err == nil {
			resp.Forward = string(p)
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func errPolicyInvalida(v string) error {
	return &policyInvalidaErr{v}
}

type policyInvalidaErr struct{ v string }

func (e *policyInvalidaErr) Error() string {
	return "postura inválida: use \"accept\" (liberar por padrão) ou \"drop\" (bloquear por padrão); veio " + e.v
}

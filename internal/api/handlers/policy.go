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
	// Survival é o que continua passando quando a postura é restritiva, por
	// chain. Vem do renderizador, não de uma lista escrita à mão na tela: a
	// porta do painel, as redes da LAN e a linha do cliente DHCP dependem
	// desta máquina, e uma tela que as adivinhe mente exatamente na frase que
	// o operador lê para decidir se continua entrando (issue #94).
	Survival *survivalView `json:"survival,omitempty"`
	// Pending descreve a janela aberta, quando a troca acabou de ser aplicada.
	Pending *pendingView `json:"pending,omitempty"`
	// Exposure é o que o firewall deixa passar HOJE, dito em vez de omitido
	// (issue #119, fase 3). As duas primeiras fases mexeram em regra; esta
	// mexe em afirmação — o ruleset passou a proteger mais e a tela continuou
	// descrevendo um firewall que não é o que está rodando.
	Exposure *nftables.Exposure `json:"exposure,omitempty"`
}

type survivalView struct {
	Input   []string `json:"input"`
	Forward []string `json:"forward"`
	// Error explica por que uma das listas veio vazia. O painel mostra o
	// aviso em vez de desenhar uma lista curta como se fosse a verdade.
	Error string `json:"error,omitempty"`
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
	sv := &survivalView{}
	inp, fwd, serr := h.svc.SurvivalPreview()
	sv.Input, sv.Forward = inp, fwd
	if serr != nil {
		sv.Error = serr.Error()
	}
	// A exposição sai das MESMAS fontes que escrevem a chain (ver ExposureNow):
	// uma tela com a própria cópia da verdade divergiria em silêncio, que é o
	// defeito que a fase 3 existe para fechar.
	exp := h.svc.ExposureNow()
	writeJSON(w, http.StatusOK, policyResponse{
		Policy: string(p), Forward: string(fw), Survival: sv, Exposure: &exp,
	})
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

// SetWANManagement fecha ou reabre as portas de gerência no que chega pelas
// WANs (#119, fase 3b).
//
// É A ÚNICA MUTAÇÃO DO PRODUTO QUE PODE CORTAR O ACESSO DE QUEM A FEZ SEM QUE
// ELE PERCEBA NA HORA. Quem fecha a gerência estando na LAN não sente nada — a
// sessão dele não passa pela regra — e descobre no dia em que precisar entrar de
// fora, que costuma ser o dia em que já não dá para entrar de dentro.
//
// Por isso ela passa pela janela de confirmação como a troca de postura, e por
// isso o flag entra no stateSnapshot (internal/firewallrules/confirm.go): sem
// isso a janela armaria, o prazo venceria, e as portas continuariam fechadas
// sem nada apontando para elas.
func (h *NftablesHandler) SetWANManagement(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Closed bool `json:"closed"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	atual, err := h.fr.WANMgmtClosed()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if atual == b.Closed {
		// Sem mudança, sem janela — mesma razão da troca de postura: armar 90
		// segundos para uma troca que não muda nada tranca a edição do firewall
		// à toa e pede confirmação de um acesso que ninguém perdeu.
		h.GetInputPolicy(w, r)
		return
	}

	if _, ok := h.applyGuarded(w, r, mutation{
		window: func() (bool, string) {
			// Só o FECHAMENTO é perigoso; reabrir devolve acesso. Mas a janela
			// vale para os dois, porque reabrir também é mudança de postura de
			// borda e o operador merece o mesmo aviso — e porque uma janela que
			// aparece só às vezes ensina a ignorá-la.
			if b.Closed {
				return true, "fechamento das portas de gerência no que chega pelas WANs"
			}
			return true, "reabertura das portas de gerência no que chega pelas WANs"
		},
		write: func() error { return h.fr.SetWANMgmtClosed(b.Closed) },
		audit: func() (string, string, string) {
			de, para := "aberta", "fechada"
			if !b.Closed {
				de, para = "fechada", "aberta"
			}
			return "nft.wan_management.set", "input", de + " → " + para
		},
	}); !ok {
		return
	}
	h.GetInputPolicy(w, r)
}

// SetEdgeContainment liga ou desliga a contenção de tentativa repetida na borda
// (#127).
//
// NÃO passa pela janela de confirmação, e a diferença em relação ao fechamento
// da gerência é real: fechar corta o acesso na hora, e a janela existe para
// desfazer isso. A contenção só corta SE alguém exceder a taxa depois — a janela
// de 90 segundos teria vencido muito antes, e pedir confirmação de um risco que
// ainda não se manifestou ensina a confirmar sem ler.
//
// A saída de emergência aqui é outra: quem está contido aparece no painel e pode
// ser liberado num clique, e a contenção expira sozinha em uma hora.
func (h *NftablesHandler) SetEdgeContainment(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	if err := h.fr.SetEdgeContainment(b.Enabled); err != nil {
		writeInternalError(w, err)
		return
	}
	if err := h.svc.ReconcileInputProtection(r.Context()); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "nft.edge_containment.set", "input", map[bool]string{true: "ligada", false: "desligada"}[b.Enabled])
	h.GetInputPolicy(w, r)
}

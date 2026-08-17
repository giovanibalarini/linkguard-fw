package handlers

// A ponte entre a camada HTTP e a ordem do confirmar-ou-reverte (issue #20).
//
// Antes disto, cada uma das dez mutações de grupo e regra executava a sequência
// de oito passos à mão, e cada passo recebia o http.ResponseWriter — o que
// prendia a rede de segurança do firewall dentro de um handler. A ordem agora
// mora em firewallrules.ApplyGuarded; o que sobra aqui é o que de fato é HTTP:
// montar a Mutation a partir do corpo, e traduzir a ETAPA em que ela parou num
// código de status.
//
// A tradução acontece numa função só (writeGuardError). É ela que faz valer a
// promessa da issue: um status novo, ou uma frase nova, muda num lugar em vez
// de dez.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/giovanibalarini/linkguard-fw/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// asGuardError isola o errors.As para que writeGuardError leia como a tabela
// de tradução que ela é.
func asGuardError(err error, target **firewallrules.GuardError) bool {
	return errors.As(err, target)
}

// mutation monta um firewallrules.Mutation a partir de closures, que é como o
// handler o descreve sem precisar de um tipo por rota.
//
// Os campos estão na ordem em que ApplyGuarded os chama, de propósito: quem
// escrever a próxima mutação lê a sequência de cima para baixo.
type mutation struct {
	validate  func() error
	preflight func(ctx context.Context) error
	window    func() (bool, string)
	write     func() error
	audit     func() (string, string, string)
}

func (m mutation) Validate() error {
	if m.validate == nil {
		return nil
	}
	return m.validate()
}

func (m mutation) Preflight(ctx context.Context) error {
	if m.preflight == nil {
		return nil
	}
	return m.preflight(ctx)
}

// Window sem closure é "não alcança a chain input" — o padrão certo: uma
// mutação que esqueça de declarar não passa a abrir janela por acidente, ela
// deixa de abrir. O erro nessa direção trava a edição do firewall à toa; na
// outra, deixaria uma mudança de input valendo sem reversão automática.
//
// Nenhuma mutação de input depende desse padrão: todas declaram.
func (m mutation) Window() (bool, string) {
	if m.window == nil {
		return false, ""
	}
	return m.window()
}

func (m mutation) Write() error { return m.write() }

func (m mutation) Audit() (string, string, string) {
	if m.audit == nil {
		return "", "", ""
	}
	return m.audit()
}

// applyGuarded roda a ordem para m e responde ao cliente em caso de erro.
//
// Devolve o resultado e `true` quando a mutação passou; em caso de erro a
// resposta JÁ FOI escrita e o chamador só retorna.
func (h *NftablesHandler) applyGuarded(w http.ResponseWriter, r *http.Request, m mutation) (*firewallrules.Applied, bool) {
	hooks := firewallrules.Hooks{
		Audit: func(action, resource, details string) {
			if action == "" {
				return
			}
			auditAction(h.db, r, action, resource, details)
		},
		SnapshotNft: func() { saveNftSnapshot(r.Context(), h.db, h.svc) },
	}

	out, err := h.fr.ApplyGuarded(r.Context(), actingUser(r), m, hooks)
	if err != nil {
		writeGuardError(w, err)
		return nil, false
	}
	return out, true
}

// preflightGroups é o pré-voo das mutações de GRUPO: lê o conjunto atual,
// deixa mutate desenhar como ele ficaria, e pergunta ao próprio nft se aquilo
// é aceitável.
//
// É o antigo checkPendingGroups sem o http.ResponseWriter. A diferença não é
// cosmética: sem o writer ele devolve erro em vez de responder, que é o que
// permite a ApplyGuarded decidir o que fazer — e é o que torna o passo
// alcançável por um caminho de mutação que não seja uma requisição.
func (h *NftablesHandler) preflightGroups(ctx context.Context, mutate func([]nftables.StoredGroup) []nftables.StoredGroup) error {
	current, err := h.fr.StoredGroups()
	if err != nil {
		return err
	}
	return h.fr.CheckPendingGroups(ctx, mutate(current))
}

// preflightRules é o mesmo para as mutações de REGRA: o candidato é montado a
// partir da lista de regras, e StoredGroupsWithRules o converte no conjunto de
// grupos que o nft vai conferir — porque uma regra só existe dentro da chain de
// um grupo.
func (h *NftablesHandler) preflightRules(ctx context.Context, mutate func([]storage.FirewallRule) []storage.FirewallRule) error {
	current, err := h.db.ListFirewallRules()
	if err != nil {
		return err
	}
	candidate, err := h.fr.StoredGroupsWithRules(mutate(current))
	if err != nil {
		return err
	}
	return h.fr.CheckPendingGroups(ctx, candidate)
}

// pendingViewOf desenha a faixa da janela que a mutação acabou de armar, ou
// nil quando ela não armou nenhuma.
//
// O aviso de "só conexões novas" é recalculado AQUI, e não onde a janela foi
// armada, porque a ordem obrigatória é armar ANTES de aplicar: lá o banco ainda
// é o estado anterior, e a resposta sairia dizendo que nada mudou justamente
// para a mutação que acabou de restringir o grupo. Neste ponto a escrita e a
// reconciliação já aconteceram — e a faixa aparece com o aviso no mesmo instante
// em que o operador salva, não no poll seguinte.
func (h *NftablesHandler) pendingViewOf(out *firewallrules.Applied) *pendingView {
	if out == nil || out.Pending == nil {
		return nil
	}
	v := h.pendingView(out.Pending)
	if v != nil {
		v.NewConnectionsOnly = h.newConnectionsOnly(out.Pending.Snapshot)
	}
	return v
}

// writeGuardError é a tradução de etapa em status, e o único lugar onde ela
// acontece.
//
// Os status não são intercambiáveis, e cada um responde a uma pergunta
// diferente do operador:
//
//	400 — "o que você mandou não serve" (campos, ou o nft recusando o
//	      resultado). Nada foi tocado.
//	409 — "não é a sua vez": há uma janela aberta. É conflito de ESTADO, não
//	      erro do pedido, e a mensagem nomeia a mudança e quem a aplicou,
//	      porque é isso que ele precisa para decidir entre confirmar e reverter.
//	500 — algo do lado do servidor não deu certo. Aqui a FRASE importa mais
//	      que o número: ela é a diferença entre "nada mudou" e "pode ter
//	      ficado pela metade, o LinkGuard está tentando reverter" — e é ela
//	      que diz se ele precisa ir olhar o firewall à mão.
func writeGuardError(w http.ResponseWriter, err error) {
	var g *firewallrules.GuardError
	if !asGuardError(err, &g) {
		// Não deveria acontecer: ApplyGuarded devolve GuardError em todo
		// caminho de erro. Se acontecer, o genérico é o lado seguro.
		slog.Error("erro sem etapa vindo de ApplyGuarded", "err", err)
		writeInternalError(w, err)
		return
	}

	switch g.Stage {
	case firewallrules.StageValidate, firewallrules.StagePreflight:
		writeError(w, http.StatusBadRequest, g.Message)

	case firewallrules.StageLocked:
		writeError(w, http.StatusConflict, g.Message)

	case firewallrules.StageWrite:
		// A causa técnica (erro de banco) não vai para a tela — writeInternalError
		// existe justamente para não vazar caminho de arquivo e erro de SQL para
		// quem está no painel. O log fica com tudo.
		slog.Error("a escrita da mutação falhou; a janela foi descartada e nada mudou", "err", g.Err)
		writeInternalError(w, g.Err)

	case firewallrules.StageWindow, firewallrules.StageReconcile, firewallrules.StageStuck:
		slog.Error("mutação de firewall interrompida", "etapa", g.Stage.String(), "err", g.Err)
		writeError(w, http.StatusInternalServerError, g.Message)

	default:
		writeInternalError(w, g.Err)
	}
}

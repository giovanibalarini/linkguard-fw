package firewallrules

// ApplyGuarded — a ordem obrigatória do confirmar-ou-reverte, num lugar só
// (issue #20).
//
// O QUE ESTAVA ERRADO. Toda mutação de grupo e de regra executava À MÃO a mesma
// sequência de oito passos: validar → trava → ler o estado → pré-voo `nft -c` →
// decidir se alcança a input → armar a janela → gravar no banco → auditar →
// reconciliar, com o desfazer certo em cada ponto de falha. Eram dez cópias, em
// nftables.go e groups.go, cada uma com um comentário explicando por que a
// ordem é aquela.
//
// Essa ordem NÃO é organização de código: é a rede que impede o operador de se
// trancar fora da máquina. Cada cópia era uma chance de inverter dois passos, e
// o repositório já registra uma vez em que isso aconteceu (groups.go:165, "C-5:
// validar ANTES de qualquer leitura do banco").
//
// E, por receberem `http.ResponseWriter`, os passos só existiam DENTRO de um
// handler HTTP. Nenhum outro caminho de mutação — uma CLI de recuperação, um
// apply agendado, o restore de backup — conseguia herdá-los, e nenhum dos dez
// era exercitável sem montar uma requisição.
//
// O QUE ESTA FUNÇÃO É. A sequência, uma vez. Ela não sabe o que é HTTP: recebe
// uma Mutation (o que muda) e devolve um erro tipado por ETAPA. Quem traduz
// etapa em status é a camada HTTP, num lugar só.
//
// O QUE ELA DELIBERADAMENTE NÃO FAZ. Não escreve auditoria nem salva snapshot
// do nft por conta própria: as duas coisas dependem de quem está pedindo (o
// usuário e o IP da requisição) e de um *storage.DB que este pacote não deve
// passar a carregar. Elas entram por Hooks, que o chamador preenche.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
)

// Mutation é uma alteração de firewall que precisa passar pela ordem.
//
// Os métodos são a ordem, na sequência em que ApplyGuarded os chama. Quem
// implementa não decide QUANDO cada um roda — essa é a inversão que a issue
// pedia, e é ela que impede a próxima cópia de nascer com dois passos trocados.
type Mutation interface {
	// Validate confere os campos. Roda ANTES de qualquer leitura do banco:
	// com o banco fora do ar, um corpo inválido virava 500 e o admin não
	// ficava sabendo que o problema era o que ele mandou (C-5).
	Validate() error

	// Preflight é o `nft -c` sobre o estado que EXISTIRIA depois desta
	// mutação. Cada tipo de mutação monta o seu candidato (o conjunto
	// completo de grupos, ou o de regras) e chama a checagem do serviço —
	// por isso o passo é da Mutation e não daqui.
	Preflight(ctx context.Context) error

	// Window diz se esta mutação alcança a chain input (e portanto exige a
	// janela de confirmação) e o resumo que o operador lê na faixa.
	//
	// Consultada DEPOIS do pré-voo e ANTES da escrita: é nesse intervalo que
	// o banco ainda é o estado anterior, que é o que o snapshot precisa ser.
	Window() (needed bool, summary string)

	// Write grava no banco. Precisa ser atômica — uma linha só, ou uma
	// transação. É o que autoriza StageWrite a apenas descartar a janela em
	// vez de rodar a reversão inteira (N-3).
	Write() error

	// Audit descreve o que aconteceu, para a linha de auditoria.
	Audit() (action, resource, details string)
}

// Hooks são os efeitos que dependem de quem pediu, e que por isso não moram
// aqui dentro.
type Hooks struct {
	// Audit grava a linha de auditoria da mutação. Chamado DEPOIS da escrita
	// e ANTES da reconciliação, que é onde as dez cópias o chamavam.
	Audit func(action, resource, details string)

	// SnapshotNft guarda o ruleset vivo depois de uma reconciliação
	// bem-sucedida. Opcional.
	SnapshotNft func()
}

// Stage é a etapa em que a mutação parou. É o que a camada HTTP traduz em
// status — e ter um tipo para isso é o que faz a tradução acontecer num lugar
// só, em vez de dez.
type Stage int

const (
	StageValidate  Stage = iota // campos inválidos
	StageLocked                 // há uma janela aberta; a mutação nem começou
	StagePreflight              // o `nft -c` recusou o estado resultante
	StageWindow                 // não foi possível ARMAR a janela; nada foi aplicado
	StageWrite                  // a escrita no banco falhou; a janela foi descartada
	StageReconcile              // o firewall vivo recusou; o estado anterior VOLTOU
	StageStuck                  // o firewall recusou E a reversão não concluiu
)

func (s Stage) String() string {
	switch s {
	case StageValidate:
		return "validação"
	case StageLocked:
		return "trava do confirmar-ou-reverte"
	case StagePreflight:
		return "pré-voo nft -c"
	case StageWindow:
		return "arme da janela"
	case StageWrite:
		return "escrita no banco"
	case StageReconcile:
		return "reconciliação"
	case StageStuck:
		return "reconciliação e reversão"
	}
	return "desconhecida"
}

// GuardError é a falha de uma mutação, com a etapa e a frase que o operador
// deve ler.
//
// A frase vem de dentro porque ela não é decoração: em StageReconcile ela é a
// diferença entre "erro interno do servidor" e "nada mudou, o estado anterior
// foi restaurado" — e essa distinção é o que diz ao operador se ele precisa ir
// conferir o firewall à mão.
type GuardError struct {
	Stage   Stage
	Message string // para o operador
	Err     error  // a causa técnica, para o log
}

func (e *GuardError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Stage, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Stage, e.Message)
}

func (e *GuardError) Unwrap() error { return e.Err }

// StageOf devolve a etapa em que err parou, e se err é mesmo um GuardError.
func StageOf(err error) (Stage, bool) {
	var g *GuardError
	if errors.As(err, &g) {
		return g.Stage, true
	}
	return 0, false
}

// Applied é o resultado de uma mutação que deu certo.
type Applied struct {
	// WindowID é a janela que ESTA mutação armou, ou "" quando ela não
	// precisou de janela (o caso de toda mutação que não alcança a input).
	WindowID string

	// Pending é o pendente relido para desenhar a faixa, ou nil quando não há
	// janela — ou quando a releitura falhou, que NÃO é motivo para abortar
	// (ver o comentário em armWindow).
	Pending *pendingSnapshot
}

// pendingSnapshot é o que o chamador precisa saber do pendente recém-armado
// sem ter de reler o banco.
type pendingSnapshot struct {
	ID        string
	Summary   string
	Snapshot  string
	ExpiresAt int64
}

// ApplyGuarded executa a ordem obrigatória para m.
//
// A ordem, e o porquê de cada posição, está nos comentários de cada bloco. O
// resumo: nada toca o banco antes de o `nft -c` aprovar; a janela é armada
// antes da escrita (para o snapshot ser o estado anterior de verdade); e todo
// caminho de erro depois do arme desfaz a janela, porque uma janela esquecida
// tranca a edição do firewall por 90 segundos à toa.
func (s *Service) ApplyGuarded(ctx context.Context, by string, m Mutation, hooks Hooks) (*Applied, error) {
	// 1. Validar. Antes de qualquer leitura do banco (C-5).
	if err := m.Validate(); err != nil {
		return nil, &GuardError{Stage: StageValidate, Message: err.Error(), Err: err}
	}

	// 2. A trava. Uma janela aberta bloqueia toda mutação de grupo e regra:
	// com duas mudanças pendentes, "reverter ao estado anterior" não teria
	// resposta (spec §5.3).
	if err := s.guardWindowOpen(); err != nil {
		return nil, err
	}

	// 3. O pré-voo. `nft -c` sobre o estado resultante, com o banco ainda
	// intocado: uma regra que o nft recusa é recusada ANTES de existir.
	if err := m.Preflight(ctx); err != nil {
		return nil, &GuardError{Stage: StagePreflight, Message: err.Error(), Err: err}
	}

	// 4. Armar a janela, ainda antes da escrita. O snapshot tirado aqui é o
	// estado anterior DE VERDADE; tirado depois, ele já conteria a mudança.
	needed, summary := m.Window()
	applied, err := s.armWindow(ctx, by, needed, summary)
	if err != nil {
		return nil, err
	}

	// 5. Escrever. A partir daqui todo erro tem de desfazer a janela.
	if err := m.Write(); err != nil {
		// Só descartar, e não reverter: a escrita é atômica, então não sobrou
		// meia mudança para desfazer. Rodar a reversão inteira aqui mandaria
		// dez comandos ao nft — flush das chains e reconstrução — por causa de
		// um erro que não alterou uma linha do banco (N-3).
		s.discardWindow(ctx, applied.WindowID, err)
		return nil, &GuardError{
			Stage:   StageWrite,
			Message: "não foi possível gravar a alteração; nada mudou",
			Err:     err,
		}
	}

	// 6. Auditar. Depois da escrita e antes da reconciliação, como nas dez
	// cópias — o histórico registra a intenção que já virou estado.
	if hooks.Audit != nil {
		action, resource, details := m.Audit()
		hooks.Audit(action, resource, details)
	}

	// 7. Registrar o estado pós-mutação (issue #20a) e reconciliar.
	return s.reconcileGuarded(ctx, applied, hooks)
}

// guardWindowOpen é o passo 2, e ele LIBERA no estado "revertendo".
//
// Essa liberação é a diferença entre um mecanismo de segurança e um beco sem
// saída (N-2): quando a reversão já restaurou o estado anterior no banco, o
// trabalho terminou na camada que manda, e toda mutação seguinte também
// reconcilia. Travando, uma máquina cuja reconciliação falha prendia o operador
// sem saída — não dava para apagar a regra que quebra o reconcile, nem
// desligar o grupo, nem confirmar, nem reverter, e o reboot repetia tudo.
func (s *Service) guardWindowOpen() error {
	p, err := s.PendingChangeOrError()
	if err != nil {
		return &GuardError{
			Stage:   StageLocked,
			Message: "não foi possível verificar se há uma mudança aguardando confirmação",
			Err:     err,
		}
	}
	if p == nil {
		return nil
	}
	if p.Reverting() {
		// Quem PROVA que a reversão terminou no banco é RevertSettled, que
		// compara linha por linha: a marca de "revertendo" sozinha não basta.
		settled, err := s.RevertSettled(p)
		if err != nil {
			// Não deu para provar: fail closed.
			return &GuardError{
				Stage:   StageLocked,
				Message: "não foi possível confirmar o estado da reversão em andamento; tente de novo em alguns segundos",
				Err:     err,
			}
		}
		if settled {
			return nil
		}
	}
	return &GuardError{
		Stage: StageLocked,
		Message: fmt.Sprintf(
			"há uma mudança de firewall aguardando confirmação (%q, aplicada por %s): confirme ou reverta antes de aplicar outra",
			p.Summary, p.AppliedBy),
	}
}

// armWindow é o passo 4. Devolve Applied com WindowID vazio quando a mutação
// não precisa de janela — que é o caso de toda mutação que não alcança a input.
func (s *Service) armWindow(ctx context.Context, by string, needed bool, summary string) (*Applied, error) {
	if !needed {
		return &Applied{}, nil
	}
	id, err := s.OpenConfirmWindow(ctx, by, summary)
	if err != nil {
		if IsWindowConflict(err) {
			// Outra janela nasceu entre a trava e aqui. Nada foi aplicado.
			return nil, &GuardError{Stage: StageLocked, Message: err.Error(), Err: err}
		}
		return nil, &GuardError{
			Stage: StageWindow,
			Message: "a janela de confirmação não pôde ser aberta e a alteração NÃO foi aplicada: " +
				"sem ela não haveria reversão automática se o acesso ao firewall se perdesse. Tente de novo.",
			Err: err,
		}
	}

	out := &Applied{WindowID: id}

	// Reler o pendente é para desenhar a faixa. Falhar AQUI não aborta nada: a
	// janela está armada, a mudança vai ser aplicada com rede embaixo, e o
	// painel busca o pendente pelo GET assim que monta.
	p, err := s.PendingChangeOrError()
	if err != nil {
		slog.Error("janela de confirmação aberta, mas não foi possível reler o pendente para a resposta", "err", err)
		return out, nil
	}
	if p == nil || p.ID != id {
		// O pendente que voltou já é outro: entre o arme e esta releitura a
		// nossa janela foi resolvida e outra foi aberta. Desenhar a faixa com
		// ELE mostraria ao operador a contagem de uma mudança que não é a dele.
		if p != nil {
			slog.Warn("a janela armada por esta mutação já não é a que está aberta; a resposta vai sem a faixa", "armada", id)
		}
		return out, nil
	}
	out.Pending = &pendingSnapshot{
		ID: p.ID, Summary: p.Summary, Snapshot: p.Snapshot, ExpiresAt: p.ExpiresAt.Unix(),
	}
	return out, nil
}

// discardWindow apaga a janela de uma mutação que falhou sem alterar nada.
//
// A falha do próprio descarte não é fatal: a janela vence sozinha em 90
// segundos, revertendo para um estado idêntico ao atual. Chato — trava as
// mutações até lá — e nunca perigoso.
func (s *Service) discardWindow(ctx context.Context, id string, cause error) {
	if id == "" {
		return
	}
	if err := s.DiscardWindow(ctx, id); err != nil {
		slog.Error("a escrita no banco falhou e a janela recém-armada não pôde ser apagada; ela vence sozinha",
			"err", err, "causa", cause, "janela", id)
	}
}

// reconcileGuarded é o passo 7: registra o estado pós-mutação, reconstrói as
// chains e, se o firewall vivo recusar, reverte.
func (s *Service) reconcileGuarded(ctx context.Context, applied *Applied, hooks Hooks) (*Applied, error) {
	// O estado pós-mutação é registrado ANTES da reconciliação e o mais perto
	// possível da escrita (issue #20a). É ele que permite à reversão desfazer
	// só o que ESTA janela mudou, em vez de restaurar o snapshot por cima do
	// que outro admin gravou no meio dos 90 segundos.
	//
	// Antes do Reconcile porque a falha DELE reverte a janela: registrar
	// depois deixaria justamente a reversão mais provável sem os dois estados
	// de que ela precisa.
	if applied.WindowID != "" {
		if err := s.MarkWindowApplied(applied.WindowID); err != nil {
			slog.Error("não foi possível registrar o estado que esta alteração deixou no banco; se esta janela for revertida, ela vai desfazer apenas o que alcança a chain input e PRESERVAR o resto, como se fosse de outro administrador",
				"err", err, "janela", applied.WindowID)
		}
	}

	if err := s.Reconcile(ctx); err != nil {
		return nil, s.abortWindow(ctx, applied.WindowID, err, hooks)
	}

	if hooks.SnapshotNft != nil {
		hooks.SnapshotNft()
	}
	return applied, nil
}

// abortWindow desfaz a janela quando a RECONCILIAÇÃO falhou — o caso em que a
// mudança já está no banco e pode estar pela metade no firewall vivo.
//
// A reversão que também não conclui NÃO é caminho perdido, e é por isso que
// armar antes conserta o defeito em vez de mudá-lo de lugar: o pendente FICA no
// banco, o watchdog retoma sozinho e, no pior caso, os 90 segundos vencem e a
// reversão automática acontece.
func (s *Service) abortWindow(ctx context.Context, id string, cause error, hooks Hooks) error {
	if id == "" {
		return &GuardError{
			Stage:   StageReconcile,
			Message: "a alteração não pôde ser aplicada no firewall",
			Err:     cause,
		}
	}
	if err := s.RevertPending(ctx, id); err != nil {
		slog.Error("a mutação falhou e a reversão da janela recém-aberta não pôde ser concluída; o pendente fica e o LinkGuard tenta de novo",
			"err", err, "causa", cause)
		return &GuardError{
			Stage: StageStuck,
			Message: "a alteração não pôde ser concluída e o estado anterior ainda não voltou por completo; " +
				"o LinkGuard vai continuar tentando reverter sozinho — acompanhe a faixa de mudança pendente no painel",
			Err: errors.Join(cause, err),
		}
	}
	if hooks.SnapshotNft != nil {
		hooks.SnapshotNft()
	}
	slog.Warn("mutação falhou depois de a janela ter sido aberta; o estado anterior foi restaurado", "err", cause)

	// A linha de auditoria do DESFAZER (N-4). A mutação já gravou a dela — um
	// `nft.group.add` de um grupo que, a esta altura, não existe mais —, e sem
	// esta o histórico afirma uma alteração que nunca chegou a valer.
	if hooks.Audit != nil {
		hooks.Audit("nft.pending.revert", "pending:"+id,
			"a alteração falhou ao ser aplicada no firewall e o estado anterior foi restaurado")
	}

	// E a resposta é a boa notícia, não o genérico "erro interno" (N-4): a
	// reversão DEU CERTO, e quem está na tela precisa saber que o firewall
	// ficou exatamente como estava.
	return &GuardError{
		Stage:   StageReconcile,
		Message: "a alteração não foi aplicada no firewall e o estado anterior foi restaurado; nada mudou",
		Err:     cause,
	}
}

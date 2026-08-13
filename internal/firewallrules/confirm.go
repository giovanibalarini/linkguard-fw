package firewallrules

// Confirmar-ou-reverte (Fase C2, spec §5) — a rede de proteção que torna
// aceitável escrever regras para o tráfego DESTINADO ao próprio firewall.
//
// Todas as entregas anteriores deste projeto mexiam em tráfego ATRAVESSANDO o
// firewall: um erro ali derruba a rede da empresa — grave, mas o operador
// ainda tem SSH e painel para consertar. Uma regra de escopo input pode tirar
// o SSH e o painel DELE, numa máquina remota, possivelmente de madrugada e
// sem acesso físico. `nft -c` prova que o ruleset compila; não prova que
// ainda dá para entrar.
//
// Por isso toda mudança que envolve um grupo de escopo input é aplicada de
// verdade, mas com prazo: 90 segundos para o operador confirmar que ainda tem
// acesso. Sem confirmação, o LinkGuard reverte sozinho.
//
// O que segura essa promessa é o pendente morar no BANCO, não num timer em
// memória (spec §5.1). O timer existe para o caso comum (processo vivo, ver
// WatchPending); o banco é a rede embaixo dele, para o caso que mais importa:
// a máquina que reiniciou dentro da janela — normalmente POR CAUSA da
// mudança — e que sem isto voltaria com a regra não confirmada valendo para
// sempre, sem volta remota.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/google/uuid"
)

// ConfirmWindow é quanto tempo o operador tem para confirmar antes de a
// mudança ser desfeita sozinha: 90 segundos (spec §5).
//
// O valor não é arbitrário nem negociável para baixo: é o tempo de perceber
// que o painel não responde, tentar o SSH, e concluir que a alteração
// trancou o acesso. E não é negociável para cima: enquanto a janela corre,
// nenhuma outra mutação de grupo ou regra é aceita (spec §5.3), então uma
// janela longa é um firewall travado por engano.
const ConfirmWindow = 90 * time.Second

// stateSnapshot é o que vai serializado no campo Snapshot do pendente: o
// estado dos GRUPOS E REGRAS, não o ruleset inteiro do nft.
//
// A diferença é a razão de este mecanismo existir de forma escopada
// (spec §5.2): restaurar um ruleset inteiro passaria por `flush ruleset`,
// que destrói as tabelas de terceiros que dividem o kernel com a nossa — a
// dívida conhecida de nftables.Service.Restore, que este caminho não pode
// repetir. Reverter aqui é restaurar estas linhas no banco e reconciliar; o
// nft só recebe `flush chain` nas chains do LinkGuard.
type stateSnapshot struct {
	Groups []storage.FirewallGroup `json:"groups"`
	Rules  []storage.FirewallRule  `json:"rules"`
}

// SnapshotState serializa o estado ATUAL dos grupos e regras — o que o
// chamador tira ANTES de aplicar a mudança arriscada, para ter para onde
// voltar.
//
// Erro de leitura viaja como erro e nunca vira um snapshot vazio: um
// snapshot vazio é um comando legítimo de "o admin não tem grupo nenhum", e
// reverter para ele apagaria o firewall inteiro, bloqueios administrativos
// incluídos. É a mesma armadilha que o CONTRATO DO CHAMADOR de
// nftables.ReconcileGroups descreve, aqui do lado de quem grava.
func (s *Service) SnapshotState() (string, error) {
	groups, err := s.db.ListFirewallGroups()
	if err != nil {
		return "", fmt.Errorf("ler os grupos para o snapshot: %w", err)
	}
	rules, err := s.db.ListFirewallRules()
	if err != nil {
		return "", fmt.Errorf("ler as regras para o snapshot: %w", err)
	}
	b, err := json.Marshal(stateSnapshot{Groups: groups, Rules: rules})
	if err != nil {
		return "", fmt.Errorf("serializar o snapshot: %w", err)
	}
	return string(b), nil
}

// OpenConfirmWindow grava o pendente: a mudança JÁ FOI aplicada, e a partir
// daqui ela tem 90 segundos para ser confirmada.
//
// Não toca no nft. Quem aplica é a mutação que veio antes; esta função é só
// a rede de proteção sendo armada, e um comando de nft aqui seria uma
// reescrita de chain que ninguém pediu.
//
// O snapshot é validado como JSON do formato esperado antes de ir para o
// banco: um pendente com snapshot ilegível é um pendente sem volta, e a hora
// de descobrir isso é agora — não daqui a 90 segundos, quando a reversão for
// a única coisa entre o operador e uma máquina inacessível.
//
// Abrir com uma janela já aberta falha (a tabela aceita uma linha só). Não é
// limitação: com dois pendentes, "reverter ao estado anterior" não teria
// resposta — anterior a qual das duas mudanças? (spec §5.3).
func (s *Service) OpenConfirmWindow(_ context.Context, snapshot, by, summary string) error {
	if snapshot == "" {
		return fmt.Errorf("snapshot vazio: sem ele não há para onde reverter")
	}
	var parsed stateSnapshot
	if err := json.Unmarshal([]byte(snapshot), &parsed); err != nil {
		return fmt.Errorf("snapshot ilegível (a reversão dependeria dele): %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, err := s.db.GetPendingChange()
	if err != nil {
		return fmt.Errorf("ler a janela de confirmação em aberto: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("já há uma mudança aguardando confirmação (%q, aplicada por %s): confirme ou reverta antes de aplicar outra",
			existing.Summary, existing.AppliedBy)
	}

	p := storage.PendingChange{
		ID:        uuid.NewString(),
		Snapshot:  snapshot,
		ExpiresAt: s.now().Add(ConfirmWindow),
		AppliedBy: by,
		Summary:   summary,
	}
	if err := s.db.SavePendingChange(p); err != nil {
		return fmt.Errorf("gravar a mudança pendente: %w", err)
	}
	slog.Warn("mudança de firewall aplicada com prazo para confirmação: sem confirmar, o LinkGuard reverte sozinho",
		"resumo", summary, "aplicada_por", by, "reverte_em", p.ExpiresAt.Format(time.RFC3339))
	return nil
}

// PendingChange devolve a janela em aberto, ou nil quando não há nenhuma. É
// a forma painel-facing (a faixa com o relógio, o GET /pending).
//
// Erro de leitura vira nil, com log de erro — e é por isso que quem TRAVA
// mutação por causa da janela (spec §5.3) tem que usar PendingChangeOrError:
// aqui, um SELECT que falhou é indistinguível de "não há janela aberta", e
// essa confusão do lado da trava LIBERARIA a mutação que ela existe para
// impedir.
func (s *Service) PendingChange() *storage.PendingChange {
	p, err := s.db.GetPendingChange()
	if err != nil {
		slog.Error("não foi possível ler a mudança de firewall pendente", "err", err)
		return nil
	}
	return p
}

// PendingChangeOrError é PendingChange com o erro de leitura preservado — a
// forma obrigatória para quem decide se uma mutação pode ou não acontecer.
func (s *Service) PendingChangeOrError() (*storage.PendingChange, error) {
	return s.db.GetPendingChange()
}

// ConfirmPending fecha a janela aceitando a mudança: apaga o pendente e NÃO
// mexe no firewall.
//
// Não mexer é o ponto. O que está valendo no nft já É o estado desejado — o
// operador acabou de provar isso, confirmando de dentro da máquina. Uma
// reconciliação "por garantia" aqui daria flush e reescreveria a chain input
// no exato instante em que o acesso foi provado bom, abrindo uma janela de
// risco criada do nada pela linha que existia para não fazer nada.
func (s *Service) ConfirmPending(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, err := s.db.GetPendingChange()
	if err != nil {
		return fmt.Errorf("ler a mudança pendente: %w", err)
	}
	if p == nil {
		return fmt.Errorf("não há mudança aguardando confirmação")
	}
	if err := s.db.ClearPendingChange(); err != nil {
		return fmt.Errorf("apagar a mudança pendente: %w", err)
	}
	slog.Info("mudança de firewall confirmada pelo operador; ela passa a valer definitivamente",
		"resumo", p.Summary, "aplicada_por", p.AppliedBy)
	return nil
}

// RevertPending desfaz a mudança a pedido do operador ("Reverter agora").
// Sem alerta: quem apertou o botão foi ele, e um alerta contando o que ele
// mesmo acabou de fazer é ruído que ensina a ignorar os alertas de verdade.
func (s *Service) RevertPending(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, err := s.db.GetPendingChange()
	if err != nil {
		return fmt.Errorf("ler a mudança pendente: %w", err)
	}
	if p == nil {
		return fmt.Errorf("não há mudança aguardando confirmação")
	}
	return s.revert(ctx, p, "a pedido do operador", false)
}

// CheckPendingExpired reverte a janela cujo prazo já passou. É a
// "próxima verificação" da spec §5: chamada pelo timer em memória
// (WatchPending) enquanto o processo vive.
//
// Janela ainda dentro do prazo é deixada em paz — de propósito. Reverter
// antes da hora tiraria do operador exatamente o tempo que este mecanismo
// existe para dar a ele. (No BOOT a decisão é a oposta e está em
// RevertPendingOnBoot; lá o que se sabe é que ele não estava presente.)
func (s *Service) CheckPendingExpired(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, err := s.db.GetPendingChange()
	if err != nil {
		return fmt.Errorf("ler a mudança pendente: %w", err)
	}
	if p == nil {
		return nil
	}
	if s.now().Before(p.ExpiresAt) {
		return nil // ainda dá tempo de confirmar
	}
	return s.revert(ctx, p, "o prazo de confirmação terminou sem ninguém confirmar", true)
}

// RevertPendingOnBoot é a verificação que roda no boot, ANTES de qualquer
// reconciliação (ver cmd/linkguard-fw/main.go).
//
// Ela reverte o pendente TENHA ELE EXPIRADO OU NÃO, e essa é a decisão
// registrada na spec §5.1 — não um descuido:
//
//   - o operador não estava lá para confirmar. Confirmação é um ato dele,
//     e um processo que reiniciou não confirma nada em nome de ninguém;
//   - um reboot dentro da janela normalmente significa que a máquina caiu
//     POR CAUSA da mudança. Tratar "ainda não expirou" como "deixa valer"
//     é justamente deixar de pé, para sempre, a regra que pode ter trancado
//     o operador fora de uma máquina remota — o cenário para o qual não há
//     conserto remoto.
//
// O custo aceito, explicitamente: um reboot planejado dentro da janela
// obriga a refazer uma alteração legítima. É pouco perto de perder o acesso.
//
// A ORDEM no boot também é parte da proteção: isto vem antes de qualquer
// reconciliação porque reverter DEPOIS de já ter reconciliado significaria
// aplicar a regra perigosa mais uma vez, na máquina que acabou de voltar por
// causa dela.
//
// Sem pendente é um no-op silencioso: nenhum comando no nft, nenhum alerta —
// é o caso de todo boot normal.
func (s *Service) RevertPendingOnBoot(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, err := s.db.GetPendingChange()
	if err != nil {
		return fmt.Errorf("ler a mudança pendente no boot: %w", err)
	}
	if p == nil {
		return nil
	}
	reason := "o LinkGuard reiniciou com a mudança ainda não confirmada"
	if !s.now().Before(p.ExpiresAt) {
		reason = "o LinkGuard reiniciou e o prazo de confirmação já havia terminado"
	}
	return s.revert(ctx, p, reason, true)
}

// revert é o caminho único da reversão: restaura os grupos e as regras do
// snapshot no banco, reconcilia as chains do LinkGuard e apaga o pendente.
//
// Chamada com s.mu já travado.
//
// Ordem e tratamento de erro, ponto a ponto:
//
//  1. Snapshot ilegível ou sem nenhum grupo: ABORTA sem tocar em nada. Um
//     snapshot sem grupos apagaria o firewall inteiro (inclusive os bloqueios
//     administrativos, que desde a Fase C1 também são itens da lista) — e o
//     pendente FICA, para o operador ver a faixa e poder confirmar. Uma
//     reversão que não pode ser feita com segurança não é motivo para
//     derrubar o firewall.
//  2. Restaura no banco, em transação (ReplaceFirewallGroupsAndRules).
//  3. Apaga o pendente. Vem ANTES do reconcile de propósito: a decisão já
//     está tomada e o estado desejado já é o antigo. Se o nft estiver fora do
//     ar, manter o pendente só travaria toda mutação de firewall (spec §5.3)
//     por causa de uma janela que já foi resolvida — e a reconciliação
//     incondicional do próximo boot aplica o estado restaurado de qualquer
//     jeito.
//  4. Reconcilia. Erro aqui é devolvido (e vira apply status não-ok lá
//     dentro), mas não desfaz nada do que veio antes.
func (s *Service) revert(ctx context.Context, p *storage.PendingChange, reason string, alert bool) error {
	var snap stateSnapshot
	if err := json.Unmarshal([]byte(p.Snapshot), &snap); err != nil {
		return fmt.Errorf("snapshot da mudança pendente ilegível, nada foi revertido: %w", err)
	}
	if err := s.db.ReplaceFirewallGroupsAndRules(snap.Groups, snap.Rules); err != nil {
		return fmt.Errorf("restaurar o estado anterior dos grupos e regras: %w", err)
	}
	if err := s.db.ClearPendingChange(); err != nil {
		// A restauração no banco já aconteceu; o pendente sobrando travaria
		// as mutações até a próxima passada. Não é motivo para abortar a
		// reconciliação — o firewall vivo é o que importa agora.
		slog.Error("estado anterior restaurado, mas não foi possível apagar a mudança pendente", "err", err)
	}

	slog.Warn("mudança de firewall NÃO confirmada foi revertida: o estado anterior dos grupos e regras foi restaurado",
		"resumo", p.Summary, "aplicada_por", p.AppliedBy, "motivo", reason,
		"grupos_restaurados", len(snap.Groups), "regras_restauradas", len(snap.Rules))

	if alert && s.alerter != nil {
		detail := fmt.Sprintf("A alteração %q, aplicada por %s, foi desfeita automaticamente porque %s. O estado anterior dos grupos e regras do firewall foi restaurado.",
			p.Summary, p.AppliedBy, reason)
		if err := s.alerter.FirewallChangeReverted(detail); err != nil {
			slog.Error("não foi possível registrar o alerta da reversão automática", "err", err)
		}
	}

	if err := s.Reconcile(ctx); err != nil {
		return fmt.Errorf("estado anterior restaurado no banco, mas a reconciliação falhou: %w", err)
	}
	return nil
}

// WatchPending é o timer em memória do caso comum (processo vivo): a cada
// `interval`, se há janela aberta e o prazo terminou, reverte.
//
// Ele NÃO é a garantia — a garantia é o pendente no banco mais a verificação
// de boot. Este laço é o que faz a reversão acontecer no minuto em que
// importa, com o operador olhando a contagem regressiva na tela; a rede
// embaixo dele é RevertPendingOnBoot.
//
// O intervalo é a granularidade da reversão, não do relógio do painel: a
// contagem que o operador vê sai de expires_at, gravado pelo servidor.
func (s *Service) WatchPending(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.CheckPendingExpired(ctx); err != nil {
				slog.Error("não foi possível reverter a mudança de firewall com prazo vencido", "err", err)
			}
		}
	}
}

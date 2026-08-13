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
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
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

// maxRevertBackoff é o teto do intervalo entre duas tentativas de concluir
// uma reversão que não terminou (ver WatchPending).
//
// Sessenta segundos, e o número foi escolhido pelo que ele custa no PIOR caso:
// o dano de espaçar tentativas não é o tempo em que o nft está fora do ar (aí
// não há nada a fazer), é a CAUDA — o tempo que o operador continua trancado
// DEPOIS de a máquina já ter voltado a aceitar a reversão. Num componente cuja
// promessa inteira é "90 segundos", o teto antigo de 5 minutos era 3,3× a
// promessa. Com 60 s a cauda cabe dentro dela.
//
// E o motivo original do backoff (não escrever ~17 mil linhas de ERROR por dia
// no journal) não depende mais dele: quem resolve isso agora é a cadência de
// LOG, separada da cadência de TENTAR — ver revertLogInterval.
const maxRevertBackoff = 60 * time.Second

// revertLogInterval é o espaçamento MÍNIMO entre duas linhas de ERROR sobre a
// mesma reversão que não conclui.
//
// Tentar é barato (um SELECT e alguns comandos de nft) e cada tentativa pode
// ser a que devolve o acesso ao operador; escrever é que enche o journal de um
// firewall de produção — que é exatamente onde alguém vai procurar a causa na
// próxima emergência. Então as duas cadências são separadas: a primeira falha
// de uma sequência sai sempre (é a que diz que algo começou a dar errado), e
// depois no máximo uma por minuto.
const revertLogInterval = time.Minute

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

// validateSnapshotGroups é a MESMA invariante que ensureSystemGroupsPresent
// defende do lado do Reconcile, aplicada aqui do lado de quem grava e de quem
// restaura: um snapshot só serve para reverter se ele descreve um firewall
// que a máquina consegue reconciliar depois.
//
// Duas condições, e as duas são falhas reais já vistas:
//
//   - sem NENHUM grupo: ReplaceFirewallGroupsAndRules recusa (apagaria o
//     firewall inteiro), então uma janela armada com um snapshot desses nunca
//     poderia disparar — 90 segundos depois o watchdog tentaria reverter,
//     seria recusado, e continuaria sendo recusado para sempre. A janela
//     existiria só no papel;
//   - sem os dois grupos do SISTEMA: restaurá-lo apagaria os bloqueios
//     administrativos do banco, e EnsureSystemGroups não os recria (é travado
//     por flag de settings). A partir daí ensureSystemGroupsPresent aborta
//     TODA reconciliação da máquina, para sempre.
//
// Nos dois casos a hora de falhar é ANTES de aplicar a mudança arriscada, não
// 90 segundos depois — quando a reversão for a única coisa entre o operador e
// uma máquina inacessível.
func validateSnapshotGroups(groups []storage.FirewallGroup) error {
	if len(groups) == 0 {
		return fmt.Errorf("snapshot sem nenhum grupo: restaurá-lo apagaria o firewall inteiro, inclusive os bloqueios administrativos")
	}
	present := make(map[string]bool, 2)
	for _, g := range groups {
		if nftables.IsSystemGroup(g.Kind) {
			present[g.Kind] = true
		}
	}
	var missing []string
	if !present[nftables.GroupKindBlockedHosts] {
		missing = append(missing, BlockedHostsGroupName)
	}
	if !present[nftables.GroupKindBlocklist] {
		missing = append(missing, BlocklistGroupName)
	}
	if len(missing) > 0 {
		return fmt.Errorf("snapshot sem o grupo do sistema %s: restaurá-lo apagaria o bloqueio do banco, e nada o recria — toda reconciliação da máquina passaria a abortar",
			joinPT(missing))
	}
	return nil
}

func joinPT(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	default:
		out := items[0]
		for _, s := range items[1:] {
			out += " e " + s
		}
		return out
	}
}

// OpenConfirmWindow grava o pendente: a mudança JÁ FOI aplicada, e a partir
// daqui ela tem 90 segundos para ser confirmada.
//
// Não toca no nft. Quem aplica é a mutação que veio antes; esta função é só
// a rede de proteção sendo armada, e um comando de nft aqui seria uma
// reescrita de chain que ninguém pediu.
//
// O snapshot é validado como JSON do formato esperado E como um estado
// restaurável (validateSnapshotGroups) antes de ir para o banco: um pendente
// que a reversão vai recusar é uma janela armada que nunca pode disparar, e a
// hora de descobrir isso é agora — não daqui a 90 segundos.
//
// Abrir com uma janela já aberta falha (a tabela aceita uma linha só). Não é
// limitação: com dois pendentes, "reverter ao estado anterior" não teria
// resposta — anterior a qual das duas mudanças? (spec §5.3).
//
// ESCOPO DO SNAPSHOT — o que ele NÃO cobre. stateSnapshot é só `groups` e
// `rules`. As mesmas chains forward e input também são renderizadas a partir
// dos named sets (blocked_hosts, blocklist), dos port forwards e do toggle de
// NTP, e NADA disso entra no snapshot: uma mutação que tocasse neles e
// abrisse janela seria revertida só pela metade — o pior resultado possível
// aqui, porque o operador acredita que o estado anterior voltou. Enquanto
// esta limitação existir, a regra é: SÓ mutação de grupo/regra pode chamar
// esta função (é a Task 4 que precisa garantir isso do lado dos handlers).
func (s *Service) OpenConfirmWindow(_ context.Context, snapshot, by, summary string) error {
	if snapshot == "" {
		return fmt.Errorf("snapshot vazio: sem ele não há para onde reverter")
	}
	var parsed stateSnapshot
	if err := json.Unmarshal([]byte(snapshot), &parsed); err != nil {
		return fmt.Errorf("snapshot ilegível (a reversão dependeria dele): %w", err)
	}
	if err := validateSnapshotGroups(parsed.Groups); err != nil {
		return fmt.Errorf("janela de confirmação NÃO aberta, porque a reversão dela seria recusada: %w", err)
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

	now := s.now()
	p := storage.PendingChange{
		ID:        uuid.NewString(),
		Snapshot:  snapshot,
		ExpiresAt: now.Add(ConfirmWindow),
		AppliedBy: by,
		Summary:   summary,
		CreatedAt: now,
	}
	if err := s.db.SavePendingChange(p); err != nil {
		return fmt.Errorf("gravar a mudança pendente: %w", err)
	}

	// O prazo MONOTÔNICO desta janela, além do expires_at de relógio de
	// parede que foi para o banco. Os dois, e não só o segundo, porque esta
	// máquina É o servidor NTP da rede: o chrony do Debian vem com `makestep`
	// ligado, e um passo do relógio PARA TRÁS maior que a janela (RTC ruim
	// depois de troca de disco, `timedatectl set-time`, o primeiro sync do
	// chrony numa máquina que acabou de subir) empurraria o expires_at para o
	// futuro e o auto-revert simplesmente não dispararia — o operador ficaria
	// trancado fora, sem confirmar e sem reverter.
	//
	// time.Now() carrega leitura monotônica; time.Unix() (que é como o
	// expires_at volta do banco) não carrega. Daí o deadline monotônico só
	// existir para a janela aberta NESTE processo — depois de um restart não
	// há um, e quem responde por aquele caso é RevertPendingOnBoot, que
	// reverte tenha expirado ou não.
	s.monoDeadline = s.monoNow().Add(ConfirmWindow)
	s.monoDeadlineID = p.ID

	slog.Warn("mudança de firewall aplicada com prazo para confirmação: sem confirmar, o LinkGuard reverte sozinho",
		"resumo", summary, "aplicada_por", by, "reverte_em", p.ExpiresAt.Format(time.RFC3339))
	return nil
}

// PendingChangeOrError devolve a janela em aberto, ou nil quando não há
// nenhuma — com o erro de leitura PRESERVADO.
//
// É a única forma que existe, e isso é deliberado. A forma "conveniente" que
// engolia o erro e devolvia nil (havia uma) mentia nos dois lados que
// importam: para o painel, um SELECT que falhou fazia a faixa "confirme em
// 0:47" sumir da tela, e o operador concluía que já tinha confirmado; para
// quem TRAVA mutação por causa da janela (spec §5.3), o mesmo nil LIBERARIA a
// mutação que a trava existe para impedir. Nunca mostrar dado falso é regra
// deste projeto; aqui ela é também a diferença entre o operador confirmar e
// perder a máquina.
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
		// m-7: a corrida confirmação × expiração não faz nada duas vezes (as
		// duas passam por s.mu), mas o operador que perdeu por um segundo
		// merece a verdade em vez de "não há mudança aguardando confirmação",
		// que soa como "você já confirmou" no pior momento possível.
		if r := s.recentRevert(); r != nil {
			return fmt.Errorf("tarde demais: a mudança %q foi revertida automaticamente porque %s; ela não está mais valendo — aplique de novo se ainda quiser",
				r.summary, r.reason)
		}
		return fmt.Errorf("não há mudança aguardando confirmação")
	}
	if p.Reverting() {
		// A reversão desta mudança já começou e não terminou (o estado
		// anterior já foi restaurado no BANCO; o que faltou foi o nft).
		// Confirmar aqui seria dizer "fica valendo" sobre uma mudança que já
		// saiu do banco — o pendente ficaria apagado com o banco no estado
		// antigo e o nft possivelmente no novo, exatamente o descasamento que
		// ninguém conserta remotamente.
		//
		// A marca vem do BANCO (reverting_at), não de um campo deste processo
		// (N-1): com ela em memória, bastava o LinkGuard reiniciar no meio de
		// uma reversão travada para este `if` sumir — e aí o operador confirmava
		// um fantasma. Ele recebia "a mudança passa a valer definitivamente"
		// sobre uma alteração que já não existia mais no banco, o pendente era
		// apagado, e a regra que tirou o SSH dele continuava viva no nft, sem
		// watchdog e sem ninguém tentando de novo.
		return fmt.Errorf("a reversão desta mudança já começou (o estado anterior já foi restaurado no banco) e não pode mais ser confirmada; o LinkGuard vai concluí-la assim que o nft aceitar")
	}
	if err := s.db.ClearPendingChange(); err != nil {
		return fmt.Errorf("apagar a mudança pendente: %w", err)
	}
	s.clearWindowMemory(p.ID)
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
//
// Duas exceções ao "deixar em paz", e as duas existem por falha observada:
//
//   - uma reversão JÁ COMEÇADA é retomada na hora, expirada ou não: o estado
//     anterior já está no banco, e parar no meio deixaria o nft com a regra
//     perigosa viva e ninguém tentando de novo;
//   - o prazo vale pelo relógio de parede OU pelo monotônico, o que vencer
//     primeiro — ver windowExpired.
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
	if p.Reverting() {
		return s.revert(ctx, p, "a reversão anterior não pôde ser concluída no firewall vivo", true)
	}
	if !s.windowExpired(p) {
		return nil // ainda dá tempo de confirmar
	}
	return s.revert(ctx, p, "o prazo de confirmação terminou sem ninguém confirmar", true)
}

// windowExpired decide se o prazo acabou. A regra depende de existir, ou não,
// um deadline MONOTÔNICO para esta janela.
//
//   - Janela aberta NESTE processo: quem manda é o deadline monotônico. Ele é
//     o único dos dois relógios que mede tempo DECORRIDO — e "90 segundos para
//     confirmar" é uma promessa sobre tempo decorrido, não sobre o que está
//     escrito no relógio da parede.
//   - Janela que veio de antes (restart): só o expires_at do banco, porque não
//     existe leitura monotônica comparável — time.Unix() não carrega uma. Esse
//     caso é o de RevertPendingOnBoot, que reverte tenha expirado ou não.
//
// Os dois relógios existem porque cada um cobre uma falha do outro, e as duas
// já foram medidas nesta máquina, que É o servidor NTP da rede (chrony do
// Debian, `makestep` ligado):
//
//   - salto para TRÁS maior que a janela (RTC ruim depois de troca de disco,
//     `timedatectl set-time`, primeiro sync depois de subir): o expires_at
//     gravado vai para o futuro e, só com relógio de parede, a reversão nunca
//     dispararia — o operador ficaria trancado fora sem poder confirmar (não
//     tem acesso) nem esperar (o prazo fugiu). O monotônico vence na hora
//     certa e devolve o acesso;
//   - salto para a FRENTE (o `makestep` do primeiro sync é bidirecional): o
//     expires_at é ultrapassado antes de os 90 segundos terem PASSADO de
//     verdade, e a janela era encerrada cedo — 2 segundos de tempo real
//     bastavam. A direção é segura (o acesso volta), mas o operador perde o
//     prazo sem aviso e a contagem do painel mente. Com o monotônico mandando,
//     o expires_at ultrapassado sozinho não encerra nada.
//
// O expires_at continua sendo a verdade PUBLICADA (é o que o painel desenha e
// o que sobrevive ao restart); ele só não decide sozinho enquanto houver um
// prazo monotônico desta mesma janela para decidir melhor.
//
// Chamada com s.mu já travado.
func (s *Service) windowExpired(p *storage.PendingChange) bool {
	if s.monoDeadlineID == p.ID {
		return !s.monoNow().Before(s.monoDeadline)
	}
	return !s.now().Before(p.ExpiresAt)
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
//
// Falhar aqui NÃO desarma nada: o pendente fica, e WatchPending retoma a
// reversão (ver revert e WatchPending). É o que salva o caso realmente
// perigoso — a máquina cuja tabela `inet linkguard` teve de ser recriada, em
// que este ponto do boot roda antes de EnsureTable e a reconciliação falha
// de forma determinística.
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
// snapshot no banco, reconcilia as chains do LinkGuard e — SÓ ENTÃO — apaga o
// pendente.
//
// Chamada com s.mu já travado.
//
// Ordem e tratamento de erro, ponto a ponto:
//
//  1. Snapshot ilegível, sem nenhum grupo ou sem os grupos do sistema:
//     ABORTA sem tocar em nada, e o pendente FICA (o operador vê a faixa e
//     pode confirmar). Uma reversão que não pode ser feita com segurança não
//     é motivo para derrubar o firewall.
//  2. Restaura no banco, em transação (ReplaceFirewallGroupsAndRules).
//  3. Reconcilia. Falhou, a função PARA AQUI e o pendente CONTINUA no banco.
//  4. Só com o firewall vivo já de volta ao estado anterior é que o pendente
//     é apagado.
//
// A ordem de 3 e 4 é a correção mais importante desta revisão, e o motivo é
// o que acontecia quando ela era a inversa. Apagar o pendente antes de saber
// se o nft aceitou desarmava a própria rede de proteção: banco revertido,
// pendente apagado, REGRA PERIGOSA AINDA VIVA no nft, watchdog sem nada para
// observar (WatchPending só age quando há linha na tabela), faixa do painel
// sumindo da tela — e nada no sistema tentando de novo. O operador ficava
// trancado fora para sempre.
//
// E não era azar: `RevertPendingOnBoot` roda antes de `EnsureTable`, então
// numa máquina cuja tabela `inet linkguard` precisou ser recriada (recuperação
// de desastre, 2026-08-10) o Reconcile falha SEMPRE nesse ponto. Também falha
// quando a leitura do estado do NTP falha — caso em que a chain input não é
// nem tocada, isto é, justamente a chain que contém a regra que trancou o
// operador.
//
// Manter o pendente é seguro porque cada passo é repetível:
// ReplaceFirewallGroupsAndRules é idempotente (DELETE + INSERT das mesmas
// linhas), Reconcile é idempotente por construção, e alerts.Create já suprime
// alerta duplicado enquanto houver um aberto do mesmo tipo. O custo de manter
// é que as mutações de firewall seguem travadas (spec §5.3) enquanto a
// reversão não conclui — e isso é exatamente o certo: o firewall está num
// estado que o LinkGuard ainda não conseguiu impor.
func (s *Service) revert(ctx context.Context, p *storage.PendingChange, reason string, alert bool) error {
	var snap stateSnapshot
	if err := json.Unmarshal([]byte(p.Snapshot), &snap); err != nil {
		return revertFailed(fmt.Errorf("snapshot da mudança pendente ilegível, nada foi revertido: %w", err))
	}
	if err := validateSnapshotGroups(snap.Groups); err != nil {
		return revertFailed(fmt.Errorf("a mudança pendente NÃO foi revertida: %w", err))
	}

	// Retomada: se a reversão deste pendente já tinha começado, nada aqui é
	// anunciado de novo (o alerta já saiu na primeira tentativa) — o que se
	// repete é só o trabalho.
	resuming := p.Reverting()

	if err := s.db.ReplaceFirewallGroupsAndRules(snap.Groups, snap.Rules); err != nil {
		return revertFailed(fmt.Errorf("restaurar o estado anterior dos grupos e regras: %w", err))
	}

	// A marca de "reversão em andamento" vem DEPOIS do commit acima, nunca
	// antes (N-2). Ela afirma que o estado anterior JÁ está no banco, e marcar
	// antes a tornava mentira exatamente no caso em que a transação falha: dali
	// em diante, confirmar responderia "o estado anterior já foi restaurado no
	// banco" sobre um banco intocado, e a verificação de expiração passaria a
	// reverter antes do prazo — tirando do operador justamente o tempo que este
	// mecanismo existe para dar a ele.
	if !resuming {
		if err := s.db.MarkPendingReverting(p.ID, s.now()); err != nil {
			// O pendente FICA e segue confirmável: sem a marca gravada, nada
			// no sistema sabe que a reversão começou, e é mais honesto tentar
			// tudo de novo na próxima passada (ReplaceFirewallGroupsAndRules é
			// idempotente) do que seguir com uma marca que não existe.
			return revertFailed(fmt.Errorf("estado anterior restaurado no banco, mas não foi possível marcar a reversão em andamento (a próxima passada tenta de novo): %w", err))
		}
	}

	if !resuming {
		slog.Warn("mudança de firewall NÃO confirmada foi revertida no banco: restaurando o estado anterior dos grupos e regras no firewall vivo",
			"resumo", p.Summary, "aplicada_por", p.AppliedBy, "motivo", reason,
			"grupos_restaurados", len(snap.Groups), "regras_restauradas", len(snap.Rules))

		if alert && s.alerter != nil {
			detail := fmt.Sprintf("A alteração %q, aplicada por %s, foi desfeita automaticamente porque %s. O estado anterior dos grupos e regras do firewall foi restaurado.",
				p.Summary, p.AppliedBy, reason)
			if err := s.alerter.FirewallChangeReverted(detail); err != nil {
				slog.Error("não foi possível registrar o alerta da reversão automática", "err", err)
			}
		}
	}

	if err := s.Reconcile(ctx); err != nil {
		// O pendente FICA. Ver o doc-comment acima: apagá-lo aqui deixaria a
		// regra perigosa viva no nft sem ninguém para tentar de novo.
		return revertFailed(fmt.Errorf("estado anterior restaurado no banco, mas a reconciliação falhou (o pendente FICA, para a próxima passada tentar de novo): %w", err))
	}
	if err := s.db.ClearPendingChange(); err != nil {
		// O firewall vivo já está no estado anterior — o pendente sobrando
		// trava as mutações, o que é chato, mas a próxima passada refaz tudo
		// e apaga. Erro, não silêncio.
		return revertFailed(fmt.Errorf("estado anterior restaurado e reconciliado, mas não foi possível apagar a mudança pendente (a próxima passada tenta de novo): %w", err))
	}

	s.clearWindowMemory(p.ID)
	s.lastRevert = &revertRecord{summary: p.Summary, reason: reason, at: s.now()}
	slog.Warn("reversão concluída: os grupos e as regras anteriores estão de volta no banco e no firewall vivo",
		"resumo", p.Summary, "aplicada_por", p.AppliedBy, "motivo", reason)
	return nil
}

// clearWindowMemory apaga o que este processo guardava sobre a janela que
// acabou de ser resolvida. Chamada com s.mu já travado.
func (s *Service) clearWindowMemory(id string) {
	if s.monoDeadlineID == id {
		s.monoDeadlineID = ""
		s.monoDeadline = time.Time{}
	}
}

// revertRecord é a memória curta da última reversão concluída — só para dar
// ao operador uma resposta verdadeira quando ele aperta "Confirmar" um
// segundo depois de o prazo ter vencido (m-7).
type revertRecord struct {
	summary string
	reason  string
	at      time.Time
}

// recentRevertWindow é por quanto tempo a última reversão ainda explica um
// "não há mudança aguardando confirmação". Depois disso a resposta genérica
// volta a ser a verdadeira — o operador de duas horas depois não está no meio
// de nenhuma corrida.
const recentRevertWindow = 5 * time.Minute

// recentRevert é chamada com s.mu já travado.
func (s *Service) recentRevert() *revertRecord {
	if s.lastRevert == nil {
		return nil
	}
	if s.now().Sub(s.lastRevert.at) > recentRevertWindow {
		return nil
	}
	return s.lastRevert
}

// revertAttemptError marca o erro que veio de uma TENTATIVA DE REVERSÃO, para
// separá-lo dos outros erros que CheckPendingExpired pode devolver (N-3).
//
// A distinção não é cosmética: é o backoff que depende dela. Um SELECT que
// falhou não é uma reversão que falhou — não há reversão nenhuma em andamento
// —, e tratar os dois igual espaçava as tentativas por causa de um erro que
// não tem nada a ver com o nft. O efeito era uma janela FUTURA vencer com o
// laço já no teto do backoff, isto é, ninguém olhando para ela na hora em que
// os 90 segundos acabam.
type revertAttemptError struct{ err error }

func (e *revertAttemptError) Error() string { return e.err.Error() }
func (e *revertAttemptError) Unwrap() error { return e.err }

// revertFailed embrulha o erro de uma tentativa de reversão. Todo caminho de
// saída com erro de Service.revert passa por aqui.
func revertFailed(err error) error { return &revertAttemptError{err: err} }

// isRevertAttempt diz se o erro veio de uma tentativa de reversão.
func isRevertAttempt(err error) bool {
	var e *revertAttemptError
	return errors.As(err, &e)
}

// nextRevertBackoff é o espaçamento da PRÓXIMA tentativa depois de uma
// reversão que não pôde ser concluída: começa no próprio intervalo do timer,
// dobra a cada falha e para em maxRevertBackoff. `current` é o backoff da
// falha anterior (zero quando a passada anterior deu certo).
//
// Desistir nunca é opção — do outro lado de uma reversão pendente pode estar o
// operador trancado fora da máquina. O espaçamento existe só para não repetir
// uma reconciliação inteira de 5 em 5 segundos durante horas numa máquina cujo
// nft está fora do ar; o teto é curto (60 s) porque o que ele custa é a cauda:
// o tempo que o operador segue trancado DEPOIS de o nft já ter voltado.
//
// O barulho no journal NÃO é problema deste espaçamento (era, e essa era a
// justificativa do teto antigo de 5 minutos): quem cuida disso é a cadência de
// log de WatchPending, separada da cadência de tentar.
func nextRevertBackoff(current, interval time.Duration) time.Duration {
	if current <= 0 {
		if interval <= 0 {
			return maxRevertBackoff
		}
		if interval > maxRevertBackoff {
			return maxRevertBackoff
		}
		return interval
	}
	next := current * 2
	if next > maxRevertBackoff || next <= 0 { // <= 0 cobre o overflow
		return maxRevertBackoff
	}
	return next
}

// nextRevertPace é a cadência de TENTAR depois de uma passada do WatchPending:
// devolve o espaçamento até a próxima tentativa, ou zero para "tente na
// próxima batida do timer, como sempre".
//
// A regra inteira do N-3 está aqui: SÓ o erro de uma tentativa de reversão
// espaça. Um GetPendingChange que falhou não é uma reversão que falhou — não há
// reversão nenhuma em andamento para esperar —, e recuar por causa dele
// deixava o laço no teto do backoff quando uma janela FUTURA vencesse: os 90
// segundos do próximo operador terminariam com ninguém olhando.
func nextRevertPace(err error, current, interval time.Duration) time.Duration {
	if err == nil || !isRevertAttempt(err) {
		return 0
	}
	return nextRevertBackoff(current, interval)
}

// logGate espaça linhas de journal sem espaçar o trabalho que as produz.
//
// A primeira falha de uma sequência sempre sai (é ela que diz que algo começou
// a dar errado); depois, no máximo uma a cada `every`. É o que substitui o
// backoff longo como remédio para o barulho: um nft fora do ar rendia ~17 mil
// linhas de ERROR por dia no journal de um firewall de produção — que é onde
// alguém vai procurar a causa na próxima emergência —, e antes o preço de
// calar isso era esperar até 5 minutos entre duas tentativas de devolver o
// acesso ao operador.
type logGate struct {
	every time.Duration
	last  time.Time
}

// allow diz se ESTA linha pode sair, e já registra o instante quando pode.
func (g *logGate) allow(now time.Time) bool {
	if g.last.IsZero() || !now.Before(g.last.Add(g.every)) {
		g.last = now
		return true
	}
	return false
}

// reset devolve o portão ao estado inicial: a próxima falha volta a ser "a
// primeira de uma sequência" e sai na hora.
func (g *logGate) reset() { g.last = time.Time{} }

// WatchPending é o timer em memória do caso comum (processo vivo): a cada
// `interval`, se há janela aberta e o prazo terminou, reverte. É também quem
// RETOMA uma reversão que ficou pela metade — o pendente que sobra depois de
// um Reconcile que falhou é justamente o que faz esta função tentar de novo.
//
// Ele NÃO é a garantia — a garantia é o pendente no banco mais a verificação
// de boot. Este laço é o que faz a reversão acontecer no minuto em que
// importa, com o operador olhando a contagem regressiva na tela; a rede
// embaixo dele é RevertPendingOnBoot.
//
// O intervalo é a granularidade da reversão, não do relógio do painel: a
// contagem que o operador vê sai de expires_at, gravado pelo servidor.
//
// O laço nunca desiste (uma reversão pendente é o operador possivelmente
// trancado fora). Duas cadências, separadas de propósito:
//
//   - TENTAR: a cada `interval`, e depois de uma reversão que falhou com um
//     espaçamento que dobra até maxRevertBackoff (60 s) e zera assim que uma
//     passada dá certo. Uma tentativa custa um SELECT e alguns comandos de
//     nft, e cada uma pode ser a que devolve o acesso ao operador — daí o teto
//     curto: o que ele custa é a cauda depois de a máquina já ter voltado;
//   - LOGAR: a primeira falha de uma sequência sempre, e depois no máximo uma
//     por revertLogInterval. Sem isso, um nft fora do ar escrevia ~17 mil
//     linhas de ERROR por dia no journal de um firewall de produção — que é
//     onde alguém vai procurar a causa na próxima emergência. Era ESTE o
//     problema que o backoff longo tentava resolver, e resolver aqui não custa
//     tentativa nenhuma.
//
// Só o erro de uma tentativa de REVERSÃO espaça as tentativas (N-3). Um erro
// de leitura do pendente é anotado com a mesma economia de log, mas não recua:
// não há reversão em andamento para esperar, e recuar por causa dele deixaria
// uma janela futura vencer com o laço no teto do backoff.
func (s *Service) WatchPending(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()

	backoff := time.Duration(0)
	var nextAttempt time.Time
	gate := &logGate{every: revertLogInterval}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if now := s.monoNow(); !nextAttempt.IsZero() && now.Before(nextAttempt) {
				continue
			}
			err := s.CheckPendingExpired(ctx)
			if err == nil {
				backoff, nextAttempt = 0, time.Time{}
				gate.reset()
				continue
			}
			backoff = nextRevertPace(err, backoff, interval)
			retryIn := interval
			if backoff > 0 {
				nextAttempt, retryIn = s.monoNow().Add(backoff), backoff
			} else {
				nextAttempt = time.Time{}
			}
			if gate.allow(s.monoNow()) {
				slog.Error("não foi possível resolver a mudança de firewall pendente; ela continua no banco e o LinkGuard vai tentar de novo",
					"err", err, "proxima_tentativa_em", retryIn)
			}
		}
	}
}

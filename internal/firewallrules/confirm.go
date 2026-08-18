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
	// Policy é a política padrão da chain input no instante do snapshot
	// (issue #78).
	//
	// PONTEIRO COM omitempty, e isso é o que dispensa migração: uma linha de
	// pendente gravada por uma versão anterior não tem o campo, e o Unmarshal
	// deixa o ponteiro nil. Nil significa "esta janela é anterior à política" —
	// reverter não mexe nela, que é a resposta certa. Mesma propriedade que o
	// applied_state já explora.
	//
	// Sem este campo, a janela desarmaria a mudança MAIS PERIGOSA que o produto
	// sabe fazer sem desfazê-la: o pendente sumiria, o prazo venceria, e a
	// política restritiva continuaria de pé sem nada apontando para ela.
	Policy *nftables.Policy `json:"policy,omitempty"`
	// ForwardPolicy é a política da chain forward (issue #92), pelo mesmo
	// motivo e com a mesma forma: sem ela, reverter devolveria os grupos e
	// deixaria o tráfego da rede bloqueado.
	ForwardPolicy *nftables.Policy `json:"forward_policy,omitempty"`
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
	st, err := s.readState()
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(st)
	if err != nil {
		return "", fmt.Errorf("serializar o snapshot: %w", err)
	}
	return string(b), nil
}

// readState lê os grupos e as regras na ordem em que o banco os devolve — a
// mesma ordem dos dois lados de toda comparação (ORDER BY position), para que
// "o banco bate com o snapshot" seja uma pergunta com resposta estável.
func (s *Service) readState() (stateSnapshot, error) {
	groups, err := s.db.ListFirewallGroups()
	if err != nil {
		return stateSnapshot{}, fmt.Errorf("ler os grupos para o snapshot: %w", err)
	}
	rules, err := s.db.ListFirewallRules()
	if err != nil {
		return stateSnapshot{}, fmt.Errorf("ler as regras para o snapshot: %w", err)
	}
	// A política entra pelo mesmo contrato dos outros dois: erro de leitura
	// vira erro e aborta o snapshot. Um snapshot sem a política, tirado por
	// engano, produziria uma reversão que devolve grupos e regras e deixa a
	// política restritiva no lugar — o pior dos dois mundos.
	policy, err := s.InputPolicy()
	if err != nil {
		return stateSnapshot{}, fmt.Errorf("ler a política para o snapshot: %w", err)
	}
	fwPolicy, err := s.ForwardPolicy()
	if err != nil {
		return stateSnapshot{}, fmt.Errorf("ler a política da forward para o snapshot: %w", err)
	}
	return stateSnapshot{Groups: groups, Rules: rules, Policy: &policy, ForwardPolicy: &fwPolicy}, nil
}

// canonicalState serializa um estado numa forma COMPARÁVEL byte a byte.
//
// Duas normalizações, e as duas existem por uma armadilha real:
//
//   - slice nil e slice vazia viram a mesma coisa (`[]`). ListFirewallGroups
//     devolve nil quando não há linha e ListFirewallRules devolve uma slice
//     vazia; comparar os dois JSONs crus diria "mudou" onde nada mudou;
//   - todo instante vai para UTC. O mesmo instante lido em fusos diferentes
//     serializa diferente, e o snapshot atravessa uma ida e volta pelo banco
//     antes de ser comparado com o que está lá agora.
//
// A ordem das listas NÃO é normalizada de propósito: ela é significativa (é a
// ordem de avaliação do firewall) e os dois lados saem do mesmo ORDER BY.
func canonicalState(st stateSnapshot) (string, error) {
	out := stateSnapshot{
		Groups: make([]storage.FirewallGroup, len(st.Groups)),
		Rules:  make([]storage.FirewallRule, len(st.Rules)),
	}
	for i, g := range st.Groups {
		g.CreatedAt, g.UpdatedAt = g.CreatedAt.UTC(), g.UpdatedAt.UTC()
		out.Groups[i] = g
	}
	for i, r := range st.Rules {
		r.CreatedAt, r.UpdatedAt = r.CreatedAt.UTC(), r.UpdatedAt.UTC()
		out.Rules[i] = r
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "", fmt.Errorf("serializar o estado para comparação: %w", err)
	}
	return string(b), nil
}

// stateMatchesSnapshot diz se os grupos e as regras do banco são HOJE,
// linha por linha, o que o snapshot descreve.
//
// É a pergunta que decide se a reversão já terminou o trabalho dela na camada
// que é a verdade (ver RevertSettled). Custa dois SELECTs e dois Marshal —
// barato o bastante para rodar na trava de toda mutação.
func (s *Service) stateMatchesSnapshot(snapshot string) (bool, error) {
	var want stateSnapshot
	if err := json.Unmarshal([]byte(snapshot), &want); err != nil {
		return false, fmt.Errorf("snapshot da mudança pendente ilegível: %w", err)
	}
	now, err := s.readState()
	if err != nil {
		return false, err
	}
	a, err := canonicalState(want)
	if err != nil {
		return false, err
	}
	b, err := canonicalState(now)
	if err != nil {
		return false, err
	}
	return a == b, nil
}

// RevertSettled diz se a reversão desta janela já TERMINOU na camada que é a
// verdade: o pendente está marcado como "revertendo" e o banco já é, linha por
// linha, o estado anterior que o snapshot descreve. O que falta é só a
// reconciliação com o nft.
//
// Quem pergunta é a trava das mutações (handlers.confirmWindowBlocks), e a
// resposta muda o que ela faz: neste estado a mutação seguinte é LIBERADA, não
// travada. A arquitetura deste produto é "o banco é a verdade, o nftables é o
// resultado renderizado, reconstruído a cada boot" — se o banco já voltou ao
// estado anterior, a reversão acabou, e qualquer mutação seguinte também
// reconcilia. Travá-la só prenderia o operador: sem isto, uma mutação de
// escopo input que falhou no reconcile deixava o painel sem saída nenhuma —
// não dava para apagar a regra que quebra a reconciliação, nem desligar o
// grupo, nem confirmar (recusado), nem reverter (falha pelo mesmo motivo). A
// única saída era o sqlite3 na máquina.
//
// Erro viaja como erro: quem não conseguiu PROVAR que a reversão terminou não
// pode liberar a mutação por otimismo.
func (s *Service) RevertSettled(p *storage.PendingChange) (bool, error) {
	if p == nil || !p.Reverting() {
		return false, nil
	}
	return s.stateMatchesSnapshot(p.Snapshot)
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

// windowConflictError marca o erro que é um CONFLITO DE ESTADO com a janela —
// "já há uma janela aberta", "não há nenhuma", "a reversão desta já começou" —
// e não uma pane do servidor.
//
// A distinção existe para quem responde HTTP: sem ela, o handler classificava
// pelo estado que tinha lido ANTES de chamar, e o estado pode ter mudado entre
// as duas chamadas (outro admin, ou o próprio watchdog). O caso que mais dói é
// o operador apertar "Confirmar" um segundo depois do prazo: a mensagem certa
// existe aqui dentro ("tarde demais: a mudança %q foi revertida..."), e o
// handler a trocava por "erro interno do servidor" no minuto em que essa é a
// informação que mais importa para ele.
type windowConflictError struct{ err error }

func (e *windowConflictError) Error() string { return e.err.Error() }
func (e *windowConflictError) Unwrap() error { return e.err }

// windowConflict embrulha um conflito de estado da janela.
func windowConflict(format string, a ...any) error {
	return &windowConflictError{err: fmt.Errorf(format, a...)}
}

// IsWindowConflict diz se o erro é conflito com o estado da janela (409 do
// lado da API) em vez de falha do servidor (500). A mensagem embrulhada foi
// escrita para o operador ler; a genérica, não.
func IsWindowConflict(err error) bool {
	var e *windowConflictError
	return errors.As(err, &e)
}

// OpenConfirmWindow grava o pendente ANTES de a mudança ser aplicada: a partir
// daqui ela tem 90 segundos para ser confirmada, e quem falhar em aplicá-la
// desfaz a janela (RevertPending) em vez de deixá-la para trás.
//
// A ORDEM — armar antes de aplicar — é a correção mais importante desta
// revisão, e o motivo é o que acontecia com a ordem inversa. Armar depois de
// reconciliar deixava dois buracos, os dois medidos por sonda:
//
//   - reconcile que falha: o handler respondia 500 e voltava ANTES de armar,
//     com a mudança de escopo input já gravada no banco e já valendo na chain
//     input viva — sem pendente, sem auto-revert e sem trava, enquanto o
//     operador lia "erro interno do servidor" e concluía que nada acontecera;
//   - duas mutações de input simultâneas: as duas passavam pela trava (que lê o
//     pendente e ainda não havia nenhum), as duas aplicavam, e só a segunda
//     descobria, ao armar, que já havia uma janela — mudança valendo sem rede
//     embaixo, e o snapshot da vencedora podendo já conter a escrita da
//     perdedora, isto é, uma reversão que o operador acredita completa e não é.
//
// Armando antes, a UNIQUE de pending_firewall_change (uma linha, só_row) é o
// que serializa: a segunda requisição recebe conflito AQUI, antes de tocar no
// firewall, e um reconcile que falha passa a ser coberto pelo watchdog.
//
// Não toca no nft. Quem aplica é a mutação que vem DEPOIS; esta função é só
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
func (s *Service) OpenConfirmWindow(_ context.Context, by, summary string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// O snapshot sai daqui de DENTRO, sob o mesmo mutex que grava o pendente
	// (N-8). Tirá-lo fora do lock, no chamador, abria um intervalo em que uma
	// mutação que NÃO abre janela (escopo forward, port forward, bloqueio por
	// host) entrava no snapshot e seria desfeita por uma reversão que o
	// operador acredita cirúrgica. São dois statements adjacentes, e agora não
	// existe mais um caminho de chamada capaz de armar a janela com um
	// snapshot de outro instante.
	//
	// Isso resolve a metade do instante do snapshot, e SÓ ela: a mutação alheia
	// que aterrissa DEPOIS deste ponto continua fora do snapshot e continuava
	// sendo apagada pela reversão (issue #20a). Quem fecha essa outra metade é a
	// conferência do estado na hora de reverter — ver revertTarget e
	// MarkWindowApplied; aqui não cabe, porque a mutação alheia ainda nem
	// aconteceu.
	snapshot, err := s.SnapshotState()
	if err != nil {
		return "", err
	}
	return s.openWindowLocked(snapshot, by, summary)
}

// openWindowWithSnapshot arma a janela com um snapshot ESCOLHIDO pelo
// chamador, em vez do estado atual. Não exportada, e sem chamador em produção
// de propósito: em produção o snapshot é sempre o de agora, tirado sob o mesmo
// mutex (ver OpenConfirmWindow, e o N-8 que ela fecha). Ela existe para os
// testes deste pacote poderem armar janelas cujo estado anterior é arbitrário
// — inclusive um irreversível, que é o que a recusa de openWindowLocked
// precisa exercitar.
func (s *Service) openWindowWithSnapshot(snapshot, by, summary string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.openWindowLocked(snapshot, by, summary)
}

// openWindowLocked é o arme propriamente dito. Chamada com s.mu já travado.
//
// Recebe o snapshot em vez de tirá-lo porque os testes precisam armar uma
// janela cujo snapshot descreve um estado anterior ARBITRÁRIO — inclusive um
// irreversível, para exercitar a recusa. Em produção o único chamador é
// OpenConfirmWindow, e lá o snapshot é sempre o do estado atual.
func (s *Service) openWindowLocked(snapshot, by, summary string) (string, error) {
	if snapshot == "" {
		return "", fmt.Errorf("snapshot vazio: sem ele não há para onde reverter")
	}
	var parsed stateSnapshot
	if err := json.Unmarshal([]byte(snapshot), &parsed); err != nil {
		return "", fmt.Errorf("snapshot ilegível (a reversão dependeria dele): %w", err)
	}
	if err := validateSnapshotGroups(parsed.Groups); err != nil {
		return "", fmt.Errorf("janela de confirmação NÃO aberta, porque a reversão dela seria recusada: %w", err)
	}

	existing, err := s.db.GetPendingChange()
	if err != nil {
		return "", fmt.Errorf("ler a janela de confirmação em aberto: %w", err)
	}
	if existing != nil {
		// A ÚNICA janela que dá lugar a outra é a da reversão que já terminou
		// no banco e só não terminou no nft (RevertSettled). Nada se perde na
		// troca, e é isso que a torna aceitável: o banco É o snapshot dela
		// neste instante, logo o snapshot da janela nova é o MESMO estado
		// anterior — mais 90 segundos de prazo e um watchdog observando. Sem a
		// troca, o operador cuja reversão não reconcilia não consegue aplicar
		// nem a mudança de escopo input que consertaria a máquina.
		settled, serr := s.RevertSettled(existing)
		if serr != nil || !settled {
			if serr != nil {
				slog.Error("não foi possível verificar se a reversão em andamento já tinha terminado no banco", "err", serr)
			}
			return "", windowConflict("já há uma mudança aguardando confirmação (%q, aplicada por %s): confirme ou reverta antes de aplicar outra",
				existing.Summary, existing.AppliedBy)
		}
		if err := s.db.ClearPendingChange(); err != nil {
			return "", fmt.Errorf("apagar a janela da reversão já concluída no banco: %w", err)
		}
		s.clearWindowMemory(existing.ID)
		s.lastRevert = &revertRecord{
			summary: existing.Summary,
			reason:  "o estado anterior já tinha voltado ao banco e uma alteração seguinte reconciliou o firewall",
			at:      s.now(),
		}
		slog.Warn("a janela de uma reversão já concluída no banco deu lugar à janela desta alteração; o estado anterior guardado é o mesmo",
			"reversao", existing.Summary, "alteracao", summary)
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
		return "", fmt.Errorf("gravar a mudança pendente: %w", err)
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
	return p.ID, nil
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

// UnconfirmedChangePending diz se há uma mudança de firewall aplicada e ainda
// não resolvida — aguardando confirmação OU com a reversão em andamento.
//
// É a guarda que o Persist do nftables consulta (nftables.SetPersistGuard, I-1
// da revisão final): enquanto a resposta for "sim", o ruleset vivo não vai para
// o /etc/nftables.conf que o systemd carrega antes de o LinkGuard subir. Os dois
// estados contam, e o segundo não é excesso de zelo: durante uma reversão que
// ainda não reconciliou, a regra perigosa continua VIVA no kernel — é justamente
// o estado que não pode ser congelado no arquivo de boot.
//
// NÃO toma s.mu, e isso é obrigatório, não economia: o Persist é alcançado de
// dentro de revert → Reconcile, com o mutex do serviço já travado. Tomá-lo aqui
// travaria a reversão em si mesma. Um SELECT solto é seguro porque a resposta é
// derivada só do banco.
func (s *Service) UnconfirmedChangePending() (bool, error) {
	p, err := s.db.GetPendingChange()
	if err != nil {
		return false, fmt.Errorf("ler a janela de confirmação em aberto: %w", err)
	}
	return p != nil, nil
}

// persistBootRuleset grava o ruleset vivo no arquivo de boot agora que a janela
// se FECHOU — o outro lado de UnconfirmedChangePending.
//
// Enquanto a janela existia, toda reconciliação pulou o Persist, então o
// /etc/nftables.conf ficou congelado no estado anterior à mudança arriscada.
// Fechada a janela (confirmada, revertida ou concluída por outra mutação), o
// arquivo tem que voltar a descrever a máquina — inclusive as mutações que NÃO
// abrem janela e aconteceram no meio dos 90 segundos (bloqueio por host, port
// forward, NTP), que também pularam o Persist.
//
// A ordem importa e é sempre a mesma: isto vem DEPOIS de o pendente ter saído do
// banco. Antes, a própria guarda o bloquearia.
//
// Falhar aqui não desfaz nada nem vira erro do chamador: a mudança está
// confirmada (ou revertida) e valendo no firewall vivo; o que ficou para trás é
// o arquivo de boot, e a próxima reconciliação — a próxima mutação ou o próximo
// boot — o alcança. É a mesma economia de todo Persist deste projeto.
//
// Chamada com s.mu travado. Segura porque o Persist não toma mutex nenhum deste
// serviço (ver UnconfirmedChangePending).
func (s *Service) persistBootRuleset(ctx context.Context, why string) {
	if s.nft == nil {
		return
	}
	if err := s.nft.Persist(ctx); err != nil {
		slog.Error("a janela de confirmação foi fechada, mas o ruleset não pôde ser gravado para o próximo boot (a próxima reconciliação tenta de novo)",
			"motivo", why, "err", err)
	}
}

// windowMismatch é a recusa de agir sobre uma janela que não é mais a que o
// chamador conhece — a identidade da janela sendo verificada DENTRO do mutex,
// que é o único lugar onde ela pode ser verificada sem corrida.
//
// O cenário que ela fecha é alcançável num produto multi-admin: o admin A faz
// uma mutação de escopo input, a janela dele é armada, e o reconcile dele
// demora (dezenas de invocações de nft numa máquina de verdade). Nesse
// intervalo o admin B aperta "Confirmar" — confirmar nunca é travado —, aplica
// a mudança DELE e arma a janela dele. O reconcile de A falha e o abort de A
// chamava "reverter o pendente", sem identidade nenhuma: quem era desfeito era
// o pendente de B. A mudança de B voltava atrás, a de A (que falhou) ficava
// valendo, e A lia na tela "o estado anterior foi restaurado".
func windowMismatch(p *storage.PendingChange) error {
	return windowConflict("esta não é mais a mudança que está aguardando confirmação: a janela em aberto agora é %q, aplicada por %s. Recarregue a tela antes de decidir — agir aqui resolveria a janela de outra pessoa, e não a que você viu.",
		p.Summary, p.AppliedBy)
}

// ConfirmPending fecha a janela aceitando a mudança: apaga o pendente e NÃO
// mexe no firewall.
//
// Não mexer é o ponto. O que está valendo no nft já É o estado desejado — o
// operador acabou de provar isso, confirmando de dentro da máquina. Uma
// reconciliação "por garantia" aqui daria flush e reescreveria a chain input
// no exato instante em que o acesso foi provado bom, abrindo uma janela de
// risco criada do nada pela linha que existia para não fazer nada.
//
// `id` é a janela que o chamador ESTÁ vendo, e ela é conferida aqui dentro
// (ver windowMismatch): confirmar é cancelar uma reversão automática, e
// cancelar a de uma mudança que o operador nunca viu é o oposto do que este
// mecanismo existe para fazer.
//
// A ÚNICA escrita que a confirmação faz fora do banco é o arquivo de boot
// (persistBootRuleset, I-1 da revisão final), e ela vem DEPOIS de o pendente ter
// sido apagado — isto é, depois de a confirmação ter sido aceita. Não é
// contradição com o parágrafo acima: Persist não toca no firewall vivo, ele lê
// `nft list table` e grava o /etc/nftables.conf. É aqui que a regra confirmada
// passa a valer também no próximo boot; enquanto a janela existia, toda
// reconciliação pulou o Persist de propósito.
func (s *Service) ConfirmPending(ctx context.Context, id string) error {
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
			return windowConflict("tarde demais: a mudança %q foi revertida automaticamente porque %s; ela não está mais valendo — aplique de novo se ainda quiser",
				r.summary, r.reason)
		}
		return windowConflict("não há mudança aguardando confirmação")
	}
	if p.ID != id {
		return windowMismatch(p)
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
		return windowConflict("a reversão desta mudança já começou (o estado anterior já foi restaurado no banco) e não pode mais ser confirmada; o LinkGuard vai concluí-la assim que o nft aceitar")
	}
	if err := s.db.ClearPendingChange(); err != nil {
		return fmt.Errorf("apagar a mudança pendente: %w", err)
	}
	s.clearWindowMemory(p.ID)
	s.persistBootRuleset(ctx, "a mudança foi confirmada pelo operador")
	slog.Info("mudança de firewall confirmada pelo operador; ela passa a valer definitivamente",
		"resumo", p.Summary, "aplicada_por", p.AppliedBy)
	return nil
}

// RevertPending desfaz a mudança a pedido do operador ("Reverter agora").
// Sem alerta: quem apertou o botão foi ele, e um alerta contando o que ele
// mesmo acabou de fazer é ruído que ensina a ignorar os alertas de verdade.
//
// `id` é a janela que o chamador conhece, conferida aqui dentro pela mesma
// razão de ConfirmPending — e aqui a razão é mais forte ainda, porque o outro
// chamador desta função é o abort de uma mutação que falhou: sem a
// identidade, ele desfazia a janela de QUEM ESTIVESSE aberto, isto é, a
// mudança de outro admin (ver windowMismatch).
func (s *Service) RevertPending(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, err := s.db.GetPendingChange()
	if err != nil {
		return fmt.Errorf("ler a mudança pendente: %w", err)
	}
	if p == nil {
		return windowConflict("não há mudança aguardando confirmação")
	}
	if p.ID != id {
		return windowMismatch(p)
	}
	return s.revert(ctx, p, "a pedido do operador", false)
}

// DiscardWindow apaga a janela armada por uma mutação que falhou ANTES de
// mudar qualquer coisa: a escrita no banco não passou, e nada foi aplicado
// nem reconciliado.
//
// Apagar é tudo o que cabe fazer, e é o ponto (N-3): a alternativa — rodar a
// reversão inteira — restaurava no banco linhas idênticas às que já estavam lá
// e, pior, mandava dez comandos ao nft, incluindo `flush chain` da input e da
// forward seguido da reconstrução, por causa de um erro que não mudou uma
// única linha. Reescrever as chains vivas do firewall é a última coisa que se
// quer fazer em cima de um erro que não teve efeito nenhum.
//
// Só apaga a janela que o chamador armou (o id), e nunca uma que já esteja
// sendo revertida — essa tem trabalho pela frente e é do watchdog.
func (s *Service) DiscardWindow(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, err := s.db.GetPendingChange()
	if err != nil {
		return fmt.Errorf("ler a mudança pendente: %w", err)
	}
	if p == nil {
		return nil // já não existe: não há o que descartar
	}
	if p.ID != id {
		return windowMismatch(p)
	}
	if p.Reverting() {
		return windowConflict("a reversão desta janela já começou; o LinkGuard vai concluí-la")
	}
	if err := s.db.ClearPendingChange(); err != nil {
		return fmt.Errorf("apagar a mudança pendente: %w", err)
	}
	s.clearWindowMemory(p.ID)
	return nil
}

// FinishSettledRevert fecha o pendente cuja reversão já tinha terminado no
// banco e cuja única pendência era o nft — depois de OUTRA mutação ter
// reconciliado com sucesso.
//
// Ela é a outra metade da liberação descrita em RevertSettled. A mutação que
// passou pela trava naquele estado acabou de reconstruir as chains a partir do
// banco, e o banco contém o estado anterior restaurado (mais a alteração
// deliberada que o operador acabou de fazer em cima). A única obrigação que
// restava ao pendente — impor esse estado ao firewall vivo — está cumprida, e
// mantê-lo seria trancar as mutações por causa de um trabalho que já acabou.
//
// Devolve true quando fechou alguma coisa. Não toca em pendente que não esteja
// revertendo: uma janela aberta por outra requisição no meio do caminho é dela,
// não desta mutação.
func (s *Service) FinishSettledRevert(ctx context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, err := s.db.GetPendingChange()
	if err != nil {
		return false, fmt.Errorf("ler a mudança pendente: %w", err)
	}
	if p == nil || !p.Reverting() {
		return false, nil
	}
	if err := s.db.ClearPendingChange(); err != nil {
		return false, fmt.Errorf("apagar a mudança pendente já revertida: %w", err)
	}
	s.clearWindowMemory(p.ID)
	// A reconciliação da mutação que chamou isto pulou o Persist (a guarda ainda
	// via o pendente). Com ele apagado, o arquivo de boot volta a valer (I-1).
	s.persistBootRuleset(ctx, "a reversão foi concluída pela reconciliação de uma alteração seguinte")
	reason := "o estado anterior já estava no banco e uma alteração seguinte reconciliou o firewall"
	s.lastRevert = &revertRecord{summary: p.Summary, reason: reason, at: s.now()}
	slog.Warn("reversão concluída pela reconciliação de uma alteração seguinte: o pendente foi fechado",
		"resumo", p.Summary, "aplicada_por", p.AppliedBy)
	return true, nil
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

// SecondsLeft é quanto tempo falta para esta janela ser revertida, em segundos,
// medido pelo MESMO relógio que decide a hora de reverter (windowExpired).
//
// É o número que o painel desenha, e por isso ele não pode sair de outro relógio
// (M-2 da revisão final). O `expires_at` que vai no corpo é relógio de PAREDE, e
// esta máquina É o servidor NTP da rede: depois de um `makestep` do chrony —
// para trás ou para a frente — a subtração `expires_at - agora` deixa de
// descrever o prazo real. Enquanto houver deadline monotônico desta janela
// (janela aberta neste processo), quem responde é ele: a contagem da tela e a
// reversão passam a ser a mesma coisa medida uma vez. Depois de um restart não
// existe leitura monotônica comparável, e aí o expires_at é a única fonte que
// há — o mesmo desempate de windowExpired, para a resposta nunca divergir dela.
//
// Trunca em vez de arredondar e nunca devolve negativo: com 89,6 segundos ele
// diz 89. O erro fica sempre do lado de mostrar MENOS tempo do que há — quem
// acha que tem um segundo a menos confirma um segundo mais cedo; quem acha que
// tem um a mais descobre pelo acesso caindo.
//
// p nil devolve 0. Não há janela; não há contagem.
func (s *Service) SecondsLeft(p *storage.PendingChange) int {
	if p == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	left := p.ExpiresAt.Sub(s.now())
	if s.monoDeadlineID == p.ID {
		left = s.monoDeadline.Sub(s.monoNow())
	}
	if left < 0 {
		return 0
	}
	return int(left.Seconds())
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
//  2. CONFERE O ESTADO (revertTarget, issue #20a): o banco de agora ainda é o
//     que a mutação desta janela deixou, ou outro admin gravou aqui dentro? No
//     segundo caso o que se aplica não é o snapshot cru e sim a mistura — o
//     delta desta janela desfeito, o do outro admin de pé —, e a auditoria
//     registra o que ficou. Sem este passo, restaurar o snapshot era um "volte
//     tudo" que apagava do banco E da chain viva a alteração de terceiros, sem
//     erro, sem alerta e sem histórico.
//  3. Restaura no banco, em transação (ReplaceFirewallGroupsAndRules).
//  4. Reconcilia. Falhou, a função PARA AQUI e o pendente CONTINUA no banco.
//  5. Só com o firewall vivo já de volta ao estado anterior é que o pendente
//     é apagado.
//
// A ordem de 4 e 5 é a correção mais importante desta revisão, e o motivo é
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
// Manter o pendente é seguro porque cada passo é repetível: Reconcile é
// idempotente por construção e alerts.Create já suprime alerta duplicado
// enquanto houver um aberto do mesmo tipo. A retomada NÃO repete a restauração
// do banco — ver o primeiro bloco da função.
//
// E manter o pendente não tranca mais o operador: com o banco já no estado
// anterior, a trava das mutações libera (RevertSettled). Enquanto ela travava,
// uma reconciliação que não passasse deixava o painel sem saída nenhuma —
// nem apagar a regra que quebra o reconcile, nem desligar o grupo, nem
// confirmar, nem reverter.
func (s *Service) revert(ctx context.Context, p *storage.PendingChange, reason string, alert bool) error {
	// Retomada: a reversão deste pendente já tinha começado, e a marca só é
	// gravada DEPOIS de a transação de restauração ter commitado. Então o banco
	// já está no estado anterior e o que restou é a reconciliação — o passo
	// abaixo, e só ele.
	//
	// Restaurar de novo seria ERRADO, não só redundante: desde que a trava
	// libera as mutações neste estado (ver RevertSettled), o banco pode ter
	// recebido, depois da restauração, uma alteração DELIBERADA do operador —
	// tipicamente a que conserta a máquina em que a reconciliação falha. Um
	// segundo ReplaceFirewallGroupsAndRules apagaria essa alteração e devolveria
	// a máquina ao estado em que ela não reconcilia, para sempre.
	//
	// E o snapshot deixa de ser necessário aqui: uma retomada que não restaura
	// nada não depende de ele estar legível, o que também tira do beco o
	// pendente cujo snapshot corrompeu no meio de uma reversão.
	if p.Reverting() {
		return s.finishRevert(ctx, p, reason)
	}

	var snap stateSnapshot
	if err := json.Unmarshal([]byte(p.Snapshot), &snap); err != nil {
		return revertFailed(fmt.Errorf("snapshot da mudança pendente ilegível, nada foi revertido: %w", err))
	}
	if err := validateSnapshotGroups(snap.Groups); err != nil {
		return revertFailed(fmt.Errorf("a mudança pendente NÃO foi revertida: %w", err))
	}

	// O que esta reversão vai aplicar não é mais o snapshot cru e sim o
	// resultado da conferência do estado (issue #20a): se outro admin gravou
	// dentro dos 90 segundos, o que se desfaz é só o delta DESTA janela. Ver
	// mergeRevertTarget.
	merge, err := s.revertTarget(p, snap)
	if err != nil {
		return revertFailed(err)
	}
	snap = merge.target

	if err := s.db.ReplaceFirewallGroupsAndRules(snap.Groups, snap.Rules); err != nil {
		return revertFailed(fmt.Errorf("restaurar o estado anterior dos grupos e regras: %w", err))
	}

	// A política volta junto (issue #78), e ANTES da reconciliação: é ela que
	// vai renderizar a chain, e restaurar a política depois deixaria a passada
	// escrever a política nova sobre o estado antigo.
	//
	// Nil é uma janela ANTERIOR à política existir — não mexer nela é a resposta
	// certa, e é o que dispensa migração das linhas de pendente já gravadas.
	//
	// Falha aqui NÃO derruba a reversão: os grupos e as regras já voltaram, e
	// abortar agora deixaria o banco pela metade. Vira erro registrado, e a
	// política é reconciliada de novo na passada seguinte — o oposto do que
	// aconteceria se este erro cancelasse tudo.
	if snap.Policy != nil {
		if err := s.SetInputPolicy(*snap.Policy); err != nil {
			slog.Error("o estado anterior dos grupos e regras voltou, mas a política padrão não pôde ser restaurada",
				"err", err, "politica", *snap.Policy)
		}
	}
	if snap.ForwardPolicy != nil {
		if err := s.SetForwardPolicy(*snap.ForwardPolicy); err != nil {
			slog.Error("o estado anterior voltou, mas a política da forward não pôde ser restaurada",
				"err", err, "politica", *snap.ForwardPolicy)
		}
	}

	s.recordPreserved(p, merge)

	// A marca de "reversão em andamento" vem DEPOIS do commit acima, nunca
	// antes (N-2). Ela afirma que o estado anterior JÁ está no banco, e marcar
	// antes a tornava mentira exatamente no caso em que a transação falha: dali
	// em diante, confirmar responderia "o estado anterior já foi restaurado no
	// banco" sobre um banco intocado, e a verificação de expiração passaria a
	// reverter antes do prazo — tirando do operador justamente o tempo que este
	// mecanismo existe para dar a ele.
	if err := s.db.MarkPendingReverting(p.ID, s.now()); err != nil {
		// O pendente FICA e segue confirmável: sem a marca gravada, nada
		// no sistema sabe que a reversão começou, e é mais honesto tentar
		// tudo de novo na próxima passada (ReplaceFirewallGroupsAndRules é
		// idempotente) do que seguir com uma marca que não existe.
		return revertFailed(fmt.Errorf("estado anterior restaurado no banco, mas não foi possível marcar a reversão em andamento (a próxima passada tenta de novo): %w", err))
	}

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

	return s.finishRevert(ctx, p, reason)
}

// revertTarget confere o estado antes de a reversão aplicar qualquer coisa e
// devolve o que ela DEVE aplicar (issue #20a).
//
// Chamada com s.mu já travado.
//
// A conferência é entre três estados — o anterior (p.Snapshot), o pós-mutação
// (p.AppliedState) e o de agora — e o caminho comum é o que não mudou: banco
// igual ao pós-mutação significa que ninguém gravou no meio, e o alvo é o
// snapshot LITERAL, exatamente como antes desta correção.
//
// Quando há divergência, o alvo passa a ser a mistura (mergeRevertTarget) e ela
// é gravada no lugar do snapshot ANTES de ser aplicada. Isso não é
// contabilidade: o snapshot é o que responde "a reversão já terminou no banco?"
// (RevertSettled), e é essa resposta que LIBERA a trava das mutações quando a
// reconciliação não passa. Deixar lá o snapshot antigo, que a reversão nunca
// mais vai produzir, trancaria o operador do lado de fora do próprio painel —
// o beco C-6. Gravar antes de aplicar é seguro porque a mistura é idempotente:
// refazê-la com o alvo já no lugar do snapshot dá o mesmo alvo.
//
// Duas faltas diferentes, e elas NÃO dão no mesmo — a primeira versão deste
// comentário dizia que sim, e era falso:
//
//   - pós-mutação ILEGÍVEL (json quebrado): cai mesmo no comportamento
//     anterior, o snapshot inteiro, e aí sim a reversão é o "volte tudo" de
//     antes;
//   - pós-mutação NUNCA GRAVADO (applied_state vazio): AppliedStateOrSnapshot
//     responde o snapshot, e a comparação vira "base contra o banco de agora".
//     Toda linha que esta janela mudou parece de outro admin e é PRESERVADA. A
//     reversão passa a desfazer só o que alcança a chain input — o quase-oposto
//     de "volte tudo".
//
// O acesso do operador está garantido nos dois casos, mas por caminhos
// diferentes: no segundo quem garante é o limite da chain input, e não o
// fallback. O resto do que a janela mudou fica de pé — inclusive coisas que ela
// mudou de verdade, como as posições dos grupos de forward reescritas por uma
// reordenação.
func (s *Service) revertTarget(p *storage.PendingChange, base stateSnapshot) (revertMerge, error) {
	plain := revertMerge{target: base}

	var applied stateSnapshot
	if err := json.Unmarshal([]byte(p.AppliedStateOrSnapshot()), &applied); err != nil {
		slog.Error("o estado pós-mutação desta janela está ilegível; a reversão restaura o estado anterior INTEIRO, inclusive o que outro admin tenha gravado no meio",
			"err", err, "resumo", p.Summary)
		return plain, nil
	}
	current, err := s.readState()
	if err != nil {
		return plain, fmt.Errorf("ler o estado de agora para conferir com o pós-mutação desta janela: %w", err)
	}

	merge := mergeRevertTarget(base, applied, current)
	if !merge.merged() {
		return plain, nil
	}
	if err := validateSnapshotGroups(merge.target.Groups); err != nil {
		// Preservar a alteração de outro admin não pode custar a reversão em si.
		slog.Error("a reversão não pôde preservar o que outro admin gravou no meio da janela (o estado resultante não seria restaurável); o estado anterior volta INTEIRO",
			"err", err, "resumo", p.Summary)
		return plain, nil
	}
	blob, err := json.Marshal(merge.target)
	if err != nil {
		return plain, fmt.Errorf("serializar o estado que esta reversão vai aplicar: %w", err)
	}
	if err := s.db.SetPendingSnapshot(p.ID, string(blob)); err != nil {
		return plain, fmt.Errorf("gravar o estado que esta reversão vai aplicar: %w", err)
	}
	p.Snapshot = string(blob)
	return merge, nil
}

// recordPreserved é a linha de auditoria que faltava: o que esta reversão
// DEIXOU DE PÉ porque não era dela.
//
// Chamada com s.mu já travado, depois de a restauração ter commitado — só se
// registra o que já aconteceu.
//
// Falhar aqui não desfaz nada e não vira erro do chamador: a reversão está
// feita e o acesso do operador é o que está em jogo. Vira ERROR no journal,
// nunca silêncio.
func (s *Service) recordPreserved(p *storage.PendingChange, m revertMerge) {
	if !m.merged() {
		return
	}
	detail := fmt.Sprintf("A reversão de %q (aplicada por %s) desfez apenas o que esta janela mudou. Outro administrador gravou dentro dos 90 segundos e isto foi PRESERVADO: %s.",
		p.Summary, p.AppliedBy, joinPT(m.preserved))
	if len(m.dropped) > 0 {
		detail += fmt.Sprintf(" NÃO foi possível preservar (o grupo que a continha some com a reversão): %s.", joinPT(m.dropped))
	}
	slog.Warn("a reversão preservou a alteração que outro administrador gravou dentro da janela",
		"resumo", p.Summary, "preservado", m.preserved, "descartado", m.dropped)
	if err := s.db.CreateAuditLog(&storage.AuditLog{
		User:     "linkguard",
		Action:   "nft.pending.revert.preserved",
		Resource: "pending:" + p.ID,
		Details:  detail,
	}); err != nil {
		slog.Error("a reversão preservou a alteração de outro administrador, mas não foi possível registrar isso na auditoria", "err", err)
	}
}

// MarkWindowApplied registra o estado dos grupos e regras COMO ESTA JANELA OS
// DEIXOU — o passo que a mutação executa logo depois de escrever no banco
// (issue #20a).
//
// É o segundo dos dois estados de que a reversão precisa. Com só o snapshot
// (o de antes), reverter é "volte tudo" e apaga o que outro admin gravou no
// meio dos 90 segundos; com os dois, a reversão sabe qual parte do banco é obra
// desta janela — ver revertTarget.
//
// A hora de chamar é a mais próxima possível da escrita. O que ficar de fora
// desse intervalo é uma escrita alheia que esta janela vai adotar como sua e
// desfazer junto; hoje o intervalo é [arme, aqui], que são poucos statements —
// contra o intervalo antigo, que ia da leitura da trava até a reversão e
// incluía um `nft -c` inteiro.
//
// Janela que já não é esta (confirmada, revertida, substituída) é NO-OP e não
// é erro: o id na cláusula WHERE existe justamente para não escrever o estado
// desta mutação por cima da janela de outra pessoa.
func (s *Service) MarkWindowApplied(id string) error {
	if id == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	state, err := s.SnapshotState()
	if err != nil {
		return fmt.Errorf("ler o estado que esta alteração deixou no banco: %w", err)
	}
	return s.db.SetPendingAppliedState(id, state)
}

// finishRevert é a metade final da reversão — a que impõe ao firewall vivo o
// estado que já está no banco e, só então, apaga o pendente. É também a
// retomada inteira: quando a reversão já tinha restaurado o banco, é isto (e
// nada mais) que falta fazer.
//
// Chamada com s.mu já travado.
//
// DÍVIDA REGISTRADA, NÃO CORRIGIDA (I-2 da revisão final) — a reversão
// AUTOMÁTICA não atualiza o `nft_live_snapshot`. Esse snapshot é o que o boot
// restaura quando EnsureTable teve de recriar a tabela `inet linkguard` do zero
// (recuperação de desastre, como em 2026-08-10), e ele continua contendo a
// regra que acabou de ser revertida: numa recuperação dessas, ela RESSUSCITA no
// firewall vivo, sem janela, sem watchdog e sem ninguém para desfazê-la de novo.
// A reversão MANUAL não tem esse problema — o handler chama saveNftSnapshot
// depois do 200 (internal/api/handlers/confirm.go, em RevertPendingChange) —, e
// é justamente isso que a automática não tem como fazer: quem a dispara é o
// watchdog (WatchPending) ou o boot (RevertPendingOnBoot), sem requisição HTTP,
// e este pacote não pode importar internal/api/handlers nem duplicar a leitura
// do ruleset vivo sem virar dono de mais uma cópia da mesma verdade. Fechar isso
// é mover a atualização do snapshot para cá — trabalho de uma tarefa própria,
// porque o snapshot cobre o ruleset INTEIRO (host_wan, blocklist, port
// forwards), não só o que esta função reconcilia.
func (s *Service) finishRevert(ctx context.Context, p *storage.PendingChange, reason string) error {
	if err := s.Reconcile(ctx); err != nil {
		// O pendente FICA. Ver o doc-comment acima: apagá-lo aqui deixaria a
		// regra perigosa viva no nft sem ninguém para tentar de novo.
		return revertFailed(fmt.Errorf("estado anterior restaurado no banco, mas a reconciliação falhou (o pendente FICA, para a próxima passada tentar de novo): %w", err))
	}
	if err := s.db.ClearPendingChange(); err != nil {
		// O firewall vivo já está no estado anterior — o pendente sobrando
		// mantém a faixa na tela, o que é chato, mas a próxima passada
		// reconcilia de novo e apaga. Erro, não silêncio.
		return revertFailed(fmt.Errorf("estado anterior restaurado e reconciliado, mas não foi possível apagar a mudança pendente (a próxima passada tenta de novo): %w", err))
	}

	s.clearWindowMemory(p.ID)
	// Agora que o pendente saiu do banco, o arquivo de boot volta a descrever a
	// máquina — e o que ele passa a descrever é o estado ANTERIOR, que é
	// exatamente o que se quer: a regra não confirmada não vale mais aqui nem no
	// próximo boot (I-1).
	s.persistBootRuleset(ctx, "a mudança não confirmada foi revertida")
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

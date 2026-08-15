// Package firewallrules bridges the admin's rules living in the database
// (internal/storage) with the nftables reconcile that renders them
// (internal/nftables) — the same shape as internal/hosts (exec + db + nft
// combined into one small service), used here because internal/nftables
// must not import internal/storage (see nftables.StoredRule's doc comment).
package firewallrules

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// ImportedSettingKey guards the one-time import of pre-existing user_rules
// (design spec §4.1: "na primeira execução, as regras hoje existentes no
// nft são importadas para o banco"). Deliberately a settings flag — "has
// this ever run" — rather than "is firewall_rules empty": the latter would
// resurrect every rule from nft on the next boot after an admin
// legitimately deleted them all, which is exactly the false confidence this
// whole DB-backed model exists to eliminate. See ImportOnce's doc comment.
const ImportedSettingKey = "firewall_rules_imported"

// Alerter é o lado painel-facing da verificação de invariante do Reconcile:
// quando os grupos do sistema somem da lista depois da migração já ter
// rodado, o apply status já fica não-ok (a faixa aparece para quem abrir a
// tela do firewall), mas um bloqueio administrativo fora do ar é motivo para
// alcançar o operador onde ele estiver — inclusive pelos canais de
// notificação.
//
// Interface local, mesma abordagem de bootstrapdeps.Alerter e alerts.Notifier:
// evita que este pacote importe internal/alerts, e deixa o Service utilizável
// sem alerta nenhum (nil) nos testes e em qualquer chamador que não tenha um.
type Alerter interface {
	// FirewallSystemGroupsMissing abre o alerta crítico de "os bloqueios não
	// estão mais na lista; a forward não foi reconstruída".
	FirewallSystemGroupsMissing(detail string) error
	// FirewallSystemGroupsOK fecha esse alerta quando a lista volta ao normal.
	// Só anuncia recuperação se havia mesmo algo aberto.
	FirewallSystemGroupsOK()
	// FirewallChangeReverted registra que uma mudança de firewall aplicada e
	// NÃO confirmada foi desfeita sozinha (janela expirada ou boot dentro da
	// janela). É como o operador descobre, quando voltar, que a alteração
	// dele não está mais valendo e por quê — sem isto a máquina "desfaz
	// sozinha" em silêncio, que é a pior forma de um firewall se comportar.
	FirewallChangeReverted(detail string) error
}

// Service combines the DB (source of truth for the admin's rules) and the
// nftables service (renders them into the live user_rules chain).
type Service struct {
	db      *storage.DB
	nft     *nftables.Service
	alerter Alerter
	// now é a fonte de tempo do confirmar-ou-reverte (Fase C2), injetável
	// para os testes de expiração não precisarem dormir 90 segundos — teste
	// que dorme é teste que ninguém roda, e a expiração ficaria sem
	// cobertura justamente por ser lenta de exercitar.
	//
	// Um campo só, e não time.Now() espalhado: o instante de expiração
	// gravado no banco e a comparação que decide reverter TÊM que sair do
	// mesmo relógio, senão a janela dura um tempo diferente do que o painel
	// mostra.
	now func() time.Time
	// monoNow é o relógio MONOTÔNICO da janela de confirmação — separado de
	// `now` de propósito, e não por simetria.
	//
	// `now` é relógio de parede: é ele que grava o expires_at que o painel
	// desenha e que sobrevive a um restart. Só que esta máquina É o servidor
	// NTP da rede, e o chrony do Debian vem com `makestep` ligado: um passo do
	// relógio PARA TRÁS maior que a janela (RTC ruim depois de troca de disco,
	// `timedatectl set-time`, o primeiro sync depois de subir) empurraria o
	// expires_at para o futuro e o auto-revert não dispararia — o operador
	// ficaria trancado fora sem conseguir confirmar nem reverter. O deadline
	// monotônico não se move quando o relógio da máquina se move, e a janela
	// vence quando QUALQUER UM dos dois vencer (ver windowExpired).
	//
	// Injetável pelo mesmo motivo de `now`: é o que permite um teste provar o
	// salto de relógio sem esperar 90 segundos.
	monoNow func() time.Time
	// monoDeadline/monoDeadlineID são o prazo monotônico da janela aberta
	// NESTE processo. Depois de um restart não existe leitura monotônica
	// comparável (o expires_at volta do banco por time.Unix(), que não carrega
	// uma), e quem responde por aquele caso é RevertPendingOnBoot — que
	// reverte tenha expirado ou não. Daí o ID: o deadline só vale para o
	// pendente que este processo mesmo abriu.
	monoDeadline   time.Time
	monoDeadlineID string
	// (A marca de "reversão já começou" NÃO mora aqui: é a coluna
	// reverting_at de pending_firewall_change. Ela já foi um campo deste
	// struct, e memória de processo não servia — um restart no meio de uma
	// reversão travada apagava a marca, e o processo novo voltava a ACEITAR a
	// confirmação daquela mudança: o operador recebia "passa a valer
	// definitivamente" sobre uma alteração que já não existia no banco,
	// enquanto a regra que trancou o SSH dele seguia viva no nft, sem ninguém
	// retomando a reversão. Ver storage.PendingChange.RevertingAt.)
	//
	// lastRevert é a memória curta da última reversão concluída, só para
	// responder a verdade ao operador que apertou "Confirmar" um segundo
	// depois de o prazo vencer (m-7).
	lastRevert *revertRecord
	// mu serializa o confirmar-ou-reverte (abrir, confirmar, reverter). O
	// timer em memória (WatchPending) roda numa goroutine própria e o
	// operador aperta os botões por HTTP: sem isto, o "reverter agora" dele e
	// a expiração podem restaurar o mesmo snapshot duas vezes, ou uma
	// mutação nova abrir janela no meio de uma reversão.
	mu sync.Mutex
}

// NewService creates a firewallrules Service.
func NewService(db *storage.DB, nft *nftables.Service) *Service {
	return &Service{db: db, nft: nft, now: time.Now, monoNow: time.Now}
}

// SetAlerter liga o serviço de alertas depois da construção (o alerts.Service
// e este são criados no mesmo bloco do main, e nenhum precisa do outro para
// existir). Opcional: sem alerter, a verificação de invariante continua
// abortando e gravando o apply status — só não abre alerta.
func (s *Service) SetAlerter(a Alerter) { s.alerter = a }

// ImportOnce migrates a box upgrading from Phase A: its admin rules exist
// only inside nft's user_rules chain, identified by a volatile handle, and
// this brings them into the DB exactly once, preserving their evaluation
// order, then reconciles so nft is re-rendered from the DB (idempotent — the
// same rules, now DB-backed).
//
// Guarded by ImportedSettingKey, not by "is firewall_rules empty": an admin
// who deliberately deletes every rule after the import has already run must
// see an empty list stay empty on the next boot, not have nft's (by-then
// also empty, once ReconcileUserRules has flushed it) or stale live chain
// repopulate the table. Checking the flag first, before ever reading nft,
// is what makes that guarantee hold regardless of what nft currently
// contains.
//
// No live rule is ever dropped on the floor (spec §4.1, "nada é perdido").
// There are two ways a rule can fail to fit the 7-field model, and both take
// the same emergency exit — imported DISABLED, with the rule's original nft
// text preserved in Description:
//
//   - not validatable at all: ValidateRuleFields rejects the best-effort
//     RuleFields ListUserRules produced (a `jump`/`log`/`return`/
//     `masquerade`/`queue` rule has no accept/drop/reject verb to model).
//     I-4: this used to be a plain skip, so the rule never reached the DB
//     and the Reconcile below deleted it from the live chain — gone from the
//     machine with nothing left to show the admin it had ever existed.
//   - not faithfully representable: see the C-2 paragraph below.
//
// The guard is set (import considered "done") even when there was nothing to
// import: a box with zero pre-existing rules must not re-attempt this on
// every subsequent boot.
//
// C-2 (round-trip check): ValidateRuleFields alone only proves the
// best-effort RuleFields are syntactically safe — it says nothing about
// whether they still mean what the live rule actually said. parseRuleFields
// ignores any token it doesn't recognise, so a rule richer than the 7-field
// model best-effort-parses into whatever survived, not "unparsable": `ct
// state established,related counter accept` collapses to {Action: accept},
// which then re-renders as "accept everything"; `tcp flags syn /
// fin,syn,rst,ack counter drop` collapses to {Proto: tcp, Action: drop},
// which re-renders as "drop all TCP". Importing either as-is (then
// reconciled into nft on the very next line) would silently change what the
// rule does, breaking spec §4.1's "nada é perdido" promise in the one
// direction that matters most — silently, not with an error anyone would
// see. Every candidate is therefore re-rendered with buildRuleTokens (via
// nftables.ExpressionMatches) and compared word-for-word against the live
// rule's own normalised text before it is trusted: a match imports as
// today, an enabled row; a mismatch imports DISABLED, with the original nft
// text preserved in Description instead of the fields that couldn't
// reproduce it, so the admin sees exactly what could not be modelled and
// can re-author it deliberately, rather than the firewall changing meaning
// underneath them.
func (s *Service) ImportOnce(ctx context.Context) error {
	flag, err := s.db.GetSetting(ImportedSettingKey)
	if err != nil {
		return err
	}
	if flag != "" {
		return nil // already imported (or confirmed nothing to import) on a prior boot
	}

	existing, err := s.nft.ListUserRules(ctx)
	if err != nil {
		return err
	}

	var rows []storage.FirewallRule
	imported, importedDisabled := 0, 0
	for _, r := range existing {
		row := storage.FirewallRule{
			Enabled: true,
			Action:  r.RuleFields.Action,
			Iif:     r.RuleFields.Iif,
			Oif:     r.RuleFields.Oif,
			Saddr:   r.RuleFields.Saddr,
			Daddr:   r.RuleFields.Daddr,
			Proto:   r.RuleFields.Proto,
			Dport:   r.RuleFields.Dport,
		}
		switch verr := nftables.ValidateRuleFields(r.RuleFields); {
		case verr != nil:
			// I-4: not validatable at all (`jump`, `log`, `return`,
			// `masquerade`, `queue`, `meta mark set …` — anything without an
			// accept/drop/reject verb). Skipping it used to mean the rule
			// never reached the DB and the Reconcile on the very next line
			// deleted it from the live chain: the rule vanished from the
			// machine with no trace anywhere, which is the exact opposite of
			// spec §4.1's "nada é perdido". Same emergency exit as the
			// unmodellable case below — imported disabled, raw text kept —
			// so the admin at least sees what was there and can re-author
			// it deliberately.
			row.Enabled = false
			row.Description = r.Raw
			importedDisabled++
			slog.Warn("regra existente do user_rules não pôde ser validada pelo modelo de campos; importada DESATIVADA, com o texto original preservado na descrição para revisão manual",
				"handle", r.Handle, "raw", r.Raw, "err", verr)
		case !nftables.ExpressionMatches(r.RuleFields, r.Raw):
			row.Enabled = false
			row.Description = r.Raw
			importedDisabled++
			slog.Warn("regra existente não pôde ser fielmente representada pelos campos estruturados (informação seria perdida ao re-renderizar); importada DESATIVADA, com o texto original preservado na descrição para revisão manual",
				"handle", r.Handle, "raw", r.Raw, "campos_interpretados", r.RuleFields)
		}
		rows = append(rows, row)
		imported++
	}

	// I-5 (already fixed, reused here): a single transaction inserts every
	// row and flips the guard together, so a crash or DB error partway
	// through can never leave the guard set with only some rules landed, or
	// vice versa. Enabled is honoured exactly as set on each row above —
	// unlike CreateFirewallRule, which always forces it true — which is
	// exactly what lets an unmodellable rule import disabled instead of
	// enabled-then-immediately-wrong.
	if err := s.db.ImportFirewallRules(rows, ImportedSettingKey, "true"); err != nil {
		return err
	}

	slog.Info("importação única das regras existentes de user_rules para o banco concluída",
		"importadas", imported,
		"importadas_desativadas_nao_modeladas", importedDisabled, "total_no_nft", len(existing))

	return s.Reconcile(ctx)
}

// CheckPending validates, with a parse-only `nft -c` dry run
// (nftables.Service.CheckUserRules), the user_rules chain that candidate —
// the DB rows exactly as they would read immediately after the mutation the
// caller is about to make — would render, before that mutation's DB write
// happens (C-1, design spec §4.1/§8). candidate must reflect every rule
// that would end up enabled in the DB, not just the one being changed:
// `nft -c` validates the whole resulting chain, the same one Reconcile
// renders immediately after the DB write actually lands. On failure the
// caller must not write anything to the DB — the error carries nft's own
// rejection message, so field-level validation (ValidateRuleFields) not
// catching something doesn't mean nothing ever will.
func (s *Service) CheckPending(ctx context.Context, candidate []storage.FirewallRule) error {
	return s.nft.CheckUserRules(ctx, ToStoredRules(candidate))
}

// CheckPendingGroups is CheckPending's counterpart for the world of groups
// (Fase C1): the same parse-only `nft -c` pre-flight, over the candidate set
// of groups exactly as the DB would read immediately after the mutation the
// caller is about to make, run BEFORE that mutation's DB write happens.
//
// candidate must be the COMPLETE set of groups, not just the one being
// changed: nftables.CheckGroups validates each group's chain AND the forward
// chain that reaches them, which is rebuilt from all of them at once — the
// very same rendering Reconcile applies for real right after the write
// lands.
func (s *Service) CheckPendingGroups(ctx context.Context, candidate []nftables.StoredGroup) error {
	return s.nft.CheckGroups(ctx, candidate)
}

// StoredGroups converte as linhas do banco na visão que internal/nftables
// entende, encaixando cada regra no seu grupo.
//
// Devolver erro aqui é obrigatório e nunca substituível por uma lista vazia:
// ReconcileGroups trata lista vazia como o comando legítimo "o admin não tem
// grupo nenhum" e, obedecendo, esvazia a forward — inclusive os bloqueios
// administrativos, que desde que ela virou uma lista ordenada só também são
// itens dela — e apaga todas as chains grp_. Um SELECT que falhou virando
// lista vazia seria o
// firewall inteiro do admin desaparecendo por causa de um erro de leitura
// (ver o CONTRATO DO CHAMADOR no doc-comment de ReconcileGroups).
//
// Exportada porque a API precisa exatamente desta montagem em três lugares
// (a visão geral, a listagem de grupos e o pré-voo de toda mutação), e uma
// segunda cópia dela nos handlers divergiria justamente no ponto em que
// mentir é mais caro: qual regra pertence a qual chain.
func (s *Service) StoredGroups() ([]nftables.StoredGroup, error) {
	rules, err := s.db.ListFirewallRules()
	if err != nil {
		return nil, fmt.Errorf("ler as regras: %w", err)
	}
	return s.StoredGroupsWithRules(rules)
}

// StoredGroupsWithRules é StoredGroups com o conjunto de regras dado pelo
// chamador em vez do que está gravado — é o que permite ao pré-voo `nft -c`
// de uma mutação de REGRA validar o firewall que resultaria dela sem nada
// ter sido escrito ainda (a ordem obrigatória: validar → conferir com o nft
// → gravar → reconciliar).
//
// Regra órfã (group_id que não aponta para grupo nenhum) é deixada de fora e
// registrada: renderizá-la em chain nenhuma seria mostrá-la no painel sem
// existir no firewall.
func (s *Service) StoredGroupsWithRules(rules []storage.FirewallRule) ([]nftables.StoredGroup, error) {
	groups, err := s.db.ListFirewallGroups()
	if err != nil {
		return nil, fmt.Errorf("ler os grupos de regras: %w", err)
	}

	known := make(map[string]bool, len(groups))
	for _, g := range groups {
		known[g.ID] = true
	}
	byGroup := make(map[string][]nftables.StoredRule, len(groups))
	for _, r := range rules {
		if !known[r.GroupID] {
			slog.Warn("regra sem grupo válido foi ignorada na reconciliação; ela aparece no painel mas não existe no firewall",
				"regra", r.ID, "group_id", r.GroupID)
			continue
		}
		byGroup[r.GroupID] = append(byGroup[r.GroupID], nftables.StoredRule{
			ID:          r.ID,
			Position:    r.Position,
			Enabled:     r.Enabled,
			Description: r.Description,
			Fields: nftables.RuleFields{
				Action: r.Action, Iif: r.Iif, Oif: r.Oif,
				Saddr: r.Saddr, Daddr: r.Daddr, Proto: r.Proto, Dport: r.Dport,
			},
		})
	}

	out := make([]nftables.StoredGroup, 0, len(groups))
	for _, g := range groups {
		stored := ToStoredGroup(g)
		stored.Rules = byGroup[g.ID]
		out = append(out, stored)
	}
	return out, nil
}

// ToStoredGroup converte o grupo persistido na visão de renderização do
// nftables. As regras são associadas separadamente por StoredGroupsWithRules.
//
// Esta é a ÚNICA conversão do projeto, e o motivo de ela ser única é caro. Cada
// campo aqui decide comportamento no kernel, e perder um compila, passa em todo
// o resto da suíte, e só morde depois:
//
//   - ConnState decide se a linha do jump leva `ct state new`. Este é o caminho
//     pelo qual a escolha do operador chega ao renderizador (e ao pré-voo
//     `nft -c` que o precede): deixá-lo de fora seria gravar a restrição no
//     banco, mostrá-la na tela e nunca aplicá-la — o firewall fazendo o
//     contrário do que o painel afirma, com apply_status ok.
//   - Scope decide em QUAL chain o grupo é alcançado. Perdê-lo faz o pré-voo
//     validar um grupo de escopo input como se fosse da forward: valida uma
//     coisa e aplica outra.
//   - Kind marca grupo do sistema. As proteções de renomear e apagar pousam
//     em cima dele; vazio, um grupo do sistema passa a parecer do admin e ganha
//     (ou perde) proteções que não deveria.
//
// Enquanto existiam duas cópias desta função, um campo novo tinha 50% de chance
// de entrar só numa delas — foi o que aconteceu com ConnState. TestToStoredGroup
// ModelsAndMappingStayInSync guarda a fronteira por reflexão: acrescentar campo
// em storage.FirewallGroup e esquecer de mapeá-lo deixa o teste vermelho.
func ToStoredGroup(g storage.FirewallGroup) nftables.StoredGroup {
	return nftables.StoredGroup{
		ID: g.ID, Name: g.Name, ChainName: g.ChainName, Position: g.Position,
		Enabled: g.Enabled, CondSaddr: g.CondSaddr, CondDaddr: g.CondDaddr,
		CondIif: g.CondIif, Fallthrough: g.Fallthrough, Kind: g.Kind, Scope: g.Scope,
		ConnState: g.ConnState,
	}
}

// ApplyStatusKey persists the outcome of the most recent user_rules
// reconcile (design spec §4.1, C-3). Reconcile is called from two places
// that never share an HTTP response — the API handlers (CreateRule,
// UpdateRule, ..., Rollback) and the unconditional boot-time call in
// cmd/linkguard-fw/main.go — and the boot case in particular has no status
// code or client to surface a failure to at all. Persisting here, inside
// Reconcile itself, means both call sites get this for free instead of each
// needing its own copy of the same bookkeeping, and a boot-time reconcile
// failure is no longer invisible: it is exactly as discoverable as any
// other mutation's, the next time anyone opens the panel.
const ApplyStatusKey = "firewall_rules_apply"

// ApplyStatus is ApplyStatusKey's persisted shape — deliberately the same
// {ok, error, at} contract as internal/api/handlers.applyStatus (NTP,
// DHCP/DNS), a proven pattern for exactly this "was the last apply actually
// applied" question, kept here as an independent, exported type: this
// package must not import internal/api/handlers (the dependency runs the
// other way), so the type can't be shared directly, only its json shape.
type ApplyStatus struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	At    int64  `json:"at"` // unix seconds

	// BootPersistError é "as regras ENTRARAM no kernel, mas o arquivo de boot
	// não foi gravado" — o estado que o §10 da validação em VM mediu e que o
	// painel reportava como `{"ok": true}`. Campo próprio, e não Error, porque
	// as duas coisas são diferentes e o operador age de forma diferente em cada
	// uma: com Error preenchido, o que ele configurou pode não estar valendo e
	// ele precisa conferir a "Visão geral" antes de confiar nas regras; com só
	// este preenchido, o que ele configurou ESTÁ valendo — o que não está é o
	// próximo boot. Enfiar isto em Error faria a faixa vermelha dizer que o
	// apply falhou, e o operador desfaria um trabalho que funcionou.
	//
	// OK fica falso mesmo assim (ver recordApplyStatus): `ok: true` com o
	// arquivo de boot para trás é a mentira mais direta que este apply status
	// contava, e um consumidor que só saiba ler `ok` tem que ver um problema —
	// nunca um verde sintético.
	BootPersistError string `json:"boot_persist_error,omitempty"`
}

// Reconcile loads every stored group with its rules (enabled or not, in
// position order) and re-renders the whole group world from it — one chain
// per group plus the forward chain that reaches them — because the DB is the
// source of truth and nft is the rendered result (design spec §4.1). Safe
// and cheap to call on every boot and after every mutation, exactly like the
// other reconciles in this project. The outcome — success or failure, with
// nft's own error message — is always persisted under ApplyStatusKey (see
// LastApplyStatus), even when this is called from a boot path with nobody
// watching synchronously.
//
// Fase C1: this used to render the flat user_rules chain. Since the forward
// chain left ReconcileStructuralChains, this is the ONLY thing that
// reconciles forward — a boot that doesn't reach here leaves the forward
// chain with no owner at all.
// I-3 da revisão final — a LEITURA do banco e a reconstrução acontecem sob o
// mesmo lock (nftables.ReconcileGroupsFrom). Antes, esta função lia os grupos e
// só então chamava ReconcileGroups, e nada serializava as duas metades: uma
// reversão automática que restaurasse o banco no meio desse intervalo era
// desfeita por esta passada, que escrevia no kernel o estado que tinha lido
// ANTES da restauração. Ver o doc-comment de ReconcileGroupsFrom para a
// intercalação inteira.
func (s *Service) Reconcile(ctx context.Context) error {
	// Os dois erros da leitura viajam para fora do closure porque cada um tem um
	// tratamento próprio aqui embaixo (apply status; apply status + alerta
	// crítico + log), e lá dentro só cabe abortar. O closure roda síncrono,
	// dentro da chamada abaixo — não há concorrência entre escrever e ler estas
	// duas variáveis.
	var loadErr, missingErr error
	applyErr := s.nft.ReconcileGroupsFrom(ctx, func() ([]nftables.StoredGroup, error) {
		groups, err := s.StoredGroups()
		if err != nil {
			// Abortar antes de qualquer comando do nft: ReconcileGroups com lista
			// vazia apaga TODAS as chains de grupo e reduz a forward aos
			// bloqueios. Um erro de leitura não pode ser confundido com "o admin
			// não tem grupo nenhum".
			loadErr = err
			return nil, err
		}

		// A defesa: depois da migração, a chain forward só pode ser reconstruída
		// se os dois grupos do sistema estiverem na lista — senão ela sairia sem
		// os bloqueios administrativos, e isso não pareceria erro. Vem ANTES da
		// reconstrução de propósito: nenhum comando do nft é emitido, então a
		// forward viva continua sendo a última que foi aplicada com sucesso, com
		// os bloqueios dentro. Ver ensureSystemGroupsPresent.
		if err := s.ensureSystemGroupsPresent(groups); err != nil {
			missingErr = err
			return nil, err
		}
		return groups, nil
	})
	if loadErr != nil {
		s.recordApplyStatus(loadErr)
		return loadErr
	}
	if missingErr != nil {
		s.recordApplyStatus(missingErr)
		if s.alerter != nil {
			_ = s.alerter.FirewallSystemGroupsMissing(missingErr.Error())
		}
		slog.Error("reconciliação abortada antes de tocar no nft: os grupos do sistema não estão na lista", "err", missingErr)
		return missingErr
	}
	s.recordApplyStatus(applyErr)

	// I-8: an enabled rule that doesn't render is recorded as a not-ok
	// apply (above) — the panel's standing banner names it, which is the
	// surface that actually reaches the admin — but it is NOT returned to
	// the caller. The mutation that triggered this reconcile did land and
	// everything renderable IS in the firewall; turning that into the
	// handler's generic 500 ("erro interno do servidor", details only in
	// the journal) would report the admin's own successful change as a
	// failure while telling them less than the banner already does.
	//
	// ATENÇÃO — o teste de identidade abaixo não é estilo. ReconcileGroups
	// pode devolver, na MESMA passada, um erro que embrulha o
	// SkippedRulesError e também a recusa do nft (ver o comentário do %w no
	// fim daquela função). Um errors.As solto — como esta função fazia no
	// tempo da user_rules — daria verdadeiro nesse caso composto e
	// converteria em sucesso uma passada em que a chain forward não foi
	// reconstruída. Quem chama seguiria em frente achando que aplicou; é
	// exatamente isso que faria a migração remover a chain user_rules com a
	// forward ainda quebrada. Só é não-fatal quando a ÚNICA coisa que
	// aconteceu foi regra pulada — isto é, quando o erro devolvido É o
	// SkippedRulesError, não algo que o embrulha.
	// (errors.As/errors.Is não servem aqui: os dois percorrem a cadeia de
	// embrulho e dariam verdadeiro para o caso composto, que é justamente o
	// que precisa ser fatal.)
	_, onlySkipped := applyErr.(*nftables.SkippedRulesError)

	// A recuperação só é anunciada DEPOIS de o apply ter dado certo, e é a
	// mesma distinção Enabled × Applied que este projeto aplica em todo o
	// resto. O texto que vai para o Telegram e para o webhook afirma que "a
	// chain forward foi reconstruída com os bloqueios"; a lista estar
	// completa não reconstrói nada — quem reconstrói é o ReconcileGroups
	// acima, e ele pode falhar. Anunciar antes fecharia o alerta crítico e
	// mandaria um "voltou" para uma máquina cuja forward continua sendo a
	// antiga.
	//
	// Regra pulada não impede o anúncio: ela é uma regra do admin que não
	// renderizou, e a forward foi reconstruída COM os bloqueios do mesmo
	// jeito — que é exatamente o que este alerta fala a respeito. (O apply
	// status já ficou não-ok por causa dela; a faixa do painel é a superfície
	// certa para isso.)
	if s.alerter != nil && (applyErr == nil || onlySkipped) {
		s.alerter.FirewallSystemGroupsOK()
	}

	if onlySkipped {
		return nil
	}
	return applyErr
}

// recordApplyStatus grava o resultado da passada — e, junto dele, o estado do
// arquivo de boot.
//
// A leitura de PersistState vale para TODOS os caminhos que chegam aqui,
// inclusive os que abortam antes de tocar no nft (loadErr, missingErr): o
// arquivo de boot continua para trás de qualquer jeito, e essa é a pergunta
// que este campo responde. Attempted falso — dry-run, ou nenhum Persist ainda
// nesta sessão — não vira nada: "não sei" nunca é gravado como problema.
func (s *Service) recordApplyStatus(applyErr error) {
	st := ApplyStatus{OK: applyErr == nil, At: time.Now().Unix()}
	if applyErr != nil {
		st.Error = applyErr.Error()
	}
	if s.nft != nil {
		if ps := s.nft.PersistState(); ps.Attempted && !ps.OK {
			st.BootPersistError = ps.Err
			st.OK = false
		}
	}
	b, err := json.Marshal(st)
	if err != nil {
		return // never happens for this fixed shape; nothing sane to do if it did
	}
	if err := s.db.SetSetting(ApplyStatusKey, string(b)); err != nil {
		slog.Warn("não foi possível persistir o status da última aplicação de user_rules", "err", err)
	}
}

// LastApplyStatus returns the persisted result of the most recent
// user_rules reconcile, or nil if Reconcile has never run yet — the same
// "never attempted" vs "attempted and failed" distinction as
// internal/api/handlers.lastApplyStatus/lastFirewallApplyStatus, so a
// caller (the rules API handler) can tell "nothing to worry about yet" from
// "actively broken" instead of defaulting one into looking like the other.
func (s *Service) LastApplyStatus() *ApplyStatus {
	raw, _ := s.db.GetSetting(ApplyStatusKey)
	if raw == "" {
		return nil
	}
	var st ApplyStatus
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return nil
	}
	return &st
}

// ToStoredRules converts the DB rows into nftables' own StoredRule shape —
// internal/nftables cannot import internal/storage (see StoredRule's doc
// comment), so this conversion always happens on the caller's side.
func ToStoredRules(rows []storage.FirewallRule) []nftables.StoredRule {
	out := make([]nftables.StoredRule, len(rows))
	for i, r := range rows {
		out[i] = nftables.StoredRule{
			ID:       r.ID,
			Position: r.Position,
			Enabled:  r.Enabled,
			Fields: nftables.RuleFields{
				Action: r.Action, Iif: r.Iif, Oif: r.Oif,
				Saddr: r.Saddr, Daddr: r.Daddr, Proto: r.Proto, Dport: r.Dport,
			},
			Description: r.Description,
		}
	}
	return out
}

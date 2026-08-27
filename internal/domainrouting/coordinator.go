// Package domainrouting liga a intenção persistida de regras por domínio ao
// runtime alimentado por dnstap. Ele é a única fronteira que traduz LinkID em
// mark e, portanto, o único lugar que pode suspender uma intenção ativa quando
// a WAN ou o grupo de bloqueio deixam de ser seguros.
package domainrouting

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/giovanibalarini/linkguard-fw/internal/domtargets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/validate"
)

var (
	// ErrInvalid identifica uma requisição que não pode representar uma
	// intenção segura.
	ErrInvalid = errors.New("intenção por domínio inválida")
	// ErrNotFound identifica um alvo que já não existe.
	ErrNotFound = errors.New("alvo por domínio não encontrado")
	// ErrConflict identifica dois alvos com o mesmo domínio normalizado.
	ErrConflict = errors.New("domínio já cadastrado")
)

const (
	ReasonBootPending           = "boot_pending"
	ReasonBlockingGroupMissing  = "blocking_group_missing"
	ReasonBlockingGroupDisabled = "blocking_group_disabled"
	ReasonLinkMissing           = "link_missing"
	ReasonLinkDisabled          = "link_disabled"
	ReasonLinkUnconfigured      = "link_unconfigured"
	ReasonLinkOffline           = "link_offline"
	ReasonLinkNotReady          = "link_not_ready"
	ReasonInvalidIntent         = "invalid_intent"
)

// Runtime é a parte do alimentador que o coordenador precisa. A troca da lista
// é atômica dentro de domtargets; Estado fornece a visão do índice e do kernel.
type Runtime interface {
	DefinirAlvos([]domtargets.Alvo)
	Estado(context.Context) domtargets.Estado
}

// Input contém apenas os campos editáveis. Stage não aparece aqui de
// propósito: promoção e retorno a ensaio usam SetStage explicitamente.
type Input struct {
	Domain     string `json:"domain"`
	Capability string `json:"capability"`
	LinkID     string `json:"link_id"`
	Note       string `json:"note"`
}

// TargetView combina a intenção persistida, a decisão efetiva desta rodada e
// a telemetria transitória. Só a primeira parte sobrevive a um reboot.
type TargetView struct {
	ID               string    `json:"id"`
	Domain           string    `json:"domain"`
	Capability       string    `json:"capability"`
	Stage            string    `json:"stage"`
	EffectiveStage   string    `json:"effective_stage"`
	LinkID           string    `json:"link_id"`
	LinkName         string    `json:"link_name"`
	LinkStatus       string    `json:"link_status,omitempty"`
	Mark             uint32    `json:"mark"`
	Note             string    `json:"note"`
	Suspended        bool      `json:"suspended"`
	SuspensionReason string    `json:"suspension_reason,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`

	NoKernel            *int   `json:"no_kernel"`
	NoIndex             int    `json:"no_index"`
	AtLimit             bool   `json:"at_limit"`
	Limit               int    `json:"limit"`
	Overflows           uint64 `json:"overflows"`
	Rejected            uint64 `json:"rejected"`
	RejectedOwn         uint64 `json:"rejected_own"`
	NoRefcountSlot      uint64 `json:"no_refcount_slot"`
	RoutedIPv6Discarded uint64 `json:"routed_ipv6_discarded"`
	LastLearned         int64  `json:"last_learned"`
	Rotation            int    `json:"rotation"`
	RotationTruncated   bool   `json:"rotation_truncated"`
}

// State é a resposta observável da capacidade. Runtime contém os totais do
// alimentador/kernel; Targets torna cada intenção atribuível.
type State struct {
	Ready                bool              `json:"ready"`
	Generation           uint64            `json:"generation"`
	LastReconciledAt     time.Time         `json:"last_reconciled_at"`
	LastError            string            `json:"last_error,omitempty"`
	BlockingGroupPresent bool              `json:"blocking_group_present"`
	BlockingGroupEnabled bool              `json:"blocking_group_enabled"`
	RoutingIPv6Supported bool              `json:"routing_ipv6_supported"`
	Runtime              domtargets.Estado `json:"runtime"`
	Targets              []TargetView      `json:"targets"`
}

// Coordinator serializa CRUD, snapshots e publicação no runtime. Isso evita
// que uma promoção concorra com uma mudança de estado da WAN e publique uma
// combinação que nunca existiu no banco.
type Coordinator struct {
	mu      sync.Mutex
	db      *storage.DB
	runtime Runtime

	ready            bool
	generation       uint64
	lastReconciledAt time.Time
	lastError        string
	blockPresent     bool
	blockEnabled     bool
	targets          []TargetView
}

func New(db *storage.DB, runtime Runtime) *Coordinator {
	return &Coordinator{db: db, runtime: runtime, targets: []TargetView{}}
}

// Prepare abre o gate de boot e só o mantém aberto se um snapshot completo
// puder ser publicado. Antes dele, Reconcile sempre força intenções a ensaio.
func (c *Coordinator) Prepare(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.ready = true
	if err := c.reconcileLocked(ctx); err != nil {
		c.ready = false
		return err
	}
	return nil
}

// Reconcile lê alvos, links e grupo numa única transação read-only e publica
// a lista completa no runtime de uma vez.
func (c *Coordinator) Reconcile(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reconcileLocked(ctx)
}

func (c *Coordinator) reconcileLocked(ctx context.Context) error {
	snapshot, err := c.db.DomainRoutingSnapshot(ctx)
	if err != nil {
		c.lastError = err.Error()
		return err
	}

	links := make(map[string]storage.Link, len(snapshot.Links))
	for _, link := range snapshot.Links {
		links[link.ID] = link
	}

	views := make([]TargetView, 0, len(snapshot.Targets))
	alvos := make([]domtargets.Alvo, 0, len(snapshot.Targets))
	for _, stored := range snapshot.Targets {
		view, alvo, valid := c.resolve(stored, links, snapshot)
		views = append(views, view)
		if valid {
			alvos = append(alvos, alvo)
		}
	}

	if c.runtime != nil {
		c.runtime.DefinirAlvos(alvos)
	}
	c.targets = views
	c.blockPresent = snapshot.BlocklistPresent
	c.blockEnabled = snapshot.BlocklistEnabled
	c.lastReconciledAt = time.Now()
	c.lastError = ""
	c.generation++
	return nil
}

func (c *Coordinator) resolve(stored storage.DomainTarget, links map[string]storage.Link, snapshot storage.DomainRoutingDBSnapshot) (TargetView, domtargets.Alvo, bool) {
	view := TargetView{
		ID: stored.ID, Domain: stored.Domain, Capability: stored.Capability,
		Stage: stored.Stage, EffectiveStage: stored.Stage,
		LinkID: stored.LinkID, LinkName: stored.LinkName, Mark: stored.Mark,
		Note: stored.Note, CreatedAt: stored.CreatedAt, UpdatedAt: stored.UpdatedAt,
	}

	domain, ok := validate.NormalizeDomainTarget(stored.Domain)
	if !ok || (stored.Capability != storage.DomainCapBarrar && stored.Capability != storage.DomainCapDirecionar) ||
		(stored.Stage != storage.DomainStageEnsaio && stored.Stage != storage.DomainStageAtivo) {
		suspend(&view, ReasonInvalidIntent)
		return view, domtargets.Alvo{}, false
	}
	view.Domain = domain

	alvo := domtargets.Alvo{
		Dominio: domain, Capacidade: domtargets.Capacidade(stored.Capability),
		Estagio: domtargets.Estagio(stored.Stage),
	}
	if stored.Capability == storage.DomainCapDirecionar {
		link, found := links[stored.LinkID]
		if found {
			view.LinkName = link.Name
			view.LinkStatus = strings.ToLower(strings.TrimSpace(link.Status))
			view.Mark = uint32(link.TableID)
			alvo.Marca = view.Mark
		} else {
			view.LinkName, view.LinkStatus, view.Mark = "", "", 0
		}
		if stored.Stage == storage.DomainStageAtivo {
			switch {
			case !c.ready:
				suspend(&view, ReasonBootPending)
			case !found:
				suspend(&view, ReasonLinkMissing)
			case !link.Enabled:
				suspend(&view, ReasonLinkDisabled)
			case strings.TrimSpace(link.Interface) == "" || link.TableID <= 0:
				suspend(&view, ReasonLinkUnconfigured)
			case view.LinkStatus == "offline":
				suspend(&view, ReasonLinkOffline)
			case view.LinkStatus != "online" && view.LinkStatus != "degraded":
				suspend(&view, ReasonLinkNotReady)
			}
		}
	} else if stored.Stage == storage.DomainStageAtivo {
		switch {
		case !c.ready:
			suspend(&view, ReasonBootPending)
		case !snapshot.BlocklistPresent:
			suspend(&view, ReasonBlockingGroupMissing)
		case !snapshot.BlocklistEnabled:
			suspend(&view, ReasonBlockingGroupDisabled)
		}
	}

	alvo.Estagio = domtargets.Estagio(view.EffectiveStage)
	return view, alvo, true
}

func suspend(view *TargetView, reason string) {
	view.Suspended = true
	view.SuspensionReason = reason
	view.EffectiveStage = storage.DomainStageEnsaio
}

// State copia primeiro a configuração publicada e só depois consulta o
// runtime. Assim uma leitura lenta de nft não segura o lock de CRUD/failover.
func (c *Coordinator) State(ctx context.Context) State {
	c.mu.Lock()
	state := State{
		Ready: c.ready, Generation: c.generation,
		LastReconciledAt: c.lastReconciledAt, LastError: c.lastError,
		BlockingGroupPresent: c.blockPresent, BlockingGroupEnabled: c.blockEnabled,
		RoutingIPv6Supported: false,
		Targets:              append([]TargetView(nil), c.targets...),
	}
	runtime := c.runtime
	c.mu.Unlock()

	if runtime == nil {
		return state
	}
	state.Runtime = runtime.Estado(ctx)
	metrics := make(map[string]domtargets.EstadoDominio, len(state.Runtime.Dominios))
	for _, row := range state.Runtime.Dominios {
		metrics[row.Dominio] = row
	}
	for idx := range state.Targets {
		row, ok := metrics[state.Targets[idx].Domain]
		if !ok {
			continue
		}
		mergeMetrics(&state.Targets[idx], row)
	}
	return state
}

func mergeMetrics(view *TargetView, row domtargets.EstadoDominio) {
	if row.NoKernel != nil {
		value := *row.NoKernel
		view.NoKernel = &value
	}
	view.NoIndex = row.NoIndice
	view.AtLimit = row.NoTeto
	view.Limit = row.Teto
	view.Overflows = row.Estouros
	view.Rejected = row.Recusados
	view.RejectedOwn = row.RecusadosProprios
	view.NoRefcountSlot = row.SemVaga
	view.RoutedIPv6Discarded = row.DirecionadoV6
	view.LastLearned = row.UltimoAprendizado
	view.Rotation = row.Rotatividade
	view.RotationTruncated = row.RotatividadeTruncada
}

// Create sempre cria em ensaio, independentemente de qualquer campo que um
// cliente tente inferir. SetStage é a única promoção.
func (c *Coordinator) Create(ctx context.Context, input Input) (State, error) {
	target, err := c.targetFromInput(input)
	if err != nil {
		return State{}, err
	}

	c.mu.Lock()
	if err := c.ensureUniqueDomain(target.Domain, ""); err != nil {
		c.mu.Unlock()
		return State{}, err
	}
	if err := c.db.CreateDomainTarget(&target); err != nil {
		c.mu.Unlock()
		return State{}, classifyStorageError(err)
	}
	if err := c.reconcileLocked(ctx); err != nil {
		c.mu.Unlock()
		return State{}, err
	}
	c.mu.Unlock()
	return c.State(ctx), nil
}

// Update preserva o estágio persistido.
func (c *Coordinator) Update(ctx context.Context, id string, input Input) (State, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return State{}, fmt.Errorf("%w: id ausente", ErrInvalid)
	}
	target, err := c.targetFromInput(input)
	if err != nil {
		return State{}, err
	}

	c.mu.Lock()
	if err := c.ensureUniqueDomain(target.Domain, id); err != nil {
		c.mu.Unlock()
		return State{}, err
	}
	if err := c.db.UpdateDomainTarget(id, target); err != nil {
		c.mu.Unlock()
		return State{}, classifyStorageError(err)
	}
	if err := c.reconcileLocked(ctx); err != nil {
		c.mu.Unlock()
		return State{}, err
	}
	c.mu.Unlock()
	return c.State(ctx), nil
}

// SetStage é a única operação que promove uma intenção para ativo.
func (c *Coordinator) SetStage(ctx context.Context, id, stage string) (State, error) {
	id, stage = strings.TrimSpace(id), strings.TrimSpace(stage)
	if id == "" || (stage != storage.DomainStageEnsaio && stage != storage.DomainStageAtivo) {
		return State{}, fmt.Errorf("%w: estágio deve ser ensaio ou ativo", ErrInvalid)
	}
	c.mu.Lock()
	if err := c.db.SetDomainTargetStage(id, stage); err != nil {
		c.mu.Unlock()
		return State{}, classifyStorageError(err)
	}
	if err := c.reconcileLocked(ctx); err != nil {
		c.mu.Unlock()
		return State{}, err
	}
	c.mu.Unlock()
	return c.State(ctx), nil
}

func (c *Coordinator) Delete(ctx context.Context, id string) (State, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return State{}, fmt.Errorf("%w: id ausente", ErrInvalid)
	}
	c.mu.Lock()
	if err := c.db.DeleteDomainTargetByID(id); err != nil {
		c.mu.Unlock()
		return State{}, classifyStorageError(err)
	}
	if err := c.reconcileLocked(ctx); err != nil {
		c.mu.Unlock()
		return State{}, err
	}
	c.mu.Unlock()
	return c.State(ctx), nil
}

func (c *Coordinator) targetFromInput(input Input) (storage.DomainTarget, error) {
	domain, ok := validate.NormalizeDomainTarget(input.Domain)
	if !ok {
		return storage.DomainTarget{}, fmt.Errorf("%w: domínio inválido", ErrInvalid)
	}
	input.Capability = strings.TrimSpace(input.Capability)
	input.LinkID = strings.TrimSpace(input.LinkID)
	input.Note = strings.TrimSpace(input.Note)
	if input.Capability != storage.DomainCapBarrar && input.Capability != storage.DomainCapDirecionar {
		return storage.DomainTarget{}, fmt.Errorf("%w: capacidade deve ser barrar ou direcionar", ErrInvalid)
	}
	if input.Capability == storage.DomainCapBarrar && input.LinkID != "" {
		return storage.DomainTarget{}, fmt.Errorf("%w: link_id não é aceito para bloqueio", ErrInvalid)
	}
	if input.Capability == storage.DomainCapDirecionar && input.LinkID == "" {
		return storage.DomainTarget{}, fmt.Errorf("%w: link_id é obrigatório para direcionamento", ErrInvalid)
	}
	if utf8.RuneCountInString(input.Note) > storage.MaxDomainTargetNoteRunes || strings.ContainsFunc(input.Note, unicode.IsControl) {
		return storage.DomainTarget{}, fmt.Errorf("%w: observação inválida", ErrInvalid)
	}

	target := storage.DomainTarget{Domain: domain, Capability: input.Capability, LinkID: input.LinkID, Note: input.Note}
	if input.Capability == storage.DomainCapDirecionar {
		link, err := c.db.GetLink(input.LinkID)
		if err != nil {
			return storage.DomainTarget{}, fmt.Errorf("consultar link: %w", err)
		}
		if link == nil {
			return storage.DomainTarget{}, fmt.Errorf("%w: link_id desconhecido", ErrInvalid)
		}
		target.LinkName = link.Name
		target.Mark = uint32(link.TableID)
	}
	return target, nil
}

func (c *Coordinator) ensureUniqueDomain(domain, exceptID string) error {
	targets, err := c.db.ListDomainTargets()
	if err != nil {
		return err
	}
	for _, target := range targets {
		if target.Domain == domain && target.ID != exceptID {
			return fmt.Errorf("%w: %s", ErrConflict, domain)
		}
	}
	return nil
}

func classifyStorageError(err error) error {
	switch {
	case errors.Is(err, storage.ErrDomainTargetNotFound):
		return fmt.Errorf("%w: %v", ErrNotFound, err)
	case strings.Contains(err.Error(), "UNIQUE constraint failed: domain_targets.domain"):
		return fmt.Errorf("%w: %v", ErrConflict, err)
	default:
		return err
	}
}

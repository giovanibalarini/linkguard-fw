package qos

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/google/uuid"
)

const redirectFilterPriority = "49152"

const (
	managedEgressHandle  = "cafe:"
	managedIngressHandle = "caff:"
	managedNetemHandle   = "2:"
	repairTimeout        = 15 * time.Second
)

// ErrStaleInterface indicates that a configuration loader observed a link
// moving to another interface while the previous interface was locked.
var ErrStaleInterface = errors.New("qos interface changed while loading configuration")

// ErrCompensationFailed indicates that a durable QoS mutation failed and its
// kernel rollback also failed. Callers must treat this as an internal failure
// rather than as the original persistence conflict.
var ErrCompensationFailed = errors.New("qos compensation failed")

// ErrOwnershipNotEstablished indicates that a kernel object is present but
// does not have the deterministic ownership markers used by this service.
var ErrOwnershipNotEstablished = errors.New("qos ownership not established")

// State describes the queue-control objects accepted by the service.
type State struct {
	Enabled   bool   `json:"enabled"`
	Interface string `json:"interface"`
	IFB       string `json:"ifb"`
	Mode      string `json:"mode"`
	DryRun    bool   `json:"dry_run"`
}

// ApplyPlan contains the effective kernel configuration, its prior state for
// compensation, and the durable write that must follow a successful apply.
// The service runs all three steps under one interface lock.
type ApplyPlan struct {
	Config   Config
	Rollback Config
	Persist  func(operationID string) error
}

// NetemFault is the exact stress-test impairment owned by LinkGuard. The
// values are carried into recovery so a colliding netem handle is never enough
// evidence to remove somebody else's qdisc.
type NetemFault struct {
	DelayMs int
	LossPct int
}

func (f NetemFault) validate() error {
	if f.DelayMs <= 0 {
		return errors.New("netem delay must be positive")
	}
	if f.LossPct < 0 || f.LossPct > 100 {
		return errors.New("netem loss must be between 0 and 100 percent")
	}
	return nil
}

type interfaceSemaphore struct {
	token chan struct{}
}

func newInterfaceSemaphore() *interfaceSemaphore {
	lock := &interfaceSemaphore{token: make(chan struct{}, 1)}
	lock.token <- struct{}{}
	return lock
}

// Service applies QoS changes through the firewall command executor.
type Service struct {
	exec  firewall.Executor
	store OperationStore

	locksMu       sync.Mutex
	interfaceLock map[string]*interfaceSemaphore
}

// NewService creates a QoS service.
func NewService(exec firewall.Executor) *Service {
	return &Service{exec: exec, interfaceLock: make(map[string]*interfaceSemaphore)}
}

// SetOperationStore enables cross-process recovery for Apply and Disable.
// It must be configured before the service is made available to callers.
func (s *Service) SetOperationStore(store OperationStore) {
	s.store = store
}

// Apply validates and applies one WAN's desired QoS configuration.
func (s *Service) Apply(ctx context.Context, cfg Config) (State, error) {
	if err := cfg.Validate(); err != nil {
		return State{}, err
	}
	unlock, err := s.lockInterface(ctx, cfg.Interface)
	if err != nil {
		return State{}, err
	}
	defer unlock()
	return s.applyDurable(ctx, cfg, cfg, operationIntent(cfg))
}

// ApplyAndPersist applies cfg and invokes persist while the interface lock is
// held. If persistence fails, rollback is applied before returning the error.
// Keeping the kernel change and its durable configuration in one critical
// section prevents boot/API operations from interleaving on one interface.
func (s *Service) ApplyAndPersist(ctx context.Context, cfg, rollback Config, persist func(string) error) (State, error) {
	if err := cfg.Validate(); err != nil {
		return State{}, err
	}
	unlock, err := s.lockInterface(ctx, cfg.Interface)
	if err != nil {
		return State{}, err
	}
	defer unlock()
	return s.applyAndPersistLocked(ctx, cfg, rollback, persist)
}

// ApplyCurrentAndPersist loads the current apply plan while iface is locked,
// then applies and persists it without allowing another operation for that
// interface to interleave. A stale loader must return a plan whose Config uses
// iface; otherwise no kernel or database mutation is attempted.
func (s *Service) ApplyCurrentAndPersist(ctx context.Context, iface string, load func() (ApplyPlan, error)) (State, error) {
	if err := (Config{Interface: iface}).Validate(); err != nil {
		return State{}, err
	}
	unlock, err := s.lockInterface(ctx, iface)
	if err != nil {
		return State{}, err
	}
	defer unlock()

	plan, err := load()
	if err != nil {
		return State{}, err
	}
	if plan.Config.Interface != iface {
		return State{}, fmt.Errorf("%w: %q became %q", ErrStaleInterface, iface, plan.Config.Interface)
	}
	return s.applyAndPersistLocked(ctx, plan.Config, plan.Rollback, plan.Persist)
}

func (s *Service) applyAndPersistLocked(ctx context.Context, cfg, rollback Config, persist func(string) error) (State, error) {
	if err := cfg.Validate(); err != nil {
		return State{}, err
	}
	if persist == nil {
		return State{}, errors.New("qos persistence callback is nil")
	}

	if rollback.Interface != cfg.Interface || rollback.Validate() != nil {
		rollback = Config{Interface: cfg.Interface}
	}
	ownership, err := s.inspectOwnership(ctx, cfg.Interface)
	if err != nil {
		return State{}, err
	}
	if err := validateApplyOwnership(cfg, ownership); err != nil {
		return State{}, err
	}
	leaseID, err := s.beginOperation(cfg, rollback, operationIntent(cfg), ownership)
	if err != nil {
		return State{}, err
	}
	state, err := s.applyFromOwnership(ctx, cfg, ownership, leaseID)
	if err != nil {
		if clearErr := s.clearCompensatedOperation(leaseID, cfg.Interface, err); clearErr != nil {
			return State{}, clearErr
		}
		return State{}, err
	}
	if err := persist(leaseID); err != nil {
		repairCtx, cancel := detachedRepairContext(ctx)
		defer cancel()
		if _, restoreErr := s.apply(repairCtx, rollback); restoreErr != nil {
			return State{}, fmt.Errorf("%w: persist QoS: %v; restore QoS: %v", ErrCompensationFailed, err, restoreErr)
		}
		if clearErr := s.clearOperation(leaseID, cfg.Interface); clearErr != nil {
			return State{}, fmt.Errorf("%w: persist QoS: %v; clear recovered operation: %v", ErrCompensationFailed, err, clearErr)
		}
		return State{}, fmt.Errorf("persist QoS: %w", err)
	}
	if leaseID != "" {
		pending, listErr := s.operationPending(leaseID)
		if listErr != nil {
			return State{}, fmt.Errorf("verify persisted QoS operation: %w", listErr)
		}
		if pending {
			return State{}, errors.New("persist QoS callback did not atomically clear operation lease")
		}
	}
	return state, nil
}

// ApplyCurrent loads a configuration while iface is locked, then applies the
// loaded value. Boot reconciliation uses this to prevent a stale snapshot
// from being applied after a newer API mutation on the same interface.
func (s *Service) ApplyCurrent(ctx context.Context, iface string, load func() (Config, error)) (State, error) {
	if err := (Config{Interface: iface}).Validate(); err != nil {
		return State{}, err
	}
	unlock, err := s.lockInterface(ctx, iface)
	if err != nil {
		return State{}, err
	}
	defer unlock()

	cfg, err := load()
	if err != nil {
		return State{}, err
	}
	if cfg.Interface != iface {
		return State{}, fmt.Errorf("%w: %q became %q", ErrStaleInterface, iface, cfg.Interface)
	}
	if err := cfg.Validate(); err != nil {
		return State{}, err
	}
	return s.applyDurable(ctx, cfg, cfg, operationIntent(cfg))
}

func operationIntent(cfg Config) OperationIntent {
	if cfg.Enabled {
		return OperationApply
	}
	return OperationDisable
}

// InterfaceOperations are the QoS operations permitted while an interface
// lock is already held by WithInterfaceLock.
type InterfaceOperations interface {
	Apply(context.Context, Config) (State, error)
	ApplyNetem(context.Context, NetemFault) error
	RestoreAfterNetem(context.Context, Config, NetemFault) (State, error)
}

type lockedInterfaceOperations struct {
	service *Service
	iface   string
}

func (o lockedInterfaceOperations) Apply(ctx context.Context, cfg Config) (State, error) {
	if cfg.Interface != o.iface {
		return State{}, fmt.Errorf("qos operation targets %q while %q is locked", cfg.Interface, o.iface)
	}
	if err := cfg.Validate(); err != nil {
		return State{}, err
	}
	return o.service.apply(ctx, cfg)
}

func (o lockedInterfaceOperations) ApplyNetem(ctx context.Context, fault NetemFault) error {
	return o.service.applyNetem(ctx, o.iface, fault)
}

func (o lockedInterfaceOperations) RestoreAfterNetem(ctx context.Context, cfg Config, fault NetemFault) (State, error) {
	if cfg.Interface != o.iface {
		return State{}, fmt.Errorf("qos operation targets %q while %q is locked", cfg.Interface, o.iface)
	}
	if err := cfg.Validate(); err != nil {
		return State{}, err
	}
	return o.service.restoreAfterNetem(ctx, cfg, fault)
}

// WithInterfaceLock serializes non-QoS link mutations with QoS operations
// that use this shared service. The callback receives operations that reuse
// the held lock and must not call a public method on this service.
func (s *Service) WithInterfaceLock(ctx context.Context, iface string, fn func(InterfaceOperations) error) error {
	if err := (Config{Interface: iface}).Validate(); err != nil {
		return err
	}
	if fn == nil {
		return errors.New("qos interface lock callback is nil")
	}
	unlock, err := s.lockInterface(ctx, iface)
	if err != nil {
		return err
	}
	defer unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn(lockedInterfaceOperations{service: s, iface: iface})
}

func (s *Service) applyNetem(ctx context.Context, iface string, fault NetemFault) error {
	if err := fault.validate(); err != nil {
		return err
	}
	ownership, err := s.inspectOwnership(ctx, iface)
	if err != nil {
		return err
	}
	root, exists := rootQdisc(ownership.egressOutput)
	if exists && !isReplaceableInitialRoot(root) && !ownership.chainOwned {
		return fmt.Errorf("%w: foreign root qdisc on %q", ErrOwnershipNotEstablished, iface)
	}
	if ownership.ingressForeign || (ownership.filterPresent && !ownership.redirectOwned) {
		return fmt.Errorf("%w: incomplete or foreign QoS chain on %q", ErrOwnershipNotEstablished, iface)
	}
	before := ownership.egressOutput
	journal := mutationJournal{service: s, ctx: ctx}
	return journal.run("apply stress-test netem", func(stepCtx context.Context) error {
		return s.execute(stepCtx, "apply stress-test netem", "tc", "qdisc", "replace", "dev", iface,
			"root", "handle", managedNetemHandle, "netem", "delay", strconv.Itoa(fault.DelayMs)+"ms", "loss", strconv.Itoa(fault.LossPct)+"%")
	}, func(repairCtx context.Context) error {
		return s.restoreRoot(repairCtx, iface, before, netemRootSignature(fault), ownership.egressSignature)
	})
}

func (s *Service) restoreAfterNetem(ctx context.Context, cfg Config, fault NetemFault) (State, error) {
	if err := fault.validate(); err != nil {
		return State{}, err
	}
	ownership, err := s.inspectOwnership(ctx, cfg.Interface)
	if err != nil {
		return State{}, err
	}
	root, exists := rootQdisc(ownership.egressOutput)
	if !exists || isReplaceableInitialRoot(root) {
		return s.apply(ctx, cfg)
	}
	if root.kind == "cake" {
		if !ownership.chainOwned {
			return State{}, fmt.Errorf("%w: foreign root qdisc on %q", ErrOwnershipNotEstablished, cfg.Interface)
		}
		return s.apply(ctx, cfg)
	}
	if !netemRootSignature(fault).matches(ownership.egressOutput) {
		return State{}, fmt.Errorf("%w: foreign root qdisc on %q", ErrOwnershipNotEstablished, cfg.Interface)
	}
	if ownership.filterPresent != ownership.redirectMatches {
		return State{}, fmt.Errorf("%w: incomplete ingress redirect on %q", ErrOwnershipNotEstablished, cfg.Interface)
	}
	ingressSignature, ingressMatches := linkGuardCakeRootSignature(ownership.ingressOutput, managedIngressHandle, "dual-dsthost", true)
	if hasRootQdisc(ownership.ingressOutput) != ingressMatches {
		return State{}, fmt.Errorf("%w: incomplete or foreign ingress qdisc on %q", ErrOwnershipNotEstablished, IFBName(cfg.Interface))
	}
	if ingressMatches != ownership.redirectMatches {
		return State{}, fmt.Errorf("%w: incomplete managed ingress chain on %q", ErrOwnershipNotEstablished, cfg.Interface)
	}
	ownership.egressOwned = true
	ownership.egressForeign = false
	ownership.egressSignature = netemRootSignature(fault)
	ownership.ingressOwned = ingressMatches
	ownership.ingressForeign = false
	ownership.ingressSignature = ingressSignature
	ownership.redirectOwned = ownership.redirectMatches
	ownership.chainOwned = true
	if !cfg.Enabled {
		return s.disableWithOwnership(ctx, cfg.Interface, ownership)
	}
	if err := s.removeRootMatching(ctx, cfg.Interface, ownership.egressSignature); err != nil {
		return State{}, err
	}
	repairNetem := func(original error) (State, error) {
		repairErr := s.compensate(ctx, []qosUndo{func(repairCtx context.Context) error {
			return s.restoreDeletedRoot(repairCtx, cfg.Interface, ownership.egressOutput, ownership.egressSignature)
		}})
		if repairErr != nil {
			return State{}, fmt.Errorf("%w: restore after netem removal error: %v; repair: %v", ErrCompensationFailed, original, repairErr)
		}
		return State{}, original
	}
	currentEgress, err := s.read(ctx, "tc", "qdisc", "show", "dev", cfg.Interface)
	if err != nil {
		return repairNetem(err)
	}
	if current, exists := rootQdisc(currentEgress); exists && !isReplaceableInitialRoot(current) {
		return repairNetem(fmt.Errorf("%w: root qdisc on %q changed after netem removal", ErrOwnershipNotEstablished, cfg.Interface))
	}
	if ownership.ingressOwned {
		currentIngress, readErr := s.read(ctx, "tc", "qdisc", "show", "dev", IFBName(cfg.Interface))
		if readErr != nil {
			return repairNetem(readErr)
		}
		if !ownership.ingressSignature.matches(currentIngress) {
			return repairNetem(fmt.Errorf("%w: ingress qdisc changed after netem removal", ErrOwnershipNotEstablished))
		}
	}
	if ownership.redirectOwned {
		currentRedirect, readErr := s.read(ctx, "tc", "filter", "show", "dev", cfg.Interface, "ingress", "pref", redirectFilterPriority)
		if readErr != nil {
			return repairNetem(readErr)
		}
		if !hasManagedRedirect(currentRedirect, IFBName(cfg.Interface)) {
			return repairNetem(fmt.Errorf("%w: ingress redirect changed after netem removal", ErrOwnershipNotEstablished))
		}
	}
	ownership.egressOutput = currentEgress
	ownership.egressOwned = false
	ownership.egressForeign = false
	state, applyErr := s.applyWithOwnership(ctx, cfg, ownership)
	if applyErr == nil {
		return state, nil
	}
	return repairNetem(applyErr)
}

func (s *Service) apply(ctx context.Context, cfg Config) (State, error) {
	ownership, err := s.inspectOwnership(ctx, cfg.Interface)
	if err != nil {
		return State{}, err
	}
	if err := validateApplyOwnership(cfg, ownership); err != nil {
		return State{}, err
	}
	return s.applyFromOwnership(ctx, cfg, ownership, "")
}

func (s *Service) applyDurable(ctx context.Context, target, recovery Config, intent OperationIntent) (State, error) {
	ownership, err := s.inspectOwnership(ctx, target.Interface)
	if err != nil {
		return State{}, err
	}
	if err := validateApplyOwnership(target, ownership); err != nil {
		return State{}, err
	}
	operationID, err := s.beginOperation(target, recovery, intent, ownership)
	if err != nil {
		return State{}, err
	}
	state, err := s.applyFromOwnership(ctx, target, ownership, operationID)
	if err != nil {
		if clearErr := s.clearCompensatedOperation(operationID, target.Interface, err); clearErr != nil {
			return State{}, clearErr
		}
		return State{}, err
	}
	if err := s.clearOperation(operationID, target.Interface); err != nil {
		return State{}, fmt.Errorf("clear QoS operation lease: %w", err)
	}
	return state, nil
}

func (s *Service) beginOperation(target, recovery Config, intent OperationIntent, ownership ownershipState) (string, error) {
	if s.store == nil || s.exec.IsDryRun() {
		return "", nil
	}
	lease := &OperationLease{
		ID:        uuid.NewString(),
		Interface: target.Interface,
		Intent:    intent,
		Target:    target,
		Recovery:  recovery,
		// A complete managed chain owns its IFB, so recovery may remove and
		// recreate it. Preserve only an IFB that predated LinkGuard ownership.
		IFBExisted:    ownership.ifbExists && !ownership.chainOwned,
		IFBWasUp:      ownership.ifbUp,
		ClsactExisted: ownership.clsact,
		CreatedAt:     time.Now().UTC(),
	}
	if ownership.chainOwned {
		lease.BeforeEgress = exportedCakeSignature(ownership.egressSignature)
		lease.BeforeIngress = exportedCakeSignature(ownership.ingressSignature)
	}
	if err := lease.Validate(); err != nil {
		return "", err
	}
	if err := s.store.SaveQoSOperationLease(lease); err != nil {
		return "", fmt.Errorf("save QoS operation lease: %w", err)
	}
	return lease.ID, nil
}

func exportedCakeSignature(sig rootSignature) *CakeSignature {
	if sig.kind != "cake" {
		return nil
	}
	return &CakeSignature{
		Handle: sig.handle, Bandwidth: sig.bandwidth, Mode: sig.mode,
		HostMode: sig.hostMode, NAT: sig.nat, Ingress: sig.ingress,
	}
}

func (s *Service) clearCompensatedOperation(operationID, iface string, operationErr error) error {
	if operationID == "" || errors.Is(operationErr, ErrCompensationFailed) {
		return nil
	}
	if err := s.clearOperation(operationID, iface); err != nil {
		return fmt.Errorf("%w: operation failed: %v; clear compensated lease: %v", ErrCompensationFailed, operationErr, err)
	}
	return nil
}

func (s *Service) clearOperation(operationID, iface string) error {
	if operationID == "" || s.store == nil || s.exec.IsDryRun() {
		return nil
	}
	return s.store.ClearQoSOperationLease(operationID, iface)
}

func (s *Service) operationPending(operationID string) (bool, error) {
	if operationID == "" || s.store == nil {
		return false, nil
	}
	leases, err := s.store.ListQoSOperationLeases()
	if err != nil {
		return false, err
	}
	for _, lease := range leases {
		if lease.ID == operationID {
			return true, nil
		}
	}
	return false, nil
}

func validateApplyOwnership(cfg Config, ownership ownershipState) error {
	if !cfg.Enabled {
		return nil
	}
	if ownership.egressForeign {
		return fmt.Errorf("%w: foreign root qdisc on %q", ErrOwnershipNotEstablished, cfg.Interface)
	}
	if ownership.ingressForeign {
		return fmt.Errorf("%w: foreign root qdisc on %q", ErrOwnershipNotEstablished, IFBName(cfg.Interface))
	}
	if ownership.filterPresent && !ownership.redirectOwned {
		return fmt.Errorf("%w: foreign ingress filter on %q", ErrOwnershipNotEstablished, cfg.Interface)
	}
	return nil
}

func (s *Service) applyFromOwnership(ctx context.Context, cfg Config, ownership ownershipState, operationID string) (State, error) {
	if !cfg.Enabled {
		return s.disableWithOwnership(ctx, cfg.Interface, ownership, operationID)
	}
	return s.applyWithOwnership(ctx, cfg, ownership, operationID)
}

type qosUndo func(context.Context) error

func (s *Service) applyWithOwnership(ctx context.Context, cfg Config, ownership ownershipState, operationIDs ...string) (State, error) {
	mode := "besteffort"
	if cfg.Interactive {
		mode = "diffserv4"
	}
	ifb := IFBName(cfg.Interface)
	journal := s.newMutationJournal(ctx, firstOperationID(operationIDs))

	if err := journal.run("apply egress CAKE", func(stepCtx context.Context) error {
		return s.execute(stepCtx, "apply egress CAKE", "tc",
			"qdisc", "replace", "dev", cfg.Interface, "root", "handle", managedEgressHandle, "cake",
			"bandwidth", bandwidthArg(cfg.UploadMbps), mode, "nat", "dual-srchost")
	}, func(repairCtx context.Context) error {
		return s.restoreRoot(repairCtx, cfg.Interface, ownership.egressOutput,
			cakeRootSignature(managedEgressHandle, bandwidthArg(cfg.UploadMbps), mode, "dual-srchost", true, false),
			ownership.egressSignature)
	}); err != nil {
		return State{}, err
	}

	if !ownership.ifbExists {
		if err := journal.run("create IFB", func(stepCtx context.Context) error {
			return s.execute(stepCtx, "create IFB", "ip", "link", "add", ifb, "type", "ifb")
		}, func(repairCtx context.Context) error {
			return s.removeIFBIfUnclaimed(repairCtx, ifb, "remove IFB after failed QoS apply")
		}); err != nil {
			return State{}, err
		}
	}
	var undoIFBUp qosUndo
	if ownership.ifbExists && !ownership.ifbUp {
		undoIFBUp = func(repairCtx context.Context) error {
			return s.execute(repairCtx, "restore IFB down state", "ip", "link", "set", "dev", ifb, "down")
		}
	}
	if err := journal.run("bring IFB up", func(stepCtx context.Context) error {
		return s.execute(stepCtx, "bring IFB up", "ip", "link", "set", "dev", ifb, "up")
	}, undoIFBUp); err != nil {
		return State{}, err
	}
	if err := journal.run("apply ingress CAKE", func(stepCtx context.Context) error {
		return s.execute(stepCtx, "apply ingress CAKE", "tc",
			"qdisc", "replace", "dev", ifb, "root", "handle", managedIngressHandle, "cake",
			"bandwidth", bandwidthArg(cfg.DownloadMbps), mode, "nat", "dual-dsthost", "ingress")
	}, func(repairCtx context.Context) error {
		return s.restoreRoot(repairCtx, ifb, ownership.ingressOutput,
			cakeRootSignature(managedIngressHandle, bandwidthArg(cfg.DownloadMbps), mode, "dual-dsthost", true, true),
			ownership.ingressSignature)
	}); err != nil {
		return State{}, err
	}
	if !ownership.clsact {
		if err := journal.run("ensure clsact", func(stepCtx context.Context) error {
			return s.execute(stepCtx, "ensure clsact", "tc", "qdisc", "add", "dev", cfg.Interface, "clsact")
		}, func(repairCtx context.Context) error {
			return s.removeAddedClsact(repairCtx, cfg.Interface)
		}); err != nil {
			return State{}, err
		}
	}
	if err := journal.run("redirect ingress", func(stepCtx context.Context) error {
		return s.execute(stepCtx, "redirect ingress", "tc",
			"filter", "replace", "dev", cfg.Interface, "ingress",
			"pref", redirectFilterPriority, "protocol", "all", "matchall",
			"action", "mirred", "egress", "redirect", "dev", ifb)
	}, func(repairCtx context.Context) error {
		if ownership.redirectOwned {
			return s.restoreRedirect(repairCtx, cfg.Interface, ifb)
		}
		return s.removeManagedRedirect(repairCtx, cfg.Interface, ifb)
	}); err != nil {
		return State{}, err
	}

	return State{
		Enabled:   true,
		Interface: cfg.Interface,
		IFB:       ifb,
		Mode:      mode,
		DryRun:    s.exec.IsDryRun(),
	}, nil
}

type mutationJournal struct {
	service     *Service
	ctx         context.Context
	operationID string
	stage       int
	undos       []qosUndo
}

func firstOperationID(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}

func (s *Service) newMutationJournal(ctx context.Context, operationID string) mutationJournal {
	return mutationJournal{service: s, ctx: ctx, operationID: operationID}
}

func (j *mutationJournal) run(action string, mutate func(context.Context) error, undo qosUndo) error {
	if err := mutate(j.ctx); err != nil {
		original := fmt.Errorf("%s: %w", action, err)
		if repairErr := j.service.compensate(j.ctx, j.undos); repairErr != nil {
			return fmt.Errorf("%w: %v; repair: %v", ErrCompensationFailed, original, repairErr)
		}
		return original
	}
	if undo != nil {
		j.undos = append(j.undos, undo)
	}
	if j.operationID != "" && j.service.store != nil && !j.service.exec.IsDryRun() {
		if err := j.service.store.AdvanceQoSOperationLease(j.operationID, j.stage, j.stage+1); err != nil {
			original := fmt.Errorf("journal %s: %w", action, err)
			if repairErr := j.service.compensate(j.ctx, j.undos); repairErr != nil {
				return fmt.Errorf("%w: %v; repair: %v", ErrCompensationFailed, original, repairErr)
			}
			return original
		}
		j.stage++
	}
	return nil
}

func (s *Service) compensate(ctx context.Context, undos []qosUndo) error {
	if len(undos) == 0 {
		return nil
	}
	repairCtx, cancel := detachedRepairContext(ctx)
	defer cancel()
	var repairErrors []error
	for i := len(undos) - 1; i >= 0; i-- {
		if err := undos[i](repairCtx); err != nil {
			repairErrors = append(repairErrors, err)
		}
	}
	return errors.Join(repairErrors...)
}

func detachedRepairContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), repairTimeout)
}

var cakeBandwidthPattern = regexp.MustCompile(`(?i)^[0-9]+(?:\.[0-9]+)?(?:kbit|mbit|gbit)$`)

type rootSignature struct {
	kind      string
	handle    string
	bandwidth string
	mode      string
	hostMode  string
	nat       bool
	ingress   bool
	delayMs   int
	lossPct   int
}

func cakeRootSignature(handle, bandwidth, mode, hostMode string, nat, ingress bool) rootSignature {
	return rootSignature{
		kind: "cake", handle: handle, bandwidth: bandwidth, mode: mode,
		hostMode: hostMode, nat: nat, ingress: ingress,
	}
}

func netemRootSignature(fault NetemFault) rootSignature {
	return rootSignature{kind: "netem", handle: managedNetemHandle, delayMs: fault.DelayMs, lossPct: fault.LossPct}
}

func managedCakeRootSignature(output, handle, hostMode string) (rootSignature, bool) {
	line, ok := rootQdiscLine(output)
	if !ok {
		return rootSignature{}, false
	}
	root, ok := rootQdisc(line)
	if !ok || root.kind != "cake" || root.handle != handle || !containsWord(strings.Fields(line), hostMode) {
		return rootSignature{}, false
	}
	bandwidth, mode, ok := cakeSettings(line)
	if !ok {
		return rootSignature{}, false
	}
	words := strings.Fields(line)
	return cakeRootSignature(handle, bandwidth, mode, hostMode,
		containsWord(words, "nat"), containsWord(words, "ingress")), true
}

func linkGuardCakeRootSignature(output, managedHandle, hostMode string, ingress bool) (rootSignature, bool) {
	sig, ok := managedCakeRootSignature(output, managedHandle, hostMode)
	return sig, ok && sig.nat && sig.ingress == ingress
}

func (sig rootSignature) matches(output string) bool {
	root, ok := rootQdisc(output)
	if !ok || root.kind != sig.kind || root.handle != sig.handle {
		return false
	}
	switch sig.kind {
	case "cake":
		bandwidth, mode, ok := cakeSettings(output)
		words := strings.Fields(output)
		return ok && strings.EqualFold(bandwidth, sig.bandwidth) && mode == sig.mode &&
			containsWord(words, sig.hostMode) && containsWord(words, "nat") == sig.nat &&
			containsWord(words, "ingress") == sig.ingress
	case "netem":
		delayMs, lossPct, ok := netemSettings(output)
		return ok && delayMs == sig.delayMs && lossPct == sig.lossPct
	default:
		return false
	}
}

func (s *Service) restoreRoot(ctx context.Context, iface, previousOutput string, current, previousManaged rootSignature) error {
	root, ok := rootQdisc(previousOutput)
	if !ok {
		currentOutput, err := s.read(ctx, "tc", "qdisc", "show", "dev", iface)
		if err != nil {
			return err
		}
		if !s.exec.IsDryRun() && !current.matches(currentOutput) {
			if _, exists := rootQdisc(currentOutput); !exists {
				return nil
			}
			return fmt.Errorf("%w: root qdisc on %q changed during repair", ErrOwnershipNotEstablished, iface)
		}
		return s.delete(ctx, "remove managed root qdisc", "tc", "qdisc", "del", "dev", iface, "root")
	}
	currentOutput, err := s.read(ctx, "tc", "qdisc", "show", "dev", iface)
	if err != nil {
		return err
	}
	if isReplaceableInitialRoot(root) {
		if currentRoot, exists := rootQdisc(currentOutput); exists && currentRoot == root {
			return nil
		}
		if !s.exec.IsDryRun() && !current.matches(currentOutput) {
			return fmt.Errorf("%w: root qdisc on %q changed before default restoration", ErrOwnershipNotEstablished, iface)
		}
		return s.execute(ctx, "restore initial root qdisc", "tc", "qdisc", "replace", "dev", iface, "root", root.kind)
	}
	if root.kind == "netem" && root.handle == managedNetemHandle {
		delayMs, lossPct, previousOK := netemSettings(previousOutput)
		if !previousOK {
			return errors.New("managed netem root has no complete restorable signature")
		}
		previous := netemRootSignature(NetemFault{DelayMs: delayMs, LossPct: lossPct})
		if previous.matches(currentOutput) {
			return nil
		}
		if !s.exec.IsDryRun() && !current.matches(currentOutput) {
			return fmt.Errorf("%w: root qdisc on %q changed during netem repair", ErrOwnershipNotEstablished, iface)
		}
		return s.execute(ctx, "restore managed netem root", "tc", "qdisc", "replace", "dev", iface,
			"root", "handle", managedNetemHandle, "netem", "delay", strconv.Itoa(delayMs)+"ms", "loss", strconv.Itoa(lossPct)+"%")
	}
	if root.kind != "cake" || previousManaged.kind != "cake" || root.handle != previousManaged.handle {
		return fmt.Errorf("%w: cannot restore root qdisc %q %q", ErrOwnershipNotEstablished, root.kind, root.handle)
	}
	if !previousManaged.matches(previousOutput) {
		return errors.New("managed CAKE root has no complete restorable signature")
	}
	if previousManaged.matches(currentOutput) {
		return nil
	}
	if !s.exec.IsDryRun() && !current.matches(currentOutput) {
		return fmt.Errorf("%w: root qdisc on %q changed during repair", ErrOwnershipNotEstablished, iface)
	}
	args := []string{"qdisc", "replace", "dev", iface, "root", "handle", previousManaged.handle, "cake"}
	args = append(args, cakeSignatureArgs(previousManaged)...)
	return s.execute(ctx, "restore managed root qdisc", "tc", args...)
}

func cakeSettings(output string) (string, string, bool) {
	line, ok := rootQdiscLine(output)
	if !ok {
		return "", "", false
	}
	fields := strings.Fields(line)
	bandwidth := ""
	mode := ""
	for i, field := range fields {
		if field == "bandwidth" && i+1 < len(fields) {
			value := fields[i+1]
			if cakeBandwidthPattern.MatchString(value) {
				bandwidth = value
			}
		}
		if field == "diffserv4" || field == "besteffort" {
			mode = field
		}
	}
	return bandwidth, mode, bandwidth != "" && mode != ""
}

func cakeSignatureArgs(sig rootSignature) []string {
	args := []string{"bandwidth", sig.bandwidth, sig.mode}
	if sig.nat {
		args = append(args, "nat")
	}
	args = append(args, sig.hostMode)
	if sig.ingress {
		args = append(args, "ingress")
	}
	return args
}

func rootQdiscLine(output string) (string, bool) {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "qdisc" && fields[3] == "root" {
			return line, true
		}
	}
	return "", false
}

func netemSettings(output string) (int, int, bool) {
	line, ok := rootQdiscLine(output)
	if !ok {
		return 0, 0, false
	}
	fields := strings.Fields(line)
	delayMs := 0
	lossPct := 0
	foundDelay := false
	unsupported := map[string]bool{
		"corrupt": true, "distribution": true, "duplicate": true, "gap": true,
		"rate": true, "reorder": true, "seed": true, "slot": true,
	}
	for i, field := range fields {
		if unsupported[field] {
			return 0, 0, false
		}
		if field == "delay" && i+1 < len(fields) {
			d, err := time.ParseDuration(strings.ToLower(fields[i+1]))
			if err != nil || d <= 0 || d%time.Millisecond != 0 {
				return 0, 0, false
			}
			delayMs = int(d / time.Millisecond)
			foundDelay = true
			if i+2 < len(fields) {
				if _, jitterErr := time.ParseDuration(strings.ToLower(fields[i+2])); jitterErr == nil {
					return 0, 0, false
				}
			}
		}
		if field == "loss" && i+1 < len(fields) {
			value := strings.TrimSuffix(fields[i+1], "%")
			loss, err := strconv.ParseFloat(value, 64)
			if err != nil || loss < 0 || loss > 100 || loss != float64(int(loss)) {
				return 0, 0, false
			}
			lossPct = int(loss)
			if i+2 < len(fields) && strings.HasSuffix(fields[i+2], "%") {
				return 0, 0, false
			}
		}
	}
	return delayMs, lossPct, foundDelay
}

func containsWord(fields []string, want string) bool {
	for _, field := range fields {
		if field == want {
			return true
		}
	}
	return false
}

func (s *Service) restoreRedirect(ctx context.Context, iface, ifb string) error {
	output, err := s.read(ctx, "tc", "filter", "show", "dev", iface, "ingress", "pref", redirectFilterPriority)
	if err != nil {
		return err
	}
	if strings.TrimSpace(output) != "" {
		if hasManagedRedirect(output, ifb) {
			return nil
		}
		return fmt.Errorf("%w: ingress filter on %q changed during repair", ErrOwnershipNotEstablished, iface)
	}
	return s.execute(ctx, "restore ingress redirect", "tc", "filter", "replace", "dev", iface, "ingress",
		"pref", redirectFilterPriority, "protocol", "all", "matchall", "action", "mirred", "egress", "redirect", "dev", ifb)
}

func (s *Service) removeRootMatching(ctx context.Context, iface string, expected rootSignature) error {
	output, err := s.read(ctx, "tc", "qdisc", "show", "dev", iface)
	if err != nil {
		return err
	}
	_, ok := rootQdisc(output)
	if !ok {
		return nil
	}
	if !expected.matches(output) {
		return fmt.Errorf("%w: refusing to remove root qdisc on %q", ErrOwnershipNotEstablished, iface)
	}
	return s.delete(ctx, "remove managed root qdisc", "tc", "qdisc", "del", "dev", iface, "root")
}

func (s *Service) restoreDeletedRoot(ctx context.Context, iface, previousOutput string, previous rootSignature) error {
	currentOutput, err := s.read(ctx, "tc", "qdisc", "show", "dev", iface)
	if err != nil {
		return err
	}
	if current, exists := rootQdisc(currentOutput); exists && !isReplaceableInitialRoot(current) {
		return fmt.Errorf("%w: root qdisc on %q changed after managed deletion", ErrOwnershipNotEstablished, iface)
	}
	root, ok := rootQdisc(previousOutput)
	if !ok {
		return nil
	}
	if root.kind == "cake" {
		if previous.kind != "cake" || !previous.matches(previousOutput) {
			return errors.New("deleted CAKE root has no complete restorable signature")
		}
		args := []string{"qdisc", "replace", "dev", iface, "root", "handle", previous.handle, "cake"}
		args = append(args, cakeSignatureArgs(previous)...)
		return s.execute(ctx, "restore deleted CAKE root", "tc", args...)
	}
	if root.kind == "netem" && root.handle == managedNetemHandle {
		if previous.kind != "netem" || !previous.matches(previousOutput) {
			return errors.New("deleted netem root has no complete restorable signature")
		}
		return s.execute(ctx, "restore deleted netem root", "tc", "qdisc", "replace", "dev", iface,
			"root", "handle", managedNetemHandle, "netem", "delay", strconv.Itoa(previous.delayMs)+"ms", "loss", strconv.Itoa(previous.lossPct)+"%")
	}
	return fmt.Errorf("%w: cannot restore deleted root qdisc %q %q", ErrOwnershipNotEstablished, root.kind, root.handle)
}

func (s *Service) removeManagedRedirect(ctx context.Context, iface, ifb string) error {
	output, err := s.read(ctx, "tc", "filter", "show", "dev", iface, "ingress", "pref", redirectFilterPriority)
	if err != nil {
		return err
	}
	if strings.TrimSpace(output) == "" {
		return nil
	}
	if !hasManagedRedirect(output, ifb) {
		return fmt.Errorf("%w: refusing to remove ingress filter on %q", ErrOwnershipNotEstablished, iface)
	}
	return s.delete(ctx, "remove managed ingress redirect", "tc", "filter", "del", "dev", iface, "ingress", "pref", redirectFilterPriority)
}

func (s *Service) removeAddedClsact(ctx context.Context, iface string) error {
	qdiscs, err := s.read(ctx, "tc", "qdisc", "show", "dev", iface)
	if err != nil || !hasClsact(qdiscs) {
		return err
	}
	for _, direction := range []string{"ingress", "egress"} {
		filters, readErr := s.read(ctx, "tc", "filter", "show", "dev", iface, direction)
		if readErr != nil {
			return readErr
		}
		if hasFilterRecord(filters) {
			return nil
		}
	}
	return s.delete(ctx, "remove empty clsact after failed QoS apply", "tc", "qdisc", "del", "dev", iface, "clsact")
}

// Disable removes only the filter priority and qdiscs managed by this service.
// It deliberately leaves clsact in place because other components may own
// filters attached to it.
func (s *Service) Disable(ctx context.Context, iface string) (State, error) {
	if err := (Config{Interface: iface}).Validate(); err != nil {
		return State{}, err
	}
	unlock, err := s.lockInterface(ctx, iface)
	if err != nil {
		return State{}, err
	}
	defer unlock()
	disabled := Config{Interface: iface}
	return s.applyDurable(ctx, disabled, disabled, OperationDisable)
}

func (s *Service) disable(ctx context.Context, iface string) (State, error) {
	ownership, err := s.inspectOwnership(ctx, iface)
	if err != nil {
		return State{}, err
	}
	return s.disableWithOwnership(ctx, iface, ownership)
}

func (s *Service) disableWithOwnership(ctx context.Context, iface string, ownership ownershipState, operationIDs ...string) (State, error) {
	ifb := IFBName(iface)
	journal := s.newMutationJournal(ctx, firstOperationID(operationIDs))

	if ownership.redirectOwned {
		if err := journal.run("remove ingress redirect", func(stepCtx context.Context) error {
			return s.removeManagedRedirect(stepCtx, iface, ifb)
		}, func(repairCtx context.Context) error {
			return s.restoreRedirect(repairCtx, iface, ifb)
		}); err != nil {
			return State{}, err
		}
	}
	if ownership.egressOwned {
		if err := journal.run("remove managed egress root", func(stepCtx context.Context) error {
			return s.removeRootMatching(stepCtx, iface, ownership.egressSignature)
		}, func(repairCtx context.Context) error {
			return s.restoreDeletedRoot(repairCtx, iface, ownership.egressOutput, ownership.egressSignature)
		}); err != nil {
			return State{}, err
		}
	}

	if ownership.ingressOwned {
		if err := journal.run("remove ingress CAKE", func(stepCtx context.Context) error {
			return s.removeRootMatching(stepCtx, ifb, ownership.ingressSignature)
		}, func(repairCtx context.Context) error {
			return s.restoreDeletedRoot(repairCtx, ifb, ownership.ingressOutput, ownership.ingressSignature)
		}); err != nil {
			return State{}, err
		}
		if ownership.redirectOwned || !ownership.filterPresent {
			if err := journal.run("remove IFB", func(stepCtx context.Context) error {
				return s.removeIFBIfUnclaimed(stepCtx, ifb, "remove IFB")
			}, func(repairCtx context.Context) error {
				return s.restoreIFB(repairCtx, ifb, ownership.ifbUp)
			}); err != nil {
				return State{}, err
			}
		}
	}

	return State{
		Interface: iface,
		IFB:       ifb,
		DryRun:    s.exec.IsDryRun(),
	}, nil
}

type ownershipState struct {
	egressOutput     string
	egressSignature  rootSignature
	egressOwned      bool
	egressForeign    bool
	ifbExists        bool
	ifbUp            bool
	ingressOutput    string
	ingressSignature rootSignature
	ingressOwned     bool
	ingressForeign   bool
	clsact           bool
	filterPresent    bool
	redirectMatches  bool
	redirectOwned    bool
	chainOwned       bool
}

func (s *Service) inspectOwnership(ctx context.Context, iface string) (ownershipState, error) {
	ifb := IFBName(iface)
	egress, err := s.read(ctx, "tc", "qdisc", "show", "dev", iface)
	if err != nil {
		return ownershipState{}, err
	}
	redirect, err := s.read(ctx, "tc", "filter", "show", "dev", iface, "ingress", "pref", redirectFilterPriority)
	if err != nil {
		return ownershipState{}, err
	}
	exists, up, err := s.ifbState(ctx, ifb)
	if err != nil {
		return ownershipState{}, err
	}
	egressSignature, egressMatches := linkGuardCakeRootSignature(egress, managedEgressHandle, "dual-srchost", false)
	ownership := ownershipState{
		egressOutput:    egress,
		egressSignature: egressSignature,
		ifbExists:       exists,
		ifbUp:           up,
		clsact:          hasClsact(egress),
		filterPresent:   hasFilterRecord(redirect),
		redirectMatches: hasManagedRedirect(redirect, ifb),
	}
	if !exists {
		// SEM O IFB, O EGRESSO CONTINUA SENDO NOSSO — e é isso que permite
		// removê-lo.
		//
		// A posse da CADEIA exige as três peças (egresso, ingresso e o
		// redirecionamento), e para APLICAR isso está certo: mexer numa cadeia
		// incompleta é mexer no que talvez não seja nosso. Mas para REMOVER a
		// regra é outra: cada peça responde pela própria assinatura.
		//
		// Sem esta linha, um IFB ausente — apagado à mão, perdido num rename de
		// interface, ou nunca recriado — fazia o produto renegar a qdisc que ele
		// mesmo instalou. `disableWithOwnership` só remove o egresso sob
		// `egressOwned`, então desligar respondia 200 e a fila continuava
		// limitando o link. Com a reconciliação de boot recolocando a fila, o
		// estado virava permanente: a tela dizia desligado, o kernel dizia
		// 25Mbit, e não havia caminho pelo painel para sair disso.
		//
		// Medido na VM: PUT {"enabled":false} devolveu 200 e o
		// `tc qdisc show` continuou mostrando a cake, duas vezes seguidas.
		//
		// `egressMatches` vem de linkGuardCakeRootSignature, que casa o handle e
		// as flags que só nós escrevemos — então isto NÃO autoriza remover
		// qdisc de terceiro, que é a garantia que o resto deste arquivo protege.
		ownership.egressOwned = egressMatches
		ownership.egressForeign = hasForeignRootQdisc(egress, egressMatches)
		return ownership, nil
	}
	ingress, err := s.read(ctx, "tc", "qdisc", "show", "dev", ifb)
	if err != nil {
		return ownershipState{}, err
	}
	ownership.ingressOutput = ingress
	ownership.ingressSignature, ownership.ingressOwned = linkGuardCakeRootSignature(ingress, managedIngressHandle, "dual-dsthost", true)
	ownership.chainOwned = egressMatches && ownership.ingressOwned && ownership.redirectMatches
	ownership.egressOwned = ownership.chainOwned
	ownership.ingressOwned = ownership.chainOwned
	ownership.redirectOwned = ownership.chainOwned
	ownership.egressForeign = hasForeignRootQdisc(egress, ownership.chainOwned)
	ownership.ingressForeign = hasForeignRootQdisc(ingress, ownership.chainOwned)
	return ownership, nil
}

func (s *Service) lockInterface(ctx context.Context, iface string) (func(), error) {
	if ctx == nil {
		return nil, errors.New("qos interface lock context is nil")
	}
	s.locksMu.Lock()
	if s.interfaceLock == nil {
		s.interfaceLock = make(map[string]*interfaceSemaphore)
	}
	lock := s.interfaceLock[iface]
	if lock == nil {
		lock = newInterfaceSemaphore()
		s.interfaceLock[iface] = lock
	}
	s.locksMu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-lock.token:
	}
	if err := ctx.Err(); err != nil {
		lock.token <- struct{}{}
		return nil, err
	}
	return func() { lock.token <- struct{}{} }, nil
}

func (s *Service) ifbState(ctx context.Context, ifb string) (bool, bool, error) {
	output, err := s.exec.ExecuteRead(ctx, "ip", "link", "show", "dev", ifb)
	if err == nil {
		return true, linkIsUp(output), nil
	}
	if isNotFoundError(err) {
		return false, false, nil
	}
	return false, false, fmt.Errorf("check IFB %q: %w", ifb, err)
}

func linkIsUp(output string) bool {
	if strings.Contains(output, " state UP ") {
		return true
	}
	start := strings.IndexByte(output, '<')
	end := strings.IndexByte(output, '>')
	if start == -1 || end <= start {
		return false
	}
	for _, flag := range strings.Split(output[start+1:end], ",") {
		if flag == "UP" {
			return true
		}
	}
	return false
}

func (s *Service) removeIFBIfUnclaimed(ctx context.Context, ifb, action string) error {
	// Dry-run writes cannot delete the device. Keep the intended command in the
	// preview without expecting earlier no-op cleanup commands to change reads.
	if s.exec.IsDryRun() {
		return s.delete(ctx, action, "ip", "link", "del", "dev", ifb)
	}
	exists, _, err := s.ifbState(ctx, ifb)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if err := s.requireUnclaimedIFBState(ctx, ifb); err != nil {
		return err
	}

	// Re-read qdiscs after the filter probes so ownership attached during the
	// cleanup window is observed immediately before the destructive command.
	qdiscs, err := s.read(ctx, "tc", "qdisc", "show", "dev", ifb)
	if err != nil {
		return err
	}
	if !hasOnlyDisposableIFBQdiscs(qdiscs) {
		return fmt.Errorf("%w: IFB %q acquired qdisc ownership before deletion", ErrOwnershipNotEstablished, ifb)
	}
	exists, _, err = s.ifbState(ctx, ifb)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	return s.delete(ctx, action, "ip", "link", "del", "dev", ifb)
}

func (s *Service) requireUnclaimedIFBState(ctx context.Context, ifb string) error {
	qdiscs, err := s.read(ctx, "tc", "qdisc", "show", "dev", ifb)
	if err != nil {
		return err
	}
	if !hasOnlyDisposableIFBQdiscs(qdiscs) {
		return fmt.Errorf("%w: IFB %q has foreign or ambiguous qdiscs", ErrOwnershipNotEstablished, ifb)
	}
	for _, direction := range []string{"ingress", "egress"} {
		filters, err := s.read(ctx, "tc", "filter", "show", "dev", ifb, direction)
		if err != nil {
			if isNotFoundError(err) {
				continue
			}
			return err
		}
		if hasFilterRecord(filters) {
			return fmt.Errorf("%w: IFB %q has a foreign %s filter", ErrOwnershipNotEstablished, ifb, direction)
		}
	}
	return nil
}

func hasOnlyDisposableIFBQdiscs(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 4 || fields[0] != "qdisc" || fields[3] != "root" || fields[2] != "0:" {
			return false
		}
		if fields[1] != "noqueue" && fields[1] != "noop" {
			return false
		}
	}
	return true
}

func (s *Service) restoreIFB(ctx context.Context, ifb string, wasUp bool) error {
	exists, _, err := s.ifbState(ctx, ifb)
	if err != nil {
		return err
	}
	if !exists {
		if err := s.execute(ctx, "recreate IFB", "ip", "link", "add", ifb, "type", "ifb"); err != nil {
			return err
		}
	}
	state := "down"
	if wasUp {
		state = "up"
	}
	return s.execute(ctx, "restore IFB state", "ip", "link", "set", "dev", ifb, state)
}

func (s *Service) execute(ctx context.Context, action, command string, args ...string) error {
	if _, err := s.exec.Execute(ctx, command, args...); err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	return nil
}

func (s *Service) delete(ctx context.Context, action, command string, args ...string) error {
	if _, err := s.exec.Execute(ctx, command, args...); err != nil && !isNotFoundError(err) {
		return fmt.Errorf("%s: %w", action, err)
	}
	return nil
}

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "executable file not found") || strings.Contains(message, "command not found") {
		return false
	}
	if message == "not found" || strings.HasSuffix(message, " not found") {
		return true
	}
	for _, marker := range []string{
		"no such file or directory",
		"no such device",
		"does not exist",
		"doesn't exist",
		"cannot find device",
		"cannot find specified",
		"cannot find filter",
		"cannot find qdisc",
		"device not found",
		"filter not found",
		"qdisc not found",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func bandwidthArg(mbps int) string {
	return strconv.Itoa(mbps) + "mbit"
}

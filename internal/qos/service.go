package qos

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

const redirectFilterPriority = "49152"

const (
	managedEgressHandle  = "1:"
	managedIngressHandle = "1:"
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
	Persist  func() error
}

// Service applies QoS changes through the firewall command executor.
type Service struct {
	exec firewall.Executor

	locksMu       sync.Mutex
	interfaceLock map[string]*sync.Mutex
}

// NewService creates a QoS service.
func NewService(exec firewall.Executor) *Service {
	return &Service{exec: exec, interfaceLock: make(map[string]*sync.Mutex)}
}

// Apply validates and applies one WAN's desired QoS configuration.
func (s *Service) Apply(ctx context.Context, cfg Config) (State, error) {
	if err := cfg.Validate(); err != nil {
		return State{}, err
	}
	unlock := s.lockInterface(cfg.Interface)
	defer unlock()
	return s.apply(ctx, cfg)
}

// ApplyAndPersist applies cfg and invokes persist while the interface lock is
// held. If persistence fails, rollback is applied before returning the error.
// Keeping the kernel change and its durable configuration in one critical
// section prevents boot/API operations from interleaving on one interface.
func (s *Service) ApplyAndPersist(ctx context.Context, cfg, rollback Config, persist func() error) (State, error) {
	if err := cfg.Validate(); err != nil {
		return State{}, err
	}
	unlock := s.lockInterface(cfg.Interface)
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
	unlock := s.lockInterface(iface)
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

func (s *Service) applyAndPersistLocked(ctx context.Context, cfg, rollback Config, persist func() error) (State, error) {
	if err := cfg.Validate(); err != nil {
		return State{}, err
	}
	if persist == nil {
		return State{}, errors.New("qos persistence callback is nil")
	}

	state, err := s.apply(ctx, cfg)
	if err != nil {
		return State{}, err
	}
	if err := persist(); err != nil {
		if rollback.Interface != cfg.Interface || rollback.Validate() != nil {
			rollback = Config{Interface: cfg.Interface}
		}
		repairCtx, cancel := detachedRepairContext(ctx)
		defer cancel()
		if _, restoreErr := s.apply(repairCtx, rollback); restoreErr != nil {
			return State{}, fmt.Errorf("%w: persist QoS: %v; restore QoS: %v", ErrCompensationFailed, err, restoreErr)
		}
		return State{}, fmt.Errorf("persist QoS: %w", err)
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
	unlock := s.lockInterface(iface)
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
	return s.apply(ctx, cfg)
}

// InterfaceOperations are the QoS operations permitted while an interface
// lock is already held by WithInterfaceLock.
type InterfaceOperations interface {
	Apply(context.Context, Config) (State, error)
	ApplyNetem(context.Context, int, int) error
	RestoreAfterNetem(context.Context, Config) (State, error)
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

func (o lockedInterfaceOperations) ApplyNetem(ctx context.Context, delayMs, lossPct int) error {
	return o.service.applyNetem(ctx, o.iface, delayMs, lossPct)
}

func (o lockedInterfaceOperations) RestoreAfterNetem(ctx context.Context, cfg Config) (State, error) {
	if cfg.Interface != o.iface {
		return State{}, fmt.Errorf("qos operation targets %q while %q is locked", cfg.Interface, o.iface)
	}
	if err := cfg.Validate(); err != nil {
		return State{}, err
	}
	return o.service.restoreAfterNetem(ctx, cfg)
}

// WithInterfaceLock serializes non-QoS link mutations with QoS operations
// that use this shared service. The callback receives operations that reuse
// the held lock and must not call a public method on this service.
func (s *Service) WithInterfaceLock(_ context.Context, iface string, fn func(InterfaceOperations) error) error {
	if err := (Config{Interface: iface}).Validate(); err != nil {
		return err
	}
	unlock := s.lockInterface(iface)
	defer unlock()
	if fn == nil {
		return errors.New("qos interface lock callback is nil")
	}
	return fn(lockedInterfaceOperations{service: s, iface: iface})
}

func (s *Service) applyNetem(ctx context.Context, iface string, delayMs, lossPct int) error {
	if delayMs <= 0 {
		return errors.New("netem delay must be positive")
	}
	if lossPct < 0 || lossPct > 100 {
		return errors.New("netem loss must be between 0 and 100 percent")
	}
	before, err := s.read(ctx, "tc", "qdisc", "show", "dev", iface)
	if err != nil {
		return err
	}
	root, exists := rootQdisc(before)
	if exists && !isReplaceableInitialRoot(root) &&
		!hasManagedRootCake(before, managedEgressHandle) &&
		!hasManagedRootKind(before, "netem", managedNetemHandle) {
		return fmt.Errorf("%w: foreign root qdisc on %q", ErrOwnershipNotEstablished, iface)
	}
	journal := mutationJournal{service: s, ctx: ctx}
	return journal.run("apply stress-test netem", func(stepCtx context.Context) error {
		return s.execute(stepCtx, "apply stress-test netem", "tc", "qdisc", "replace", "dev", iface,
			"root", "handle", managedNetemHandle, "netem", "delay", strconv.Itoa(delayMs)+"ms", "loss", strconv.Itoa(lossPct)+"%")
	}, func(repairCtx context.Context) error {
		return s.restoreRoot(repairCtx, iface, before, "netem", managedNetemHandle, managedEgressHandle, "dual-srchost")
	})
}

func (s *Service) restoreAfterNetem(ctx context.Context, cfg Config) (State, error) {
	output, err := s.read(ctx, "tc", "qdisc", "show", "dev", cfg.Interface)
	if err != nil {
		return State{}, err
	}
	root, exists := rootQdisc(output)
	if exists && !isReplaceableInitialRoot(root) &&
		!hasManagedRootCake(output, managedEgressHandle) &&
		!hasManagedRootKind(output, "netem", managedNetemHandle) {
		return State{}, fmt.Errorf("%w: foreign root qdisc on %q", ErrOwnershipNotEstablished, cfg.Interface)
	}
	if hasManagedRootKind(output, "netem", managedNetemHandle) {
		if err := s.removeManagedRoot(ctx, cfg.Interface, "netem", managedNetemHandle); err != nil {
			return State{}, err
		}
	}
	return s.apply(ctx, cfg)
}

func (s *Service) apply(ctx context.Context, cfg Config) (State, error) {
	if !cfg.Enabled {
		return s.disable(ctx, cfg.Interface)
	}
	ownership, err := s.inspectOwnership(ctx, cfg.Interface)
	if err != nil {
		return State{}, err
	}
	if ownership.egressForeign {
		return State{}, fmt.Errorf("%w: foreign root qdisc on %q", ErrOwnershipNotEstablished, cfg.Interface)
	}
	if ownership.ingressForeign {
		return State{}, fmt.Errorf("%w: foreign root qdisc on %q", ErrOwnershipNotEstablished, IFBName(cfg.Interface))
	}
	if ownership.filterPresent && !ownership.redirectOwned {
		return State{}, fmt.Errorf("%w: foreign ingress filter on %q", ErrOwnershipNotEstablished, cfg.Interface)
	}
	return s.applyWithOwnership(ctx, cfg, ownership)
}

type qosUndo func(context.Context) error

func (s *Service) applyWithOwnership(ctx context.Context, cfg Config, ownership ownershipState) (State, error) {
	mode := "besteffort"
	if cfg.Interactive {
		mode = "diffserv4"
	}
	ifb := IFBName(cfg.Interface)
	journal := mutationJournal{service: s, ctx: ctx}

	if err := journal.run("apply egress CAKE", func(stepCtx context.Context) error {
		return s.execute(stepCtx, "apply egress CAKE", "tc",
			"qdisc", "replace", "dev", cfg.Interface, "root", "handle", managedEgressHandle, "cake",
			"bandwidth", bandwidthArg(cfg.UploadMbps), mode, "dual-srchost")
	}, func(repairCtx context.Context) error {
		return s.restoreRoot(repairCtx, cfg.Interface, ownership.egressOutput,
			"cake", managedEgressHandle, managedEgressHandle, "dual-srchost")
	}); err != nil {
		return State{}, err
	}

	if !ownership.ifbExists {
		if err := journal.run("create IFB", func(stepCtx context.Context) error {
			return s.execute(stepCtx, "create IFB", "ip", "link", "add", ifb, "type", "ifb")
		}, func(repairCtx context.Context) error {
			return s.delete(repairCtx, "remove IFB after failed QoS apply", "ip", "link", "del", "dev", ifb)
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
			"bandwidth", bandwidthArg(cfg.DownloadMbps), mode, "dual-dsthost")
	}, func(repairCtx context.Context) error {
		return s.restoreRoot(repairCtx, ifb, ownership.ingressOutput,
			"cake", managedIngressHandle, managedIngressHandle, "dual-dsthost")
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
	service *Service
	ctx     context.Context
	undos   []qosUndo
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

func (s *Service) restoreRoot(ctx context.Context, iface, previousOutput, currentKind, currentHandle, previousManagedHandle, hostMode string) error {
	root, ok := rootQdisc(previousOutput)
	if !ok {
		return s.removeManagedRoot(ctx, iface, currentKind, currentHandle)
	}
	if isReplaceableInitialRoot(root) {
		return s.execute(ctx, "restore initial root qdisc", "tc", "qdisc", "replace", "dev", iface, "root", root.kind)
	}
	if root.kind != "cake" || root.handle != previousManagedHandle {
		return fmt.Errorf("%w: cannot restore root qdisc %q %q", ErrOwnershipNotEstablished, root.kind, root.handle)
	}
	currentOutput, err := s.read(ctx, "tc", "qdisc", "show", "dev", iface)
	if err != nil {
		return err
	}
	current, currentExists := rootQdisc(currentOutput)
	if currentExists && !hasManagedRootKind(currentOutput, currentKind, currentHandle) &&
		!(current.kind == root.kind && current.handle == root.handle) {
		return fmt.Errorf("%w: root qdisc on %q changed during repair", ErrOwnershipNotEstablished, iface)
	}
	bandwidth, mode, ok := cakeSettings(previousOutput)
	if !ok {
		return errors.New("managed CAKE root has no restorable bandwidth")
	}
	return s.execute(ctx, "restore managed root qdisc", "tc", "qdisc", "replace", "dev", iface,
		"root", "handle", previousManagedHandle, "cake", "bandwidth", bandwidth, mode, hostMode)
}

func cakeSettings(output string) (string, string, bool) {
	fields := strings.Fields(output)
	bandwidth := ""
	mode := "besteffort"
	for i, field := range fields {
		if field == "bandwidth" && i+1 < len(fields) {
			value := strings.ToLower(fields[i+1])
			if strings.HasSuffix(value, "mbit") {
				bandwidth = value
			}
		}
		if field == "diffserv4" {
			mode = field
		}
	}
	return bandwidth, mode, bandwidth != ""
}

func (s *Service) restoreRedirect(ctx context.Context, iface, ifb string) error {
	return s.execute(ctx, "restore ingress redirect", "tc", "filter", "replace", "dev", iface, "ingress",
		"pref", redirectFilterPriority, "protocol", "all", "matchall", "action", "mirred", "egress", "redirect", "dev", ifb)
}

func (s *Service) removeManagedRoot(ctx context.Context, iface, kind, handle string) error {
	output, err := s.read(ctx, "tc", "qdisc", "show", "dev", iface)
	if err != nil {
		return err
	}
	root, ok := rootQdisc(output)
	if !ok || isReplaceableInitialRoot(root) {
		return nil
	}
	if !hasManagedRootKind(output, kind, handle) {
		return fmt.Errorf("%w: refusing to remove root qdisc on %q", ErrOwnershipNotEstablished, iface)
	}
	return s.delete(ctx, "remove managed root qdisc", "tc", "qdisc", "del", "dev", iface, "root")
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
	unlock := s.lockInterface(iface)
	defer unlock()
	return s.disable(ctx, iface)
}

func (s *Service) disable(ctx context.Context, iface string) (State, error) {
	ifb := IFBName(iface)
	ownership, err := s.inspectOwnership(ctx, iface)
	if err != nil {
		return State{}, err
	}
	journal := mutationJournal{service: s, ctx: ctx}

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
		if err := journal.run("remove egress CAKE", func(stepCtx context.Context) error {
			return s.removeManagedRoot(stepCtx, iface, "cake", managedEgressHandle)
		}, func(repairCtx context.Context) error {
			return s.restoreRoot(repairCtx, iface, ownership.egressOutput,
				"cake", managedEgressHandle, managedEgressHandle, "dual-srchost")
		}); err != nil {
			return State{}, err
		}
	}

	if ownership.ingressOwned {
		if err := journal.run("remove ingress CAKE", func(stepCtx context.Context) error {
			return s.removeManagedRoot(stepCtx, ifb, "cake", managedIngressHandle)
		}, func(repairCtx context.Context) error {
			return s.restoreRoot(repairCtx, ifb, ownership.ingressOutput,
				"cake", managedIngressHandle, managedIngressHandle, "dual-dsthost")
		}); err != nil {
			return State{}, err
		}
		if ownership.redirectOwned || !ownership.filterPresent {
			if err := journal.run("remove IFB", func(stepCtx context.Context) error {
				return s.delete(stepCtx, "remove IFB", "ip", "link", "del", "dev", ifb)
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
	egressOutput   string
	egressOwned    bool
	egressForeign  bool
	ifbExists      bool
	ifbUp          bool
	ingressOutput  string
	ingressOwned   bool
	ingressForeign bool
	clsact         bool
	filterPresent  bool
	redirectOwned  bool
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
	ownership := ownershipState{
		egressOutput:  egress,
		egressOwned:   hasManagedRootCake(egress, managedEgressHandle),
		egressForeign: hasForeignRootQdisc(egress, managedEgressHandle),
		ifbExists:     exists,
		ifbUp:         up,
		clsact:        hasClsact(egress),
		filterPresent: hasFilterRecord(redirect),
		redirectOwned: hasManagedRedirect(redirect, ifb),
	}
	if !exists {
		return ownership, nil
	}
	ingress, err := s.read(ctx, "tc", "qdisc", "show", "dev", ifb)
	if err != nil {
		return ownershipState{}, err
	}
	ownership.ingressOutput = ingress
	ownership.ingressOwned = hasManagedRootCake(ingress, managedIngressHandle)
	ownership.ingressForeign = hasForeignRootQdisc(ingress, managedIngressHandle)
	return ownership, nil
}

func (s *Service) lockInterface(iface string) func() {
	s.locksMu.Lock()
	if s.interfaceLock == nil {
		s.interfaceLock = make(map[string]*sync.Mutex)
	}
	lock := s.interfaceLock[iface]
	if lock == nil {
		lock = &sync.Mutex{}
		s.interfaceLock[iface] = lock
	}
	s.locksMu.Unlock()

	lock.Lock()
	return lock.Unlock
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

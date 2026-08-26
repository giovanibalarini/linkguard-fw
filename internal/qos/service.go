package qos

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

const redirectFilterPriority = "49152"

const (
	managedEgressHandle  = "1:"
	managedIngressHandle = "1:"
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
		if _, restoreErr := s.apply(ctx, rollback); restoreErr != nil {
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

func (s *Service) apply(ctx context.Context, cfg Config) (State, error) {
	if !cfg.Enabled {
		return s.disable(ctx, cfg.Interface)
	}
	ownership, err := s.inspectOwnership(ctx, cfg.Interface)
	if err != nil {
		return State{}, err
	}
	if ownership.egressRoot && !ownership.egressOwned {
		return State{}, fmt.Errorf("%w: foreign root qdisc on %q", ErrOwnershipNotEstablished, cfg.Interface)
	}
	if ownership.ingressRoot && !ownership.ingressOwned {
		return State{}, fmt.Errorf("%w: foreign root qdisc on %q", ErrOwnershipNotEstablished, IFBName(cfg.Interface))
	}
	if ownership.filterPresent && !ownership.redirectOwned {
		return State{}, fmt.Errorf("%w: foreign ingress filter on %q", ErrOwnershipNotEstablished, cfg.Interface)
	}

	mode := "besteffort"
	if cfg.Interactive {
		mode = "diffserv4"
	}
	ifb := IFBName(cfg.Interface)

	if err := s.execute(ctx, "apply egress CAKE", "tc",
		"qdisc", "replace", "dev", cfg.Interface, "root", "handle", managedEgressHandle, "cake",
		"bandwidth", bandwidthArg(cfg.UploadMbps), mode, "dual-srchost"); err != nil {
		return State{}, err
	}

	if !ownership.ifbExists {
		if err := s.execute(ctx, "create IFB", "ip", "link", "add", ifb, "type", "ifb"); err != nil {
			return State{}, err
		}
	}
	if err := s.execute(ctx, "bring IFB up", "ip", "link", "set", "dev", ifb, "up"); err != nil {
		return State{}, err
	}
	if err := s.execute(ctx, "apply ingress CAKE", "tc",
		"qdisc", "replace", "dev", ifb, "root", "handle", managedIngressHandle, "cake",
		"bandwidth", bandwidthArg(cfg.DownloadMbps), mode, "dual-dsthost"); err != nil {
		return State{}, err
	}
	if !ownership.clsact {
		if err := s.execute(ctx, "ensure clsact", "tc", "qdisc", "add", "dev", cfg.Interface, "clsact"); err != nil {
			return State{}, err
		}
	}
	if err := s.execute(ctx, "redirect ingress", "tc",
		"filter", "replace", "dev", cfg.Interface, "ingress",
		"pref", redirectFilterPriority, "protocol", "all", "matchall",
		"action", "mirred", "egress", "redirect", "dev", ifb); err != nil {
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

	if ownership.redirectOwned {
		if err := s.delete(ctx, "remove ingress redirect", "tc",
			"filter", "del", "dev", iface, "ingress", "pref", redirectFilterPriority); err != nil {
			return State{}, err
		}
	}
	if ownership.egressOwned {
		if err := s.delete(ctx, "remove egress CAKE", "tc", "qdisc", "del", "dev", iface, "root"); err != nil {
			return State{}, err
		}
	}

	if ownership.ingressOwned {
		if err := s.delete(ctx, "remove ingress CAKE", "tc", "qdisc", "del", "dev", ifb, "root"); err != nil {
			return State{}, err
		}
		if ownership.redirectOwned || !ownership.filterPresent {
			if err := s.delete(ctx, "remove IFB", "ip", "link", "del", "dev", ifb); err != nil {
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
	egressRoot    bool
	egressOwned   bool
	ifbExists     bool
	ingressRoot   bool
	ingressOwned  bool
	clsact        bool
	filterPresent bool
	redirectOwned bool
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
	exists, err := s.ifbExists(ctx, ifb)
	if err != nil {
		return ownershipState{}, err
	}
	ownership := ownershipState{
		egressRoot:    hasRootQdisc(egress),
		egressOwned:   hasManagedRootCake(egress, managedEgressHandle),
		ifbExists:     exists,
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
	ownership.ingressRoot = hasRootQdisc(ingress)
	ownership.ingressOwned = hasManagedRootCake(ingress, managedIngressHandle)
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

func (s *Service) ifbExists(ctx context.Context, ifb string) (bool, error) {
	_, err := s.exec.ExecuteRead(ctx, "ip", "link", "show", "dev", ifb)
	if err == nil {
		return true, nil
	}
	if isNotFoundError(err) {
		return false, nil
	}
	return false, fmt.Errorf("check IFB %q: %w", ifb, err)
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

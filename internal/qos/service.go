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

// ErrStaleInterface indicates that a configuration loader observed a link
// moving to another interface while the previous interface was locked.
var ErrStaleInterface = errors.New("qos interface changed while loading configuration")

// State describes the queue-control objects accepted by the service.
type State struct {
	Enabled   bool   `json:"enabled"`
	Interface string `json:"interface"`
	IFB       string `json:"ifb"`
	Mode      string `json:"mode"`
	DryRun    bool   `json:"dry_run"`
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

	state, err := s.apply(ctx, cfg)
	if err != nil {
		return State{}, err
	}
	if err := persist(); err != nil {
		if rollback.Interface != cfg.Interface || rollback.Validate() != nil {
			rollback = Config{Interface: cfg.Interface}
		}
		if _, restoreErr := s.apply(ctx, rollback); restoreErr != nil {
			return State{}, fmt.Errorf("persist QoS: %w; restore QoS: %v", err, restoreErr)
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

// WithInterfaceLock serializes non-QoS link mutations with QoS operations
// that use this shared service. The callback must not call a public method on
// this service, because it already runs under the interface lock.
func (s *Service) WithInterfaceLock(_ context.Context, iface string, fn func() error) error {
	if err := (Config{Interface: iface}).Validate(); err != nil {
		return err
	}
	unlock := s.lockInterface(iface)
	defer unlock()
	return fn()
}

func (s *Service) apply(ctx context.Context, cfg Config) (State, error) {
	if !cfg.Enabled {
		return s.disable(ctx, cfg.Interface)
	}

	mode := "besteffort"
	if cfg.Interactive {
		mode = "diffserv4"
	}
	ifb := IFBName(cfg.Interface)

	if err := s.execute(ctx, "apply egress CAKE", "tc",
		"qdisc", "replace", "dev", cfg.Interface, "root", "cake",
		"bandwidth", bandwidthArg(cfg.UploadMbps), mode, "dual-srchost"); err != nil {
		return State{}, err
	}

	if s.exec.IsDryRun() {
		if err := s.execute(ctx, "create IFB", "ip", "link", "add", ifb, "type", "ifb"); err != nil {
			return State{}, err
		}
	} else {
		exists, err := s.ifbExists(ctx, ifb)
		if err != nil {
			return State{}, err
		}
		if !exists {
			if err := s.execute(ctx, "create IFB", "ip", "link", "add", ifb, "type", "ifb"); err != nil {
				return State{}, err
			}
		}
	}
	if err := s.execute(ctx, "bring IFB up", "ip", "link", "set", "dev", ifb, "up"); err != nil {
		return State{}, err
	}
	if err := s.execute(ctx, "apply ingress CAKE", "tc",
		"qdisc", "replace", "dev", ifb, "root", "cake",
		"bandwidth", bandwidthArg(cfg.DownloadMbps), mode, "dual-dsthost"); err != nil {
		return State{}, err
	}
	if err := s.execute(ctx, "ensure clsact", "tc", "qdisc", "replace", "dev", cfg.Interface, "clsact"); err != nil {
		return State{}, err
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

	if err := s.delete(ctx, "remove ingress redirect", "tc",
		"filter", "del", "dev", iface, "ingress", "pref", redirectFilterPriority); err != nil {
		return State{}, err
	}
	if err := s.delete(ctx, "remove egress CAKE", "tc", "qdisc", "del", "dev", iface, "root"); err != nil {
		return State{}, err
	}

	if s.exec.IsDryRun() {
		if err := s.delete(ctx, "remove ingress CAKE", "tc", "qdisc", "del", "dev", ifb, "root"); err != nil {
			return State{}, err
		}
		if err := s.delete(ctx, "remove IFB", "ip", "link", "del", "dev", ifb); err != nil {
			return State{}, err
		}
	} else {
		exists, err := s.ifbExists(ctx, ifb)
		if err != nil {
			return State{}, err
		}
		if exists {
			if err := s.delete(ctx, "remove ingress CAKE", "tc", "qdisc", "del", "dev", ifb, "root"); err != nil {
				return State{}, err
			}
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

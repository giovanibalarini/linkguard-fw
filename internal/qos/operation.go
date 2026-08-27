package qos

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// OperationIntent identifies the kernel transition protected by a durable
// lease. The value is persisted and must remain stable across upgrades.
type OperationIntent string

const (
	OperationApply     OperationIntent = "apply"
	OperationDisable   OperationIntent = "disable"
	OperationBenchmark OperationIntent = "benchmark"
)

// CakeSignature is the complete CAKE identity LinkGuard accepts during
// recovery. NAT and ingress are part of ownership, not optional decoration.
type CakeSignature struct {
	Handle    string `json:"handle"`
	Bandwidth string `json:"bandwidth"`
	Mode      string `json:"mode"`
	HostMode  string `json:"host_mode"`
	NAT       bool   `json:"nat"`
	Ingress   bool   `json:"ingress"`
}

// OperationLease is the durable recovery journal for one interface. Target
// records what the interrupted process was applying; Recovery records the
// state a fresh process must converge to before clearing the lease.
type OperationLease struct {
	ID            string          `json:"id"`
	Interface     string          `json:"interface"`
	Intent        OperationIntent `json:"intent"`
	Stage         int             `json:"stage"`
	Target        Config          `json:"target"`
	Recovery      Config          `json:"recovery"`
	BeforeEgress  *CakeSignature  `json:"before_egress,omitempty"`
	BeforeIngress *CakeSignature  `json:"before_ingress,omitempty"`
	IFBExisted    bool            `json:"ifb_existed"`
	IFBWasUp      bool            `json:"ifb_was_up"`
	ClsactExisted bool            `json:"clsact_existed"`
	CreatedAt     time.Time       `json:"created_at"`
}

// Validate rejects malformed recovery evidence before it reaches SQLite.
func (l OperationLease) Validate() error {
	if l.ID == "" {
		return errors.New("qos operation lease requires id")
	}
	if !validInterfaceName(l.Interface) {
		return errors.New("qos operation lease has invalid interface")
	}
	if l.Intent != OperationApply && l.Intent != OperationDisable && l.Intent != OperationBenchmark {
		return errors.New("qos operation lease has invalid intent")
	}
	if l.Stage < 0 {
		return errors.New("qos operation lease has invalid stage")
	}
	if l.Target.Interface != l.Interface || l.Recovery.Interface != l.Interface {
		return errors.New("qos operation lease configurations must use its interface")
	}
	if err := l.Target.Validate(); err != nil {
		return err
	}
	return l.Recovery.Validate()
}

// OperationStore persists QoS recovery evidence before and between kernel
// mutations. Implementations must use compare-and-swap for stage and clear.
type OperationStore interface {
	SaveQoSOperationLease(*OperationLease) error
	AdvanceQoSOperationLease(operationID string, fromStage, toStage int) error
	ListQoSOperationLeases() ([]OperationLease, error)
	ClearQoSOperationLease(operationID, iface string) error
}

// RecoverInterrupted consumes every durable lease under the same per-interface
// lock used by normal Apply/Disable operations. Partial objects are removed
// only when they match a signature recorded or derived from the lease; then
// the recovery configuration is reapplied and the lease is cleared.
func (s *Service) RecoverInterrupted(ctx context.Context) error {
	if s.store == nil || s.exec.IsDryRun() {
		return nil
	}
	leases, err := s.store.ListQoSOperationLeases()
	if err != nil {
		return fmt.Errorf("list interrupted QoS operations: %w", err)
	}
	var recoveryErrors []error
	for _, lease := range leases {
		if err := lease.Validate(); err != nil {
			recoveryErrors = append(recoveryErrors, fmt.Errorf("operation %q: %w", lease.ID, err))
			continue
		}
		unlock, err := s.lockInterface(ctx, lease.Interface)
		if err != nil {
			recoveryErrors = append(recoveryErrors, fmt.Errorf("operation %q: %w", lease.ID, err))
			continue
		}
		err = s.recoverLeaseLocked(ctx, lease)
		unlock()
		if err != nil {
			recoveryErrors = append(recoveryErrors, fmt.Errorf("operation %q on %q: %w", lease.ID, lease.Interface, err))
		}
	}
	return errors.Join(recoveryErrors...)
}

func (s *Service) recoverLeaseLocked(ctx context.Context, lease OperationLease) error {
	ifb := IFBName(lease.Interface)
	egress, err := s.read(ctx, "tc", "qdisc", "show", "dev", lease.Interface)
	if err != nil {
		return err
	}
	redirect, err := s.read(ctx, "tc", "filter", "show", "dev", lease.Interface, "ingress", "pref", redirectFilterPriority)
	if err != nil {
		return err
	}
	if hasFilterRecord(redirect) && !hasManagedRedirect(redirect, ifb) {
		return fmt.Errorf("%w: recovery found foreign ingress filter", ErrOwnershipNotEstablished)
	}
	if hasManagedRedirect(redirect, ifb) {
		if err := s.removeManagedRedirect(ctx, lease.Interface, ifb); err != nil {
			return err
		}
	}
	if sig, ok, err := recoveryRootSignature(egress, false, lease); err != nil {
		return err
	} else if ok {
		if err := s.removeRootMatching(ctx, lease.Interface, sig); err != nil {
			return err
		}
	}

	ifbExists, _, err := s.ifbState(ctx, ifb)
	if err != nil {
		return err
	}
	if ifbExists {
		ingress, err := s.read(ctx, "tc", "qdisc", "show", "dev", ifb)
		if err != nil {
			return err
		}
		if sig, ok, err := recoveryRootSignature(ingress, true, lease); err != nil {
			return err
		} else if ok {
			if err := s.removeRootMatching(ctx, ifb, sig); err != nil {
				return err
			}
		}
		if !lease.IFBExisted {
			if err := s.removeIFBIfUnclaimed(ctx, ifb, "recover interrupted QoS IFB"); err != nil {
				return err
			}
		}
	}
	if !lease.ClsactExisted {
		if err := s.removeAddedClsact(ctx, lease.Interface); err != nil {
			return err
		}
	}

	if lease.Recovery.Enabled {
		if _, err := s.apply(ctx, lease.Recovery); err != nil {
			return fmt.Errorf("restore recovery configuration: %w", err)
		}
	} else if lease.IFBExisted {
		// A pre-existing unclaimed IFB is not ours to delete. Restore only the
		// administrative state that the interrupted Apply may have changed.
		state := "down"
		if lease.IFBWasUp {
			state = "up"
		}
		if err := s.execute(ctx, "restore pre-existing IFB state", "ip", "link", "set", "dev", ifb, state); err != nil {
			return err
		}
	}
	if err := s.store.ClearQoSOperationLease(lease.ID, lease.Interface); err != nil {
		return fmt.Errorf("clear recovered QoS operation: %w", err)
	}
	return nil
}

func recoveryRootSignature(output string, ingress bool, lease OperationLease) (rootSignature, bool, error) {
	root, exists := rootQdisc(output)
	if !exists || isReplaceableInitialRoot(root) {
		return rootSignature{}, false, nil
	}
	for _, sig := range recoveryCakeSignatures(ingress, lease) {
		if sig.matches(output) {
			return sig, true, nil
		}
	}
	return rootSignature{}, false, fmt.Errorf("%w: recovery found unrecorded root qdisc", ErrOwnershipNotEstablished)
}

func recoveryCakeSignatures(ingress bool, lease OperationLease) []rootSignature {
	var signatures []rootSignature
	for _, cfg := range []Config{lease.Target, lease.Recovery} {
		if !cfg.Enabled {
			continue
		}
		mode := "besteffort"
		if cfg.Interactive {
			mode = "diffserv4"
		}
		if ingress {
			signatures = append(signatures, cakeRootSignature(
				managedIngressHandle, bandwidthArg(cfg.DownloadMbps), mode, "dual-dsthost", true, true))
		} else {
			signatures = append(signatures, cakeRootSignature(
				managedEgressHandle, bandwidthArg(cfg.UploadMbps), mode, "dual-srchost", true, false))
		}
	}
	before := lease.BeforeEgress
	if ingress {
		before = lease.BeforeIngress
	}
	if before != nil {
		signatures = append(signatures, rootSignature{
			kind: "cake", handle: before.Handle, bandwidth: before.Bandwidth,
			mode: before.Mode, hostMode: before.HostMode, nat: before.NAT, ingress: before.Ingress,
		})
	}
	return signatures
}

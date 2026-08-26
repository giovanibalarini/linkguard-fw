package qos

import (
	"context"
	"fmt"
	"strconv"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

const redirectFilterPriority = "49152"

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
}

// NewService creates a QoS service.
func NewService(exec firewall.Executor) *Service {
	return &Service{exec: exec}
}

// Apply validates and applies one WAN's desired QoS configuration.
func (s *Service) Apply(ctx context.Context, cfg Config) (State, error) {
	if err := cfg.Validate(); err != nil {
		return State{}, err
	}
	if !cfg.Enabled {
		return s.Disable(ctx, cfg.Interface)
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

	if s.exec.IsDryRun() || !s.ifbExists(ctx, ifb) {
		if err := s.execute(ctx, "create IFB", "ip", "link", "add", ifb, "type", "ifb"); err != nil {
			return State{}, err
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
	ifb := IFBName(iface)

	if err := s.execute(ctx, "remove ingress redirect", "tc",
		"filter", "del", "dev", iface, "ingress", "pref", redirectFilterPriority); err != nil {
		return State{}, err
	}
	if err := s.execute(ctx, "remove egress CAKE", "tc", "qdisc", "del", "dev", iface, "root"); err != nil {
		return State{}, err
	}

	if s.exec.IsDryRun() || s.ifbExists(ctx, ifb) {
		if err := s.execute(ctx, "remove ingress CAKE", "tc", "qdisc", "del", "dev", ifb, "root"); err != nil {
			return State{}, err
		}
		if err := s.execute(ctx, "remove IFB", "ip", "link", "del", "dev", ifb); err != nil {
			return State{}, err
		}
	}

	return State{
		Interface: iface,
		IFB:       ifb,
		DryRun:    s.exec.IsDryRun(),
	}, nil
}

func (s *Service) ifbExists(ctx context.Context, ifb string) bool {
	_, err := s.exec.ExecuteRead(ctx, "ip", "link", "show", "dev", ifb)
	return err == nil
}

func (s *Service) execute(ctx context.Context, action, command string, args ...string) error {
	if _, err := s.exec.Execute(ctx, command, args...); err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	return nil
}

func bandwidthArg(mbps int) string {
	return strconv.Itoa(mbps) + "mbit"
}

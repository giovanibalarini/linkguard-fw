package qos

import (
	"context"
	"fmt"
	"strings"
)

// Observe reads the queue-control objects managed for one interface without
// changing them. The returned state describes the presence of the complete
// egress/IFB/ingress/redirect chain in the kernel.
func (s *Service) Observe(ctx context.Context, iface string) (State, error) {
	if err := (Config{Interface: iface}).Validate(); err != nil {
		return State{}, err
	}
	unlock := s.lockInterface(iface)
	defer unlock()
	return s.observe(ctx, iface)
}

func (s *Service) observe(ctx context.Context, iface string) (State, error) {
	ifb := IFBName(iface)
	state := State{Interface: iface, IFB: ifb, DryRun: s.exec.IsDryRun()}

	if _, err := s.read(ctx, "ip", "link", "show", "dev", ifb); err != nil {
		if isNotFoundError(err) {
			return state, nil
		}
		return State{}, err
	}
	egress, err := s.read(ctx, "tc", "qdisc", "show", "dev", iface)
	if err != nil {
		return State{}, err
	}
	ingress, err := s.read(ctx, "tc", "qdisc", "show", "dev", ifb)
	if err != nil {
		return State{}, err
	}
	redirect, err := s.read(ctx, "tc", "filter", "show", "dev", iface, "ingress", "pref", redirectFilterPriority)
	if err != nil {
		return State{}, err
	}

	state.Enabled = hasRootCake(egress) && hasRootCake(ingress) && hasManagedRedirect(redirect, ifb)
	state.Mode = observedMode(egress, ingress)
	return state, nil
}

func (s *Service) read(ctx context.Context, command string, args ...string) (string, error) {
	output, err := s.exec.ExecuteRead(ctx, command, args...)
	if err != nil {
		return "", fmt.Errorf("observe %s: %w", command, err)
	}
	return output, nil
}

func hasRootCake(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "qdisc" && fields[1] == "cake" && containsField(fields[2:], "root") {
			return true
		}
	}
	return false
}

func hasManagedRedirect(output, ifb string) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "pref "+redirectFilterPriority) &&
			strings.Contains(line, "matchall") && strings.Contains(line, ifb) {
			return true
		}
	}
	return false
}

func observedMode(outputs ...string) string {
	for _, output := range outputs {
		if strings.Contains(output, "diffserv4") {
			return "diffserv4"
		}
		if strings.Contains(output, "besteffort") {
			return "besteffort"
		}
	}
	return ""
}

func containsField(fields []string, want string) bool {
	for _, field := range fields {
		if field == want {
			return true
		}
	}
	return false
}

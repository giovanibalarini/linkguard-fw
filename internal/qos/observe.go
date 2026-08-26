package qos

import (
	"context"
	"fmt"
	"strings"
	"unicode"
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

	state.Enabled = hasManagedRootCake(egress, managedEgressHandle) &&
		hasManagedRootCake(ingress, managedIngressHandle) && hasManagedRedirect(redirect, ifb)
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
	return hasManagedRootCake(output, managedEgressHandle)
}

func hasManagedRootCake(output, handle string) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "qdisc" && fields[1] == "cake" &&
			fields[2] == handle && fields[3] == "root" {
			return true
		}
	}
	return false
}

func hasRootQdisc(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "qdisc" && fields[3] == "root" {
			return true
		}
	}
	return false
}

func hasClsact(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "qdisc" && fields[1] == "clsact" {
			return true
		}
	}
	return false
}

func hasManagedRedirect(output, ifb string) bool {
	// `tc filter show` emits one filter as a block: the preference, matchall,
	// action, and destination device commonly occur on separate lines. Keep
	// block boundaries at the next filter record and match within the block.
	var block strings.Builder
	flush := func() bool {
		if block.Len() == 0 {
			return false
		}
		words := tcWords(block.String())
		for _, required := range []string{
			"pref", redirectFilterPriority, "matchall", "action", "mirred", "egress", "redirect", strings.ToLower(ifb),
		} {
			if !containsField(words, required) {
				return false
			}
		}
		return true
	}
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "filter ") && block.Len() > 0 {
			if flush() {
				return true
			}
			block.Reset()
		}
		if block.Len() > 0 {
			block.WriteByte('\n')
		}
		block.WriteString(line)
	}
	return flush()
}

func hasFilterRecord(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "filter ") {
			return true
		}
	}
	return strings.TrimSpace(output) != ""
}

func tcWords(text string) []string {
	return strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == ':')
	})
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

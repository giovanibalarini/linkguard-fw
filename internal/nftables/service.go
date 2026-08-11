// Package nftables manages the firewall via the native nft tooling. It replaces
// the legacy iptables path: the system now runs a single `table inet linkguard`
// ruleset, and all management (read, backup/restore, host blocking) goes through
// nft rather than iptables.
package nftables

import (
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

// Family/table the application owns.
const (
	Family = "inet"
	Table  = "linkguard"
	// BlockedSet holds individual host IPs whose forwarded traffic is dropped.
	BlockedSet = "blocked_hosts"
	// HostWanMap maps a host IP to the fwmark that steers it to a given WAN.
	HostWanMap = "host_wan"
)

// Service wraps nft operations.
type Service struct {
	exec firewall.Executor
}

// NewService creates an nftables Service.
func NewService(exec firewall.Executor) *Service {
	return &Service{exec: exec}
}

// Ruleset returns the full live nftables ruleset (`nft list ruleset`).
func (s *Service) Ruleset(ctx context.Context) (string, error) {
	return s.exec.ExecuteRead(ctx, "nft", "list", "ruleset")
}

// Save returns the current ruleset for storage as a backup (same as Ruleset).
func (s *Service) Save(ctx context.Context) (string, error) {
	return s.Ruleset(ctx)
}

// Restore atomically reloads a previously saved ruleset via `nft -f`.
func (s *Service) Restore(ctx context.Context, ruleset string) (string, error) {
	f, err := os.CreateTemp("", "linkguard-nft-*.conf")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(f.Name())
	// Ensure a clean load: flush before applying the snapshot.
	body := "flush ruleset\n" + ruleset
	if _, err := f.WriteString(body); err != nil {
		f.Close()
		return "", fmt.Errorf("write ruleset: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close temp file: %w", err)
	}
	return s.exec.Execute(ctx, "nft", "-f", f.Name())
}

// BlockHost drops a host's forwarded traffic by adding its IP to the blocked set.
func (s *Service) BlockHost(ctx context.Context, ip string) (string, error) {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("ip inválido")
	}
	out, err := s.exec.Execute(ctx, "nft", "add", "element", Family, Table, BlockedSet, "{", ip, "}")
	if err != nil {
		return out, err
	}
	return out, s.Persist(ctx)
}

// UnblockHost removes a host's IP from the blocked set.
func (s *Service) UnblockHost(ctx context.Context, ip string) (string, error) {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("ip inválido")
	}
	out, err := s.exec.Execute(ctx, "nft", "delete", "element", Family, Table, BlockedSet, "{", ip, "}")
	if err != nil {
		return out, err
	}
	return out, s.Persist(ctx)
}

// ─── Managed view & editing (sets / map elements) ────────────────────────────

// ConfPath is the persisted ruleset loaded by nftables.service at boot. A var
// (not const) so tests can point it at a temp file instead of the real
// system path — Persist() has no other way to reach it, being the only
// filesystem write in this package that doesn't go through the Executor.
var ConfPath = "/etc/nftables.conf"

// DefaultWanMark steers a host to the secondary WAN (sumicity).
const DefaultWanMark = "0x12c"

// WanHost is one entry of the host_wan map (a host steered to a WAN by fwmark).
type WanHost struct {
	IP   string `json:"ip"`
	Mark string `json:"mark"`
}

// Managed is the editable, element-level view of the linkguard ruleset.
type Managed struct {
	WanHosts     []WanHost `json:"wan_hosts"`
	Blocklist    []string  `json:"blocklist"`
	BlockedHosts []string  `json:"blocked_hosts"`
}

// Managed returns the current elements of the host_wan map and the sets.
func (s *Service) Managed(ctx context.Context) (*Managed, error) {
	m := &Managed{WanHosts: []WanHost{}, Blocklist: []string{}, BlockedHosts: []string{}}

	if out, err := s.exec.ExecuteRead(ctx, "nft", "list", "map", Family, Table, HostWanMap); err == nil {
		for _, e := range parseElements(out) {
			parts := strings.SplitN(e, ":", 2)
			h := WanHost{IP: strings.TrimSpace(parts[0])}
			if len(parts) == 2 {
				h.Mark = strings.TrimSpace(parts[1])
			}
			m.WanHosts = append(m.WanHosts, h)
		}
	}
	if out, err := s.exec.ExecuteRead(ctx, "nft", "list", "set", Family, Table, "blocklist"); err == nil {
		m.Blocklist = parseElements(out)
	}
	if out, err := s.exec.ExecuteRead(ctx, "nft", "list", "set", Family, Table, BlockedSet); err == nil {
		m.BlockedHosts = parseElements(out)
	}
	return m, nil
}

// AddWanHost steers a host IP to a WAN by adding it to the host_wan map.
func (s *Service) AddWanHost(ctx context.Context, ip, mark string) (string, error) {
	if mark == "" {
		mark = DefaultWanMark
	}
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("ip inválido")
	}
	if !ValidMark(mark) {
		return "", fmt.Errorf("marca inválida")
	}
	out, err := s.exec.Execute(ctx, "nft", "add", "element", Family, Table, HostWanMap, "{", ip, ":", mark, "}")
	if err != nil {
		return out, err
	}
	return out, s.Persist(ctx)
}

// DelWanHost removes a host from the host_wan map (reverts it to the primary WAN).
func (s *Service) DelWanHost(ctx context.Context, ip string) (string, error) {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("ip inválido")
	}
	out, err := s.exec.Execute(ctx, "nft", "delete", "element", Family, Table, HostWanMap, "{", ip, "}")
	if err != nil {
		return out, err
	}
	return out, s.Persist(ctx)
}

// AddBlocklist blocks a destination CIDR by adding it to the blocklist set.
func (s *Service) AddBlocklist(ctx context.Context, cidr string) (string, error) {
	cidr = strings.TrimSpace(cidr)
	if !validIPOrCIDR(cidr) {
		return "", fmt.Errorf("CIDR/IP inválido")
	}
	out, err := s.exec.Execute(ctx, "nft", "add", "element", Family, Table, "blocklist", "{", cidr, "}")
	if err != nil {
		return out, err
	}
	return out, s.Persist(ctx)
}

// DelBlocklist removes a destination CIDR from the blocklist set.
func (s *Service) DelBlocklist(ctx context.Context, cidr string) (string, error) {
	cidr = strings.TrimSpace(cidr)
	if !validIPOrCIDR(cidr) {
		return "", fmt.Errorf("CIDR/IP inválido")
	}
	out, err := s.exec.Execute(ctx, "nft", "delete", "element", Family, Table, "blocklist", "{", cidr, "}")
	if err != nil {
		return out, err
	}
	return out, s.Persist(ctx)
}

// Persist writes ConfPath — reloaded by nftables.service at boot — so element
// edits (host_wan, blocklist, user rules, port forwards, ...) survive a
// reboot. Skipped in dry-run.
//
// Two hard-won constraints, both from a production incident (see
// docs/incidents or ask before "simplifying" this):
//
//  1. It serializes ONLY `table Family Table` (the table LinkGuard owns) via
//     `nft list table <family> <table>`, never `nft list ruleset` (the whole
//     kernel ruleset). During an incident an operator manually added a
//     blanket `iptables -t nat -A POSTROUTING -j MASQUERADE`, which lives in
//     `table ip nat` — a table LinkGuard does not own. A prior version of
//     this function dumped the entire ruleset into ConfPath, so it captured
//     that foreign rule and nftables.service recreated it on every boot, even
//     after it was deleted from the live ruleset. That rule had no interface
//     filter, so it masqueraded loopback traffic too: the box's own DNS
//     queries to 127.0.0.1 arrived at unbound with the WAN's source address
//     and were refused, chrony then had no working DNS to resolve its NTP
//     pool, and the clock silently drifted unsynchronized. LAN clients kept
//     working throughout, so the panel looked healthy — the failure was
//     invisible until directly investigated. Scoping to `table Family Table`
//     means a foreign table can never be captured here again.
//  2. The written file leads with the standard nft idempotent-reload
//     preamble — a bare `table <family> <table>` (creates it if absent, so
//     this line can never fail) followed by `delete table <family> <table>`
//     (now safe to delete, since it's guaranteed to exist) — before the full
//     table definition. Without this, `nft -f` on a box where the table
//     already exists in the kernel *appends* the definition instead of
//     replacing it, which is exactly how the same production box ended up
//     with two `oifname { ... } masquerade` rules in the postrouting chain,
//     one of them referencing an interface that no longer existed. This is
//     deliberately NOT `flush ruleset`: that would delete every foreign
//     table (including whatever else the box's operator or another tool set
//     up) on every boot, which is the opposite of what this fix is about —
//     LinkGuard resets only the table it owns.
func (s *Service) Persist(ctx context.Context) error {
	if s.exec.IsDryRun() {
		return nil
	}
	tbl, err := s.exec.ExecuteRead(ctx, "nft", "list", "table", Family, Table)
	if err != nil {
		return err
	}
	body := fmt.Sprintf(
		"#!/usr/sbin/nft -f\n\ntable %s %s\ndelete table %s %s\n\n%s\n",
		Family, Table, Family, Table, tbl,
	)
	return os.WriteFile(ConfPath, []byte(body), 0o644)
}

// ─── Port forwarding (DNAT) ──────────────────────────────────────────────────

// DNATChain is the prerouting nat chain that holds port-forward rules. It is
// created on demand and fully rebuilt on every apply, so it is always an exact
// reflection of the stored forwards.
const DNATChain = "prerouting_dnat"

// PortForward describes a single external-port → internal-host:port mapping.
type PortForward struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Proto     string `json:"proto"`     // tcp | udp
	Interface string `json:"interface"` // WAN iif; empty = any
	ExtPort   int    `json:"ext_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
}

// ApplyPortForwards rebuilds the DNAT chain from the given forwards atomically
// (`nft -f` with flush + re-add) and persists the ruleset. Only enabled,
// well-formed entries are emitted.
func (s *Service) ApplyPortForwards(ctx context.Context, fwds []PortForward) error {
	var b strings.Builder
	// Idempotent chain create, then flush + re-add inside one atomic load.
	fmt.Fprintf(&b, "add chain %s %s %s { type nat hook prerouting priority dstnat ; policy accept ; }\n",
		Family, Table, DNATChain)
	fmt.Fprintf(&b, "flush chain %s %s %s\n", Family, Table, DNATChain)
	for _, f := range fwds {
		if !f.Enabled {
			continue
		}
		rule, err := dnatRule(f)
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "add rule %s %s %s %s\n", Family, Table, DNATChain, rule)
	}

	f, err := os.CreateTemp("", "linkguard-dnat-*.conf")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(b.String()); err != nil {
		f.Close()
		return fmt.Errorf("write dnat: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if _, err := s.exec.Execute(ctx, "nft", "-f", f.Name()); err != nil {
		return fmt.Errorf("apply port forwards: %w", err)
	}
	return s.Persist(ctx)
}

// dnatRule renders one PortForward into an nft rule body (inet family DNAT to an
// IPv4 destination requires the `dnat ip to` form).
func dnatRule(f PortForward) (string, error) {
	proto := strings.ToLower(strings.TrimSpace(f.Proto))
	if proto != "tcp" && proto != "udp" {
		return "", fmt.Errorf("protocolo inválido: %q (use tcp ou udp)", f.Proto)
	}
	if f.ExtPort < 1 || f.ExtPort > 65535 || f.DestPort < 1 || f.DestPort > 65535 {
		return "", fmt.Errorf("porta fora do intervalo 1-65535")
	}
	if net.ParseIP(f.DestIP) == nil || strings.Contains(f.DestIP, ":") {
		return "", fmt.Errorf("IP de destino inválido: %q", f.DestIP)
	}
	var parts []string
	if iif := strings.TrimSpace(f.Interface); iif != "" {
		if !reIface.MatchString(iif) {
			return "", fmt.Errorf("interface inválida: %q", iif)
		}
		parts = append(parts, fmt.Sprintf("iifname %q", iif))
	}
	parts = append(parts,
		fmt.Sprintf("%s dport %d", proto, f.ExtPort),
		fmt.Sprintf("dnat ip to %s:%d", f.DestIP, f.DestPort),
	)
	return strings.Join(parts, " "), nil
}

// ─── User rules (custom allow/block, ordered, edited via modal) ──────────────

// UserChain is the admin-managed chain (evaluated from `forward`).
const UserChain = "user_rules"

// RuleFields is the structured, UX-friendly description of a custom rule. The
// admin fills these in a modal; the spec is built server-side so they never see
// raw nft syntax.
type RuleFields struct {
	Action string `json:"action"` // accept | drop | reject
	Iif    string `json:"iif"`    // input interface
	Oif    string `json:"oif"`    // output interface
	Saddr  string `json:"saddr"`  // source IP/CIDR
	Daddr  string `json:"daddr"`  // destination IP/CIDR
	Proto  string `json:"proto"`  // tcp | udp | icmp | ""
	Dport  string `json:"dport"`  // destination port (tcp/udp)
}

// UserRule is a stored custom rule with its nft handle (stable id) and the
// parsed fields so the modal can pre-fill on edit.
type UserRule struct {
	Handle int    `json:"handle"`
	Raw    string `json:"raw"`
	RuleFields
}

var (
	reHandle  = regexp.MustCompile(`# handle (\d+)`)
	reCounter = regexp.MustCompile(`counter packets \d+ bytes \d+`)
)

// ListUserRules returns the custom rules in order, with handles and fields.
func (s *Service) ListUserRules(ctx context.Context) ([]UserRule, error) {
	out, err := s.exec.ExecuteRead(ctx, "nft", "-a", "list", "chain", Family, Table, UserChain)
	if err != nil {
		return nil, err
	}
	rules := []UserRule{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		// Skip the chain header (`chain user_rules { # handle N`) and any block
		// delimiters — only actual rule lines carry a handle here.
		if strings.HasPrefix(line, "chain ") || strings.Contains(line, "{") || strings.HasPrefix(line, "}") {
			continue
		}
		m := reHandle.FindStringSubmatch(line)
		if m == nil {
			continue // not a rule line
		}
		handle, _ := strconv.Atoi(m[1])
		clean := reHandle.ReplaceAllString(line, "")
		clean = reCounter.ReplaceAllString(clean, "")
		clean = strings.Join(strings.Fields(clean), " ")
		rules = append(rules, UserRule{Handle: handle, Raw: clean, RuleFields: parseRuleFields(clean)})
	}
	return rules, nil
}

// AddUserRule appends (or inserts before beforeHandle) a custom rule.
func (s *Service) AddUserRule(ctx context.Context, f RuleFields, beforeHandle int) (string, error) {
	tokens, err := buildRuleTokens(f)
	if err != nil {
		return "", err
	}
	out, err := s.addRule(ctx, tokens, beforeHandle)
	if err != nil {
		return out, err
	}
	return out, s.Persist(ctx)
}

// UpdateUserRule replaces a rule (by handle) with new fields, keeping its position.
func (s *Service) UpdateUserRule(ctx context.Context, handle int, f RuleFields) (string, error) {
	rules, err := s.ListUserRules(ctx)
	if err != nil {
		return "", err
	}
	before := 0 // the rule that follows the one being edited (to keep position)
	for i, r := range rules {
		if r.Handle == handle && i+1 < len(rules) {
			before = rules[i+1].Handle
		}
	}
	tokens, err := buildRuleTokens(f)
	if err != nil {
		return "", err
	}
	if _, err := s.delRule(ctx, handle); err != nil {
		return "", err
	}
	if _, err := s.addRule(ctx, tokens, before); err != nil {
		return "", err
	}
	return "", s.Persist(ctx)
}

// DeleteUserRule removes a custom rule by handle.
func (s *Service) DeleteUserRule(ctx context.Context, handle int) (string, error) {
	if _, err := s.delRule(ctx, handle); err != nil {
		return "", err
	}
	return "", s.Persist(ctx)
}

// MoveUserRule reorders a rule up or down by one position.
func (s *Service) MoveUserRule(ctx context.Context, handle int, dir string) error {
	rules, err := s.ListUserRules(ctx)
	if err != nil {
		return err
	}
	idx := -1
	for i, r := range rules {
		if r.Handle == handle {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("rule not found")
	}

	switch dir {
	case "up":
		if idx == 0 {
			return nil
		}
		pred := rules[idx-1]
		moved := rules[idx]
		tokens, _ := buildRuleTokens(moved.RuleFields)
		if _, err := s.delRule(ctx, moved.Handle); err != nil {
			return err
		}
		if _, err := s.addRule(ctx, tokens, pred.Handle); err != nil {
			return err
		}
	case "down":
		if idx >= len(rules)-1 {
			return nil
		}
		// Move the successor up above this rule (reuses insert-before).
		succ := rules[idx+1]
		tokens, _ := buildRuleTokens(succ.RuleFields)
		if _, err := s.delRule(ctx, succ.Handle); err != nil {
			return err
		}
		if _, err := s.addRule(ctx, tokens, handle); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid direction")
	}
	return s.Persist(ctx)
}

func (s *Service) addRule(ctx context.Context, tokens []string, beforeHandle int) (string, error) {
	args := []string{}
	if beforeHandle > 0 {
		args = append(args, "insert", "rule", Family, Table, UserChain, "position", strconv.Itoa(beforeHandle))
	} else {
		args = append(args, "add", "rule", Family, Table, UserChain)
	}
	args = append(args, tokens...)
	return s.exec.Execute(ctx, "nft", args...)
}

func (s *Service) delRule(ctx context.Context, handle int) (string, error) {
	return s.exec.Execute(ctx, "nft", "delete", "rule", Family, Table, UserChain, "handle", strconv.Itoa(handle))
}

// buildRuleTokens turns structured fields into nft rule tokens (validated).
// Input validators. nft parses its argv joined by spaces, so an unvalidated
// token containing spaces/";" could inject extra nft commands (e.g. flush
// ruleset). Every user-supplied token below is constrained to a safe charset.
var (
	reIface = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,15}$`)
	reMark  = regexp.MustCompile(`^(0x[0-9a-fA-F]{1,8}|[0-9]{1,10})$`)
	rePort  = regexp.MustCompile(`^[0-9]{1,5}(-[0-9]{1,5})?$`)
)

// ValidMark reports whether a fwmark string is a plain hex/decimal number.
func ValidMark(s string) bool { return reMark.MatchString(strings.TrimSpace(s)) }

func validIPOrCIDR(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// validIPv4OrCIDR is validIPOrCIDR narrowed to what `ip saddr`/`ip daddr`
// actually match. Those tokens are IPv4-only even inside the `inet` family
// (IPv6 needs the separate `ip6 saddr`/`ip6 daddr` keywords, which this
// package never emits) — but net.ParseIP/net.ParseCIDR happily accept an
// IPv6 literal or CIDR, so validIPOrCIDR alone let one straight into the nft
// argv (C-1). At that point nft rejects the rule outright, and — before the
// rest of C-1's fix — that single bad row used to truncate every rule after
// it in the chain, permanently (the same bad DB row re-renders and re-fails
// on every subsequent boot). Rejecting here, before the value ever reaches
// buildRuleTokens' caller, is cheaper and gives the admin an immediate,
// specific reason instead of a a later nft failure.
func validIPv4OrCIDR(s string) bool {
	if ip := net.ParseIP(s); ip != nil {
		return ip.To4() != nil
	}
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return false
	}
	return ipnet.IP.To4() != nil
}

// validPort reports whether s is a single TCP/UDP port or a range, both
// ends within the protocol's actual 1-65535 range, and — for a range — the
// start no greater than the end. rePort's charset check alone accepted
// `99999` (five digits, but out of range) and inverted ranges like
// `8080-80`, both of which nft rejects at rule-add time; by then (before
// this fix) the whole chain had already been flushed, so nft's rejection
// truncated everything after that rule (C-1). Every one of these is
// reachable with ordinary typing into the rule modal, not just a
// hand-crafted API request.
func validPort(s string) bool {
	if !rePort.MatchString(s) {
		return false
	}
	parts := strings.SplitN(s, "-", 2)
	start, err := strconv.Atoi(parts[0])
	if err != nil || start < 1 || start > 65535 {
		return false
	}
	if len(parts) == 1 {
		return true
	}
	end, err := strconv.Atoi(parts[1])
	if err != nil || end < 1 || end > 65535 {
		return false
	}
	return start <= end
}

func buildRuleTokens(f RuleFields) ([]string, error) {
	action := strings.ToLower(strings.TrimSpace(f.Action))
	if action != "accept" && action != "drop" && action != "reject" {
		return nil, fmt.Errorf("ação inválida (use accept, drop ou reject)")
	}
	var t []string
	if f.Iif != "" {
		if !reIface.MatchString(f.Iif) {
			return nil, fmt.Errorf("interface de entrada inválida")
		}
		t = append(t, "iifname", f.Iif)
	}
	if f.Oif != "" {
		if !reIface.MatchString(f.Oif) {
			return nil, fmt.Errorf("interface de saída inválida")
		}
		t = append(t, "oifname", f.Oif)
	}
	if f.Saddr != "" {
		if !validIPv4OrCIDR(f.Saddr) {
			return nil, fmt.Errorf("origem inválida: use um IP/CIDR IPv4 (IPv6 ainda não é suportado nas regras personalizadas)")
		}
		t = append(t, "ip", "saddr", f.Saddr)
	}
	if f.Daddr != "" {
		if !validIPv4OrCIDR(f.Daddr) {
			return nil, fmt.Errorf("destino inválido: use um IP/CIDR IPv4 (IPv6 ainda não é suportado nas regras personalizadas)")
		}
		t = append(t, "ip", "daddr", f.Daddr)
	}
	proto := strings.ToLower(strings.TrimSpace(f.Proto))
	switch proto {
	case "tcp", "udp":
		if f.Dport != "" {
			if !validPort(f.Dport) {
				return nil, fmt.Errorf("porta inválida: use um valor entre 1 e 65535, ou um intervalo início-fim válido (ex.: 8000-8080)")
			}
			t = append(t, proto, "dport", f.Dport)
		} else {
			t = append(t, "ip", "protocol", proto)
		}
	case "icmp":
		t = append(t, "ip", "protocol", "icmp")
	case "", "all", "any":
		// no L4 match
	default:
		return nil, fmt.Errorf("protocolo inválido")
	}
	t = append(t, "counter", action)
	return t, nil
}

// parseRuleFields best-effort parses our generated rule text back into fields
// (so the edit modal can pre-fill). Unknown tokens are ignored.
func parseRuleFields(clean string) RuleFields {
	f := RuleFields{}
	toks := strings.Fields(clean)
	unq := func(s string) string { return strings.Trim(s, `"`) }
	for i := 0; i < len(toks); i++ {
		switch toks[i] {
		case "iif", "iifname":
			if i+1 < len(toks) {
				f.Iif = unq(toks[i+1])
				i++
			}
		case "oif", "oifname":
			if i+1 < len(toks) {
				f.Oif = unq(toks[i+1])
				i++
			}
		case "ip":
			if i+2 < len(toks) {
				switch toks[i+1] {
				case "saddr":
					f.Saddr = toks[i+2]
				case "daddr":
					f.Daddr = toks[i+2]
				case "protocol":
					f.Proto = toks[i+2]
				}
				i += 2
			}
		case "tcp", "udp":
			f.Proto = toks[i]
			if i+2 < len(toks) && toks[i+1] == "dport" {
				f.Dport = toks[i+2]
				i += 2
			}
		case "accept", "drop", "reject":
			f.Action = toks[i]
		}
	}
	return f
}

// parseElements extracts the comma-separated tokens inside an `elements = { ... }`
// block from `nft list set/map` output (the block may span multiple lines).
func parseElements(out string) []string {
	res := []string{}
	i := strings.Index(out, "elements = {")
	if i < 0 {
		return res
	}
	rest := out[i+len("elements = {"):]
	j := strings.Index(rest, "}")
	if j < 0 {
		return res
	}
	for _, tok := range strings.Split(rest[:j], ",") {
		t := strings.Join(strings.Fields(tok), " ")
		if t != "" {
			res = append(res, t)
		}
	}
	return res
}

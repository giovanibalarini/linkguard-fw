package nftables

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sort"
	"strings"
)

// masqueradeChain is the chain whose sole content is the WAN masquerade
// rule (verified against the live production ruleset: nothing else is ever
// written there — port forwards live in prerouting_dnat, filtering in
// forward/user_rules). That is what makes flush-then-rewrite safe here.
const masqueradeChain = "postrouting"

// ReconcileMasquerade re-derives the WAN masquerade (NAT) rule from the
// currently configured WAN interfaces, on every boot and on every link
// mutation — not just once at bootstrap.
//
// Why this exists: EnsureTable only creates `table inet linkguard` when it
// is missing, so on an already-provisioned box it is a no-op and the
// masquerade rule keeps whatever interface names it was born with. In
// production on 2026-08-10 a NIC was renamed by a PCI reshuffle
// (enp4s0 -> enp5s0) and the stale rule silently stopped matching, taking
// WAN1's NAT down until an operator added an iptables rule by hand.
//
// It flushes the chain before writing because `nft -f` (and `nft add`)
// ACCUMULATE rules rather than replacing them — the same production ruleset
// ended up with two masquerade lines, one of them referencing an interface
// that no longer existed. Flushing only this chain (never the table or the
// ruleset) keeps host_wan / blocklist / blocked_hosts / user_rules /
// prerouting_dnat untouched.
//
// Idempotent by construction: the same WAN set always yields the same two
// commands and the same final chain contents. A no-op in dry-run mode, same
// convention as the rest of the package.
func (s *Service) ReconcileMasquerade(ctx context.Context, wanInterfaces []string) error {
	if s.exec.IsDryRun() {
		return nil
	}
	ifaces := sanitizeInterfaces(wanInterfaces)

	if len(ifaces) == 0 {
		// No configured WANs (all disabled, last one deleted, or a box using
		// LinkGuard for firewall/hosts but no links): refuse to touch the
		// chain at all. Flushing here would take down whatever masquerade
		// rule is currently live and working, and since Persist is skipped
		// in this branch too, /etc/nftables.conf would silently diverge
		// from the (now empty) live chain. Acting on an empty source of
		// truth is strictly less safe than doing nothing, so we do nothing.
		slog.Warn("nenhuma interface WAN válida configurada; regra de NAT existente foi mantida intacta", "requested", wanInterfaces)
		return nil
	}

	if _, err := s.exec.Execute(ctx, "nft", "flush", "chain", Family, Table, masqueradeChain); err != nil {
		return fmt.Errorf("limpar chain %s: %w", masqueradeChain, err)
	}

	quoted := make([]string, len(ifaces))
	for i, iface := range ifaces {
		quoted[i] = fmt.Sprintf("%q", iface)
	}
	set := fmt.Sprintf("{ %s }", strings.Join(quoted, ", "))
	if _, err := s.exec.Execute(ctx, "nft", "add", "rule", Family, Table, masqueradeChain,
		"oifname", set, "masquerade"); err != nil {
		return fmt.Errorf("aplicar regra de masquerade: %w", err)
	}

	slog.Info("regra de NAT reconciliada a partir das WANs configuradas", "interfaces", ifaces)

	if err := s.Persist(ctx); err != nil {
		slog.Warn("regra de NAT reconciliada, mas não foi possível persistir para o próximo boot", "err", err)
	}
	return nil
}

// InputChain is the first `hook input` chain this project has ever created
// (added 2026-08-11 for "serve NTP to the LAN" — see
// docs/superpowers/specs/2026-08-11-ntp-server-for-lan-design.md §2). Before
// it, nothing filtered traffic destined for the firewall itself (SSH, the
// web panel, DNS, DHCP) — the table only had prerouting/forward/postrouting
// hooks.
//
// Non-negotiable: this chain is declared, created and reconciled with
// `policy accept` and must never become `policy drop`. A drop policy would
// cut SSH and the panel the instant it applied, on a firewall that may have
// no other admin access. Protection here is via a specific deny rule, not a
// restrictive default policy — hardening the policy is a separate project
// with its own port inventory and maintenance window (spec §8).
const InputChain = "input"

// sanitizeNetworks validates admin-supplied CIDRs before they reach an nft
// argv, mirroring sanitizeInterfaces' treatment of interface names — an
// admin-controlled string is exactly as dangerous here as an interface name
// is elsewhere in this package. An entry is dropped (not fatal to the whole
// reconcile) when it fails net.ParseCIDR, is a duplicate, is the open
// wildcard (0.0.0.0/0 or ::/0, checked by mask size so any equivalent
// spelling is caught), or is IPv6.
//
// IPv6 is rejected here too, independent of the handler-level
// timesync.ValidateAllowedNetworks that is the primary gate: the rule this
// function builds is `ip saddr { … }`, which in the `inet` family only ever
// matches IPv4 — nft errors out on an IPv6 prefix there. Before this guard
// existed, an IPv6 entry reaching ReconcileNTPInput made the accept-rule nft
// command itself fail, which returned an error *after* the chain had
// already been flushed and *before* the drop rule was added — an empty,
// unprotected input chain, silently. Dropping the bad entry here instead
// keeps the reconcile succeeding and every valid IPv4 entry still
// protected, the same "one bad entry doesn't sink the good ones" contract
// already applied to the wildcard and to plain garbage.
//
// A survivor is rewritten to ipnet.String() — its canonical network form —
// rather than passed through as typed, so a non-canonical prefix like
// "192.168.3.5/24" (host bits set, which net.ParseCIDR accepts and masks)
// ends up in the nft saddr set as exactly the same bytes as everywhere else
// this value is used (persisted config, chrony's `allow` line). This is
// defense in depth: the API handler already normalizes on save (see
// timesync.NormalizeAllowedNetworks), but this function must hold the same
// property on its own for any value that reached it another way (an old DB
// row saved before normalization existed, for instance).
func sanitizeNetworks(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, cidr := range in {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" || seen[cidr] {
			continue
		}
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ones, _ := ipnet.Mask.Size(); ones == 0 {
			continue
		}
		if ipnet.IP.To4() == nil {
			slog.Warn("rede IPv6 ignorada na chain de proteção do NTP (ainda não suportada; ip saddr só casa IPv4 na família inet)", "network", cidr)
			continue
		}
		seen[cidr] = true
		out = append(out, ipnet.String())
	}
	return out
}

// ReconcileNTPInput rebuilds the input chain's NTP-protection rules from the
// serve-NTP-to-LAN toggle and the admin's own choice of allowed networks
// (internal/timesync.Config.AllowedNetworks, spec §3.1), mirroring
// ReconcileMasquerade's structure and safety properties: it flushes only
// this chain (never the table or the ruleset), validates every CIDR before
// it reaches nft, is a no-op in dry-run, and persists afterward.
//
// Reshaped 2026-08-11 (spec §4) from an earlier, narrower design that denied
// NTP by WAN interface: allowedNetworks replaces wanInterfaces because the
// admin — not the software — decides which networks may use the time
// service, and a deny-by-WAN rule would silently let an unauthorized VLAN
// or guest network straight through since neither is a WAN.
//
// Unlike the masquerade chain (always present since bootstrap), the input
// chain may not exist yet on a box provisioned before this feature — so it
// is created first via an idempotent `nft add chain ... { type filter hook
// input priority filter; policy accept; }`, which nft treats as a no-op
// when a base chain with the same declaration already exists (the same
// convention already in production for DNATChain, see ApplyPortForwards).
//
// When serving is true and at least one network survives sanitization, the
// chain ends up with exactly two rules, in this order — order matters, nft
// evaluates top to bottom, and a drop before the accept would shadow it:
//
//	udp dport 123 ip saddr { <cidr>, ... } accept
//	udp dport 123 drop
//
// Defense in depth alongside chrony's own `allow` directives — see spec §4,
// "why this matters even with chrony's allow". Both rules match only
// udp/123; nothing else destined to the firewall (SSH, the panel, DNS,
// DHCP) is ever touched. When serving is false, or the network list is
// empty after sanitization, the chain is flushed and left empty — not
// deleted — so its state is always explicit and idempotent.
// ForwardChain evaluates the managed blocklist/host-block drops and then
// jumps into each enabled rule group, in the admin's order (a partir da Fase
// C1 — ver forwardChainRules para por que os bloqueios vêm primeiro).
// MarkHostsChain steers a host's forwarded traffic to a specific WAN by
// fwmark, looked up from the host_wan map. Both are structural — created
// once at EnsureTable/bootstrap — and reconciled on every boot exactly like
// postrouting/input: mark_hosts por ReconcileStructuralChains, forward por
// ReconcileGroups.
const (
	ForwardChain   = "forward"
	MarkHostsChain = "mark_hosts"
)

// forwardChainRules é o conteúdo canônico e ordenado da chain forward.
// Ordem importa — o nft avalia de cima para baixo:
//
//  1. Os bloqueios administrativos (host bloqueado, destino bloqueado)
//     vêm PRIMEIRO e vencem qualquer regra do admin. Até a Fase B era o
//     contrário: um "permitir" do usuário anulava a lista de bloqueio, o
//     que fazia o botão "bloquear host em 1 clique" mentir. Se o bloqueio
//     não vence, ele não é bloqueio (design spec §3).
//  2. Depois, um jump por grupo ativado, na ordem que o admin configurou.
//     A condição de entrada do grupo vai na própria linha do jump: se ela
//     não casa, o grupo inteiro é pulado sem o kernel olhar as regras de
//     dentro.
//
// Toda linha carrega `counter`: ver ReconcileStructuralChains sobre por que
// isso não é negociável.
//
// A chain user_rules deixou de ser alcançada daqui: as regras do admin agora
// moram dentro de um grupo (a migração única leva as antigas para o grupo
// "Minhas regras"), e um jump para uma chain que não é mais a fonte da
// verdade só poderia divergir dela.
func forwardChainRules(groups []StoredGroup) [][]string {
	rules := [][]string{
		{"ip", "saddr", "@" + BlockedSet, "counter", "drop"},
		{"ip", "daddr", "@" + BlockedSet, "counter", "drop"},
		{"ip", "daddr", "@blocklist", "counter", "drop"},
		{"ip", "saddr", "@blocklist", "counter", "drop"},
	}

	sorted := make([]StoredGroup, len(groups))
	copy(sorted, groups)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Position < sorted[j].Position })

	for _, g := range sorted {
		if !g.Enabled {
			continue // desligar = tirar o jump; a chain e as regras continuam guardadas
		}
		if !validGroupChainName(g.ChainName) {
			// Não é paranoia redundante: este nome sai do banco e é
			// interpolado no argv do nft, que junta os argumentos e parseia
			// o resultado — a mesma porta que reIface/ValidMark fecham nos
			// outros geradores deste pacote.
			slog.Error("grupo ignorado ao montar a chain forward: nome de chain inseguro",
				"grupo", g.ID, "nome", g.Name, "chain", g.ChainName)
			continue
		}
		tokens, err := groupJumpTokens(g)
		if err != nil {
			slog.Error("grupo ignorado ao montar a chain forward: condição inválida",
				"grupo", g.ID, "nome", g.Name, "err", err)
			continue
		}
		rules = append(rules, tokens)
	}
	return rules
}

// markHostsChainRules is the canonical rule set for mark_hosts — a single
// rule, also carrying `counter`.
func markHostsChainRules() [][]string {
	return [][]string{
		{"counter", "meta", "mark", "set", "ip", "saddr", "map", "@" + HostWanMap},
	}
}

// ReconcileStructuralChains rebuilds the mark_hosts chain from its canonical
// definition above, on every boot — not just once at EnsureTable/bootstrap
// time — mirroring ReconcileMasquerade's safety properties exactly: the
// chain is flushed on its own (never the table or the ruleset), the result
// is idempotent, it's a no-op in dry-run, and it persists afterward.
//
// A forward saiu daqui (grupos de regras, Fase C1): ela agora depende dos
// grupos do admin e é reconstruída por ReconcileGroups, que é quem os
// conhece. Reconciliar as duas em lugares diferentes faria a última a rodar
// apagar os jumps da outra — quem chama esta função no boot tem que chamar
// ReconcileGroups também, senão a forward deixa de ser reconciliada.
//
// Why this exists (design spec §1/§6): unlike postrouting/input, these two
// chains were, until now, only ever created once at bootstrap and never
// touched again — the exact gap that let a double-load of the ruleset
// (2026-08-10 incident: the same file applied twice) leave every rule in
// both chains permanently duplicated. Duplicates survived every reboot
// because Persist snapshots whatever is live, and nothing ever flushed
// these two chains again to clear the second copy. Reconciling on every
// boot closes that gap the same way it was already closed for masquerade
// and the NTP input rules: a duplicate cannot outlive the next restart.
//
// Every rule in every canonical definition here — e em forwardChainRules,
// que hoje mora em ReconcileGroups — carries `counter`. Production's
// forward-chain drop rules were hand-created in June 2026 already WITH
// counters (the whole reason Phase A exists is to surface those counts on
// the panel) — reconciling to a counter-less definition would flush the
// chain and rebuild it from scratch every boot, silently resetting that
// data to zero each time. mark_hosts never had a counter in production
// (nothing reconciled it before this); this is what starts counting it,
// on the same schedule as everything else from now on.
func (s *Service) ReconcileStructuralChains(ctx context.Context) error {
	if s.exec.IsDryRun() {
		return nil
	}

	if err := s.rebuildChain(ctx, MarkHostsChain, markHostsChainRules()); err != nil {
		return err
	}

	slog.Info("chains estruturais reconciliadas a partir da definição canônica", "chains", []string{MarkHostsChain})

	if err := s.Persist(ctx); err != nil {
		slog.Warn("chains estruturais reconciliadas, mas não foi possível persistir para o próximo boot", "err", err)
	}
	return nil
}

// rebuildChain flushes exactly the named chain and re-adds each rule from
// the given canonical token lists, in order. Shared by
// ReconcileStructuralChains' two chains and ReconcileUserRules so the
// flush-then-rewrite sequence can't drift between them.
//
// C-1 (fix): a flush failure still aborts immediately — nothing can safely
// proceed without knowing the chain is actually empty first. But a failure
// adding one specific rule no longer aborts the rest: before this fix, the
// very first `nft add rule` error returned immediately, leaving the chain
// flushed but only partially rebuilt — every rule after the failing one
// silently disappeared from the live firewall, on this call and (since the
// same bad row keeps being re-rendered) on every subsequent boot too. A
// rule nft rejects for a reason field-level validation cannot catch (nft's
// own semantic checks go further than buildRuleTokens' regexes) must not be
// able to take the rest of the chain down with it: skip it, log it loudly,
// keep going, and report every failure back to the caller as one aggregate
// error so it can be surfaced (400 with nft's message, an alert, a boot-log
// warning) — a partial firewall with the other rules intact is strictly
// safer than an empty one.
func (s *Service) rebuildChain(ctx context.Context, chain string, rules [][]string) error {
	if _, err := s.exec.Execute(ctx, "nft", "flush", "chain", Family, Table, chain); err != nil {
		return fmt.Errorf("limpar chain %s: %w", chain, err)
	}
	var failures []string
	for _, tokens := range rules {
		args := append([]string{"add", "rule", Family, Table, chain}, tokens...)
		if _, err := s.exec.Execute(ctx, "nft", args...); err != nil {
			expr := strings.Join(tokens, " ")
			slog.Error("nft rejeitou uma regra ao reconciliar a chain; as demais continuam sendo aplicadas",
				"chain", chain, "regra", expr, "err", err)
			failures = append(failures, fmt.Sprintf("%q: %v", expr, err))
			continue
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("%d regra(s) rejeitada(s) pelo nft em %s (as demais foram aplicadas normalmente): %s",
			len(failures), chain, strings.Join(failures, "; "))
	}
	return nil
}

// renderChainScript renders the exact sequence of commands rebuildChain
// would execute against chain — flush, then each rule in tokenSets, in
// order — as an nft script body, for CheckChain's parse-only dry run.
func renderChainScript(chain string, tokenSets [][]string) string {
	return renderChainScriptEnsuring(chain, tokenSets, nil)
}

// renderChainScriptEnsuring is renderChainScript plus one `add chain` line
// per name in ensure, emitted BEFORE the flush and before any rule — the
// only form of pre-flight that works for a chain that does not exist yet.
//
// Why it is needed (verified live against nft on Debian 13): inside a script
// handed to `nft -c -f`, both `flush chain … grp_novo` and `add rule …
// jump grp_novo` fail with "No such file or directory" when grp_novo isn't
// in the live ruleset — and the group pre-flight runs BEFORE the DB insert,
// so a brand-new group's chain never is. Prefixing the script with `add
// chain` makes the whole thing parse clean, and `nft -c` still creates
// nothing: it is a dry run, the chain is not materialised. `add chain` is
// idempotent, so a group that already exists is unaffected.
//
// ensure is only ever fed chain names the caller has already validated
// (CheckGroups rejects anything outside validGroupChainName before getting
// here) — this text goes to nft, exactly like an argv would.
func renderChainScriptEnsuring(chain string, tokenSets [][]string, ensure []string) string {
	var b strings.Builder
	for _, name := range ensure {
		fmt.Fprintf(&b, "add chain %s %s %s\n", Family, Table, name)
	}
	fmt.Fprintf(&b, "flush chain %s %s %s\n", Family, Table, chain)
	for _, tokens := range tokenSets {
		fmt.Fprintf(&b, "add rule %s %s %s %s\n", Family, Table, chain, strings.Join(tokens, " "))
	}
	return b.String()
}

// CheckChain performs a parse-only dry run (`nft -c -f`) of exactly the
// script rebuildChain would execute against chain, without changing
// anything live — nft's own `--check` flag validates syntax and semantics
// against the current ruleset and discards the result. Deliberately generic
// (any chain, any token sets) rather than user_rules-specific: this is the
// mechanism C-1 introduces for the rule-editor pre-flight (see
// internal/firewallrules.Service.CheckPending), and the design spec picks
// the same `nft -c` approach for Phase C's own admin-facing dry run — a
// second, chain-specific implementation there would only risk drifting from
// this one.
func (s *Service) CheckChain(ctx context.Context, chain string, tokenSets [][]string) error {
	return s.CheckChainEnsuring(ctx, chain, tokenSets, nil)
}

// CheckChainEnsuring is CheckChain for a script that references chains which
// may not exist in the live ruleset yet — the rule-group pre-flight, which
// by contract runs before the group's row is written (and therefore before
// its chain is ever created). Each name in ensure gets an idempotent `add
// chain` at the top of the validated script; see renderChainScriptEnsuring
// for why nothing less works and why `nft -c` still changes nothing.
//
// Kept separate from CheckChain so the chains that have existed since
// bootstrap (user_rules, forward) keep validating the byte-for-byte script
// they validate in production today.
func (s *Service) CheckChainEnsuring(ctx context.Context, chain string, tokenSets [][]string, ensure []string) error {
	if s.exec.IsDryRun() {
		return nil
	}
	f, err := os.CreateTemp("", "linkguard-nft-check-*.conf")
	if err != nil {
		return fmt.Errorf("criar arquivo temporário para validação: %w", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(renderChainScriptEnsuring(chain, tokenSets, ensure)); err != nil {
		f.Close()
		return fmt.Errorf("escrever script de validação: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("fechar arquivo temporário de validação: %w", err)
	}
	if _, err := s.exec.ExecuteRead(ctx, "nft", "-c", "-f", f.Name()); err != nil {
		return err
	}
	return nil
}

func (s *Service) ReconcileNTPInput(ctx context.Context, allowedNetworks []string, serving bool) error {
	if s.exec.IsDryRun() {
		return nil
	}

	if _, err := s.exec.Execute(ctx, "nft", "add", "chain", Family, Table, InputChain,
		"{", "type", "filter", "hook", "input", "priority", "filter", ";", "policy", "accept", ";", "}"); err != nil {
		return fmt.Errorf("criar chain %s: %w", InputChain, err)
	}

	if _, err := s.exec.Execute(ctx, "nft", "flush", "chain", Family, Table, InputChain); err != nil {
		return fmt.Errorf("limpar chain %s: %w", InputChain, err)
	}

	networks := sanitizeNetworks(allowedNetworks)
	if serving {
		if len(networks) == 0 {
			slog.Warn("servir NTP para a LAN está ligado, mas nenhuma rede autorizada válida está configurada; chain de proteção ficou vazia", "requested", allowedNetworks)
		} else {
			set := fmt.Sprintf("{ %s }", strings.Join(networks, ", "))
			if _, err := s.exec.Execute(ctx, "nft", "add", "rule", Family, Table, InputChain,
				"udp", "dport", "123", "ip", "saddr", set, "accept"); err != nil {
				return fmt.Errorf("aplicar regra de aceite do NTP: %w", err)
			}
			if _, err := s.exec.Execute(ctx, "nft", "add", "rule", Family, Table, InputChain,
				"udp", "dport", "123", "drop"); err != nil {
				return fmt.Errorf("aplicar regra de proteção do NTP: %w", err)
			}
		}
	}

	slog.Info("chain de proteção do NTP (input) reconciliada", "serving", serving, "allowed_networks", networks)

	if err := s.Persist(ctx); err != nil {
		slog.Warn("chain de input reconciliada, mas não foi possível persistir para o próximo boot", "err", err)
	}
	return nil
}

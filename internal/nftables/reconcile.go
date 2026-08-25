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

// ForwardChain is rendered from a single ordered list — the admin's own —
// where each item is either a jump into a rule group or the managed
// blocklist/host-block drops, in the position the admin chose (see
// forwardChainRules; blocks first is the migration's default, not a code
// invariant). MarkHostsChain
// steers a host's forwarded traffic to a specific WAN by fwmark, looked up
// from the host_wan map. Both are structural — created once at
// EnsureTable/bootstrap — and reconciled on every boot exactly like
// postrouting/input: mark_hosts by ReconcileStructuralChains, forward by
// ReconcileGroups.
const (
	ForwardChain   = "forward"
	MarkHostsChain = "mark_hosts"
)

// forwardChainRules rende a chain forward a partir de UMA lista ordenada —
// a mesma que o admin vê na tela, na mesma ordem. Antes desta mudança a
// ordem era fixa em código (os quatro bloqueios, depois os jumps); agora
// bloqueio é um item da lista como qualquer outro, e a posição dele é
// escolha do admin.
//
// Cada item vira uma coisa ou outra, nunca as duas:
//
//   - grupo do sistema (host bloqueado, destino bloqueado): as linhas de
//     `drop` do named set correspondente, lidas de systemGroupForwardRules
//     (groups.go) — a mesma fonte que IsSystemGroup consulta, para que os
//     dois nunca possam discordar sobre o que é um kind de sistema. Ele não
//     tem chain própria — o conteúdo dele é o set — e o chain_name reservado
//     (sys_…) nunca vai para o nft.
//   - grupo do admin: qualquer kind que não está em systemGroupForwardRules
//     (hoje, kind == "admin" ou vazio). Um `jump` para a chain dele. A
//     condição de entrada vai na própria linha do jump: se ela não casa, o
//     grupo inteiro é pulado sem o kernel olhar as regras de dentro.
//
// O padrão continua sendo bloqueios primeiro (é assim que a migração os cria,
// nas posições 0 e 1), e continua valendo a razão da §3 da design spec: um
// "permitir" do admin avaliado antes do bloqueio faz o botão "bloquear host
// em 1 clique" mentir. O que a Fase C1 eliminou foi a SURPRESA — uma regra
// antiga anulando um bloqueio sem ninguém ver, porque a ordem era invisível
// —, não a possibilidade. A ordem agora está na tela, numerada, e mover um
// bloqueio para baixo de um grupo é uma decisão explícita.
//
// ATENÇÃO — não existe mais nenhum bloqueio garantido por código aqui: uma
// lista sem os grupos do sistema rende uma forward sem `drop` nenhum. Quem
// chama é que não pode deixar isso acontecer, e não deixa:
// internal/firewallrules.Service.Reconcile aborta antes de emitir comando
// (ensureSystemGroupsPresent) quando os dois grupos não estão na lista.
//
// Toda linha carrega `counter`: ver ReconcileStructuralChains sobre por que
// isso não é negociável.
//
// A chain user_rules deixou de ser alcançada daqui: as regras do admin agora
// moram dentro de um grupo (a migração única leva as antigas para o grupo
// "Minhas regras"), e um jump para uma chain que não é mais a fonte da
// verdade só poderia divergir dela.
func forwardChainRules(groups []StoredGroup, logarBloqueios bool) [][]string {
	sorted := make([]StoredGroup, len(groups))
	copy(sorted, groups)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Position < sorted[j].Position })

	var rules [][]string
	for _, g := range sorted {
		if !g.Enabled {
			// Desligar = sumir do firewall. Para o grupo do admin, a chain e
			// as regras dele continuam guardadas no nft; para o do sistema, os
			// membros do set continuam guardados (o set não é tocado aqui).
			continue
		}
		if renderer, ok := systemGroupForwardRules[g.Kind]; ok {
			// Grupo do sistema é sempre forward, qualquer que seja a coluna
			// scope: o conteúdo dele é um named set de bloqueio de tráfego
			// ATRAVESSANDO o firewall. Uma linha com scope=input (edição à
			// mão, corrupção) que tirasse o bloqueio daqui apagaria da forward
			// a proteção que o admin ligou, sem parecer erro nenhum.
			rules = append(rules, renderer(logarBloqueios)...)
			continue
		}
		if GroupScope(g) != ScopeForward {
			// Grupo de escopo input: o jump dele mora na chain input
			// (inputChainRules). Emiti-lo aqui aplicaria as regras do admin a
			// um tráfego que ele não pediu para filtrar.
			continue
		}
		// grupo do admin
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
// The forward chain left this function with rule groups (Phase C1): it now
// depends on the admin's groups and is rebuilt by ReconcileGroups, the only
// place that knows them. Reconciling it in two places would make whichever
// ran last wipe the other's rules — so whoever calls this at boot must call
// ReconcileGroups too, or the forward stops being reconciled at all.
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
// Every rule in every canonical definition here — and in forwardChainRules,
// which now lives with ReconcileGroups — carries `counter`. Production's
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
	return s.rebuildChainIn(ctx, Table, chain, rules)
}

// rebuildChainIn é o mesmo flush-e-reescreve, numa tabela nomeada.
//
// Existe porque o registro de conversa da #115 vive numa TABELA PRÓPRIA
// (nftables.FlowsTable) — ver o topo de flows.go para a razão, que é o Persist
// não poder despejar aquele set no /etc/nftables.conf. Sem este parâmetro a
// feature nova teria de duplicar a sequência aqui, e é exatamente a duplicação
// que o comentário acima existe para impedir: as duas cópias divergiriam, e a
// que divergisse deixaria uma chain vazia num hook por onde passa todo o
// tráfego da LAN.
func (s *Service) rebuildChainIn(ctx context.Context, table, chain string, rules [][]string) error {
	if _, err := s.exec.Execute(ctx, "nft", "flush", "chain", Family, table, chain); err != nil {
		return fmt.Errorf("limpar chain %s: %w", chain, err)
	}
	var failures []string
	for _, tokens := range rules {
		args := append([]string{"add", "rule", Family, table, chain}, tokens...)
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

// inputChainRules é o renderizador ÚNICO da chain input (Fase C2), o mesmo
// molde que forwardChainRules já é para a forward: uma lista ordenada só,
// emitida de cima para baixo, com tudo que mora ali dentro.
//
// Por que ele existe: até a Fase C2 a chain input tinha um dono exclusivo —
// ReconcileNTPInput dava flush nela e escrevia só as regras de NTP. No
// momento em que um segundo escritor (os grupos de escopo input) passasse a
// escrever no mesmo lugar, um apagaria o outro: ligar o NTP sumiria com os
// grupos do admin, e salvar um grupo sumiria com a proteção do NTP — nos dois
// casos sem nada na tela mudar. Com um renderizador só, a chain é sempre
// reconstruída inteira, a partir de tudo que a compõe.
//
// A ordem não é arbitrária, e o nft avalia de cima para baixo:
//
//  1. `ct state related accept`, SEMPRE, incondicional (ver o bloco logo
//     abaixo).
//  2. as duas linhas de NTP (quando servir NTP está ligado e sobrou pelo
//     menos uma rede válida): o accept das redes autorizadas ANTES do drop
//     geral de udp/123 — invertido, o drop sombrearia o accept e ninguém
//     sincronizaria hora nenhuma. Defesa em profundidade junto do `allow` do
//     próprio chrony; as duas casam só udp/123, e nada mais destinado ao
//     firewall (SSH, painel, DNS, DHCP, Samba) é tocado por elas.
//  3. um `jump` por grupo de escopo input ativado, na ordem de posição — a
//     mesma que o admin vê na tela. A condição de entrada vai na própria
//     linha do jump: se não casa, o grupo inteiro é pulado sem o kernel olhar
//     as regras de dentro.
//
// As linhas de NTP vêm antes dos grupos por serem proteção do serviço de hora
// contra a internet, e não uma regra que o admin ordenou na lista dele.
// Quando a UI da Fase C2 puser os grupos de input na tela, a posição relativa
// deles continua sendo escolha do admin — entre eles.
//
// Por que `ct state related` no topo, e por que ele é a PRIMEIRA linha
// (armadilha de PMTUD):
//
// Um grupo de escopo input que bloqueie ICMP destinado ao firewall — coisa
// que todo manual de firewall da internet ainda manda fazer — quebra Path MTU
// Discovery em silêncio. O caminho até um destino tem um enlace com MTU menor
// (PPPoE, túnel, VPN); o roteador do meio devolve um ICMP tipo 3 código 4
// ("fragmentation needed"); o firewall descarta esse ICMP; e a origem nunca
// descobre que precisa mandar pacote menor. O sintoma é o clássico
// enlouquecedor: o SSH conecta, autentica, e trava no primeiro pacote grande.
// Nada aparece na tela, porque do ponto de vista do painel a regra do admin
// está aplicada e correta — ela está.
//
// `related` é exatamente a classe do conntrack para isso: um ICMP de erro
// cujo cabeçalho interno referencia um fluxo que o conntrack já conhece entra
// como RELATED. Medido contra o kernel 6.12 numa topologia PMTUD real
// (cliente 1500 → roteador → enlace 1280): com esta linha, o frag-needed é
// aceito e o cliente aprende MTU 1280; sem ela, 8 frag-needed são descartados
// pelo grupo e o PMTU nunca é aprendido.
//
// É `related` E SÓ `related` — NUNCA `established`, e isso é decisão tomada,
// não descuido. A Fase C2 tem uma janela de confirmação de 90 segundos em que
// o operador aplica uma regra que pode trancá-lo para fora e precisa testar
// se ainda tem acesso antes de confirmar. Com `established accept`, a sessão
// SSH dele sobreviveria ao próprio bloqueio: ele testaria, veria tudo
// funcionando, confirmaria — e descobriria o bloqueio na próxima reconexão,
// sem rede nenhuma embaixo. O teste passaria a mentir. `related` não tem esse
// efeito: ele não carrega nenhuma sessão já aberta, só os erros ICMP
// associados a conexões que o conntrack já conhece.
//
// Ela vem ANTES das linhas de NTP, e isso não abre buraco na proteção do NTP
// que já está em produção — medido, não presumido:
//
//   - `udp dport 123` compila para `meta l4proto == 17` + comparação de
//     payload (conferido com `nft --debug=netlink`). Um ICMP de erro tem
//     l4proto 1, então nunca casou com as duas linhas de NTP: elas não
//     perdem para esta linha nada que já pegassem.
//   - para um pacote udp/123 de verdade cair em `related` seria preciso uma
//     expectation do conntrack para aquela tupla, e só um helper cria
//     expectation. Nenhum helper do kernel registra porta 123, o LinkGuard
//     nunca emite `ct helper set`, e desde o kernel 6.0 o sysctl
//     nf_conntrack_helper não existe mais — o auto-assign de helper foi
//     removido, então helper só entra em jogo se alguém pedir explicitamente.
//   - medido em namespace isolado: 5 pacotes udp/123 de origem NÃO
//     autorizada com esta linha no topo → contador do `related` em 0,
//     contador do drop de NTP em 5. A proteção segue intacta.
//
// Toda linha carrega `counter`: mesma razão de ReconcileStructuralChains e de
// forwardChainRules — é o número que o painel mostra, e uma definição
// canônica sem counter faria cada boot zerar a contagem em silêncio.
//
// Grupo do sistema nunca entra aqui: o conteúdo dele é um named set de
// bloqueio de tráfego atravessando, e o lugar dele é a forward.
func inputChainRules(groups []StoredGroup, ntpNetworks []string, ntpServing bool, policy Policy, access AdminAccess, wanIfaces []string, gerenciaFechada, contencao bool) [][]string {
	// Incondicional: sem toggle, sem depender de grupo nenhum. Um firewall
	// que só quebra PMTUD depois que o admin cria o grupo errado é um
	// firewall que guarda a armadilha armada esperando.
	rules := [][]string{{"ct", "state", "related", "counter", "accept"}}

	// AS REGRAS DE SOBREVIVÊNCIA SÓ ENTRAM COM POLÍTICA RESTRITIVA, e a
	// condição é a parte importante desta função.
	//
	// Com `policy accept` elas seriam inócuas em teoria e nocivas na prática:
	// entram ACIMA dos jumps dos grupos, então um admin com um grupo de escopo
	// input bloqueando DNS de uma VLAN teria esse bloqueio anulado em silêncio
	// por um accept nosso. Seria o produto afrouxando o firewall de quem já o
	// usa, para preparar um recurso que ele talvez nunca ligue.
	//
	// Com `policy drop` elas são o que separa "bloquear tudo" de "eu me tranquei
	// fora": sem elas, a política corta SSH e painel no instante em que é
	// aplicada. Ver internal/nftables/survival.go.
	if policy == PolicyDrop {
		rules = append(rules, SurvivalRules(access)[1:]...) // [1:]: o `related` já está acima
	}

	networks := sanitizeNetworks(ntpNetworks)
	if ntpServing {
		if len(networks) == 0 {
			slog.Warn("servir NTP para a LAN está ligado, mas nenhuma rede autorizada válida está configurada; a chain input fica sem as regras de proteção do NTP", "requested", ntpNetworks)
		} else {
			set := fmt.Sprintf("{ %s }", strings.Join(networks, ", "))
			rules = append(rules,
				[]string{"udp", "dport", "123", "ip", "saddr", set, "counter", "accept"},
				[]string{"udp", "dport", "123", "counter", "drop"},
			)
		}
	}

	sorted := make([]StoredGroup, len(groups))
	copy(sorted, groups)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Position < sorted[j].Position })

	for _, g := range sorted {
		if !g.Enabled {
			// Desligar = sumir do firewall. A chain do grupo e as regras dela
			// continuam guardadas no nft; só ninguém pula para lá.
			continue
		}
		if IsSystemGroup(g.Kind) || GroupScope(g) != ScopeInput {
			continue
		}
		if !validGroupChainName(g.ChainName) {
			// Este nome sai do banco e é interpolado no argv do nft, que junta
			// os argumentos e parseia o resultado — mesma porta que reIface e
			// ValidMark fecham nos outros geradores deste pacote.
			slog.Error("grupo ignorado ao montar a chain input: nome de chain inseguro",
				"grupo", g.ID, "nome", g.Name, "chain", g.ChainName)
			continue
		}
		tokens, err := groupJumpTokens(g)
		if err != nil {
			slog.Error("grupo ignorado ao montar a chain input: condição inválida",
				"grupo", g.ID, "nome", g.Name, "err", err)
			continue
		}
		rules = append(rules, tokens)
	}

	// A proteção de entrada das WANs vem DEPOIS dos jumps, e a posição é a
	// decisão (#119): um grupo de escopo input que libere algo vindo da WAN
	// precisa ser avaliado antes, senão o produto anularia em silêncio uma
	// decisão explícita do admin. Ver waninput.go.
	rules = append(rules, WANInputRules(wanIfaces, access, gerenciaFechada, contencao)...)
	return rules
}

// ReconcileInputProtection reconstrói a chain input a partir das fontes
// ligadas — grupos, NTP, política e a lista de WANs (#119).
//
// Existe porque a proteção de entrada deriva da lista de WANs, e essa lista
// muda por um caminho que não passa pelos dois escritores da chain: criar,
// editar, desligar ou apagar um link. Sem esta porta, a chain só acompanharia
// a mudança no boot seguinte — e uma interface renomeada deixaria o `iifname`
// apontando para um nome que não existe mais, isto é, a proteção calada com
// cara de ligada. É o mesmo defeito que a bateria G pegou na contabilidade.
func (s *Service) ReconcileInputProtection(ctx context.Context) error {
	if s.exec.IsDryRun() {
		return nil
	}
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()

	groups, err := s.inputChainGroups()
	if err != nil {
		return fmt.Errorf("ler os grupos de regras para reconstruir a chain %s: %w", InputChain, err)
	}
	ntpNetworks, ntpServing, err := s.ntpInputState()
	if err != nil {
		return fmt.Errorf("ler o estado do NTP para reconstruir a chain %s: %w", InputChain, err)
	}
	if err := s.reconcileInputChain(ctx, groups, ntpNetworks, ntpServing); err != nil {
		return err
	}
	if err := s.Persist(ctx); err != nil {
		slog.Warn("chain de input reconciliada, mas não foi possível persistir para o próximo boot", "err", err)
	}
	return nil
}

// reconcileInputChain é o único caminho que escreve na chain input: garante
// que ela existe e a reconstrói inteira a partir de inputChainRules.
//
// A chain é criada antes de tudo com um `add chain` idempotente porque, ao
// contrário da postrouting (existe desde o bootstrap), ela pode não existir
// numa máquina provisionada antes de 2026-08-11 — e o nft trata o `add chain`
// como no-op quando uma base chain com a mesma declaração já está lá (mesma
// convenção já em produção para a DNATChain, ver ApplyPortForwards).
//
// A política da declaração sai de inputPolicy(), e o padrão continua sendo
// `policy accept`.
//
// Até 2026-08-18 este valor era o literal "accept", com o comentário dizendo
// que não era negociável — porque uma chain input com `policy drop` corta SSH e
// painel no instante em que é aplicada, num firewall que pode não ter outro
// acesso administrativo. Isso continua verdade, e é por isso que NENHUM caminho
// do produto grava `drop` hoje: a fonte é opcional e, sem ela, o resultado é
// byte a byte o de antes (TestPoliticaPadraoEhAceitarSemFonte).
//
// O que mudou foi só o LUGAR da leitura, e é o ponto da issue #81: ela acontece
// aqui dentro, no caminho que os dois escritores da chain (reconcileGroups e
// ReconcileNTPInput) percorrem já sob reconcileMu. Lida de fora, ela reabriria
// pelo lado da política o mesmo buraco que o lock fecha pelo lado dos grupos —
// um toggle de NTP escrevendo a política antiga por cima de uma reversão.
func (s *Service) reconcileInputChain(ctx context.Context, groups []StoredGroup, ntpNetworks []string, ntpServing bool) error {
	policy, err := s.inputPolicy()
	if err != nil {
		// Aborta sem tocar na chain, o mesmo contrato dos grupos e do NTP: não
		// saber qual é a política não pode virar "então é accept".
		return err
	}
	// O acesso administrativo só é consultado quando ele importa: com política
	// permissiva as regras de sobrevivência não são emitidas, e uma leitura a
	// mais aqui seria mais uma forma de a chain deixar de ser reconciliada.
	var access AdminAccess
	if policy == PolicyDrop {
		access, err = s.adminAccess()
		if err != nil {
			return err
		}
	}
	// A lista de WANs é lida DENTRO desta função pelo mesmo motivo da política
	// (#81): os dois escritores da chain já passam por aqui sob reconcileMu, e
	// uma leitura feita fora do lock poderia gravar a lista antiga por cima de
	// uma reconciliação em curso.
	wans, err := s.wanInterfaces()
	if err != nil {
		return err
	}
	// AS PORTAS DE GERÊNCIA PRECISAM SER CONHECIDAS ANTES DE EMITIR O DESCARTE,
	// e não saber quais são elas CANCELA a proteção em vez de emiti-la sem a
	// liberação. É fail-open deliberado, na direção que este produto já
	// escolheu: um firewall permissivo por meia hora é um problema; uma caixa
	// que descarta a própria porta do painel não tem caminho de volta. Ver o
	// comentário em waninput.go sobre o que a VM mostrou.
	if len(wans) > 0 && policy != PolicyDrop {
		a, aerr := s.adminAccess()
		if aerr != nil {
			slog.Error("não foi possível ler as portas de gerência; a proteção de entrada das WANs NÃO será aplicada nesta reconciliação (emiti-la sem a liberação trancaria o admin do lado de fora)", "err", aerr)
			wans = nil
		} else {
			access = a
		}
	}
	// Lido AQUI DENTRO, sob reconcileMu, pelo mesmo motivo da política e das
	// WANs (#81): os dois escritores da chain passam por esta função, e uma
	// leitura feita fora do lock poderia gravar a decisão antiga por cima de
	// uma reversão em curso — justamente na mudança cuja reversão é a rede de
	// segurança contra tranca.
	fechada, err := s.wanMgmtClosed()
	if err != nil {
		return err
	}
	contencao, err := s.edgeContainment()
	if err != nil {
		return err
	}
	if _, err := s.exec.Execute(ctx, "nft", "add", "chain", Family, Table, InputChain,
		"{", "type", "filter", "hook", "input", "priority", "filter", ";", "policy", string(policy), ";", "}"); err != nil {
		return fmt.Errorf("criar chain %s: %w", InputChain, err)
	}
	return s.rebuildChain(ctx, InputChain, inputChainRules(groups, ntpNetworks, ntpServing, policy, access, wans, fechada, contencao))
}

// ReconcileNTPInput reconcilia a chain input a partir do toggle "servir NTP
// para a LAN" e das redes autorizadas que o admin escolheu
// (internal/timesync.Config.AllowedNetworks, spec §3.1). Mantém as
// propriedades de segurança de ReconcileMasquerade: só dá flush nesta chain
// (nunca na tabela nem no ruleset), valida todo CIDR antes de ele chegar ao
// nft, é no-op em dry-run e persiste ao final.
//
// Reformulada 2026-08-11 (spec §4) de um desenho anterior que negava NTP por
// interface WAN: quem decide quais redes podem usar o serviço de hora é o
// admin, não o software — e uma negação por WAN deixaria passar uma VLAN ou
// rede de visitantes não autorizada, já que nenhuma das duas é WAN.
//
// Fase C2: esta função DEIXOU de ser a dona da chain. Ela continua sendo a
// porta de entrada de quem mexe no NTP (o handler e o boot), mas quem escreve
// é reconcileInputChain, com o renderizador único — por isso ela precisa
// saber quais grupos de escopo input existem, e os lê de SetInputChainSources.
// Sem isso, ligar/desligar o NTP apagaria os jumps dos grupos de input.
//
// Erro ao ler os grupos ABORTA sem tocar na chain, e não reconstrói com lista
// vazia: um SELECT que falhou não é "o admin não tem grupo nenhum" — obedecer
// a essa lista vazia apagaria da chain input todos os jumps do admin por causa
// de um erro de leitura. É o mesmo contrato do doc-comment de ReconcileGroups.
//
// I-3 da revisão final: a leitura dos grupos e a reescrita da chain acontecem
// sob o LOCK DE RECONCILIAÇÃO (reconcileMu). Sem ele, um toggle de NTP — que é
// mutação deliberadamente NÃO travada pela janela de confirmação — podia ler os
// grupos antes de uma reversão restaurar o banco e escrevê-los depois, devolvendo
// ao kernel o jump que a reversão acabou de tirar.
func (s *Service) ReconcileNTPInput(ctx context.Context, allowedNetworks []string, serving bool) error {
	if s.exec.IsDryRun() {
		return nil
	}
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()

	groups, err := s.inputChainGroups()
	if err != nil {
		return fmt.Errorf("ler os grupos de regras para reconstruir a chain %s: %w", InputChain, err)
	}

	if err := s.reconcileInputChain(ctx, groups, allowedNetworks, serving); err != nil {
		return err
	}

	slog.Info("chain input reconciliada (proteção do NTP + grupos de escopo input)",
		"serving", serving, "allowed_networks", sanitizeNetworks(allowedNetworks), "grupos", len(groups))

	if err := s.Persist(ctx); err != nil {
		slog.Warn("chain de input reconciliada, mas não foi possível persistir para o próximo boot", "err", err)
	}
	return nil
}

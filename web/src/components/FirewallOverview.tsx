import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ChevronDown, ChevronRight, ExternalLink, Pencil, Check, Ban, Slash,
  ArrowRightLeft, CornerDownRight, Tag, HelpCircle,
} from 'lucide-react';
import type { NftChainInfo, NftChainRule } from '../types';

type Unit = 'bytes' | 'bits';

interface Props {
  chains: NftChainInfo[];
  onOpenGroupsTab: () => void;
  onOpenBlocksTab: () => void;
  onOpenPortForwardTab: () => void;
}

// The packet-path stages from the design spec (§3): a fixed, human grouping
// of the chains, in the order the kernel actually evaluates them for each
// kind of traffic. user_rules is grouped into "Encaminhamento" right before
// forward's own rules, because that's literally what happens on the wire —
// forward jumps into user_rules first, then falls through to the
// blocklist/host-block drops.
// chainPrefix cobre as chains de nome dinâmico: cada grupo de regras do
// admin vira uma chain grp_<hex>, e o nome não dá para listar aqui. Sem
// isso elas caíam em "Outras chains", com borda amarela e o aviso de
// "não previstas no agrupamento" — a peça central da tela de grupos
// apresentada como anomalia. Elas são previstíssimas: a forward pula
// para elas, e é aí que o pacote passa.
const STAGE_DEFS: { key: string; label: string; hint: string; chainNames: string[]; chainPrefix?: string }[] = [
  { key: 'input', label: 'Entrada', hint: 'tráfego destinado ao próprio firewall (ex.: proteção de NTP)', chainNames: ['input'] },
  { key: 'mark_hosts', label: 'Marcação', hint: 'direciona um host para uma WAN específica', chainNames: ['mark_hosts'] },
  { key: 'forward', label: 'Encaminhamento', hint: 'tráfego atravessando: os bloqueios primeiro, depois seus grupos de regras', chainNames: ['forward'], chainPrefix: 'grp_' },
  { key: 'postrouting', label: 'NAT de saída', hint: 'mascaramento de origem para as WANs', chainNames: ['postrouting'] },
  { key: 'prerouting_dnat', label: 'Redirecionamento de porta', hint: 'encaminhamento de porta (DNAT)', chainNames: ['prerouting_dnat'] },
];

const CHAIN_LABELS: Record<string, string> = {
  input: 'input',
  mark_hosts: 'mark_hosts',
  user_rules: 'Suas regras (user_rules)',
  forward: 'forward',
  postrouting: 'postrouting',
  prerouting_dnat: 'prerouting_dnat',
};

// Where "abrir" takes the admin for a managed rule's owning control. `to`
// navigates to another page; `tab` switches a tab on this same page.
// wan_steering and blocklist moved from "Regras" to "Bloqueios e
// direcionamento" (Task 10) — the links follow the panels, not the chain
// name they still share with user_rules.
const OWNER_LINKS: Record<string, { to?: string; tab?: 'groups' | 'blocks' | 'portforward' }> = {
  ntp: { to: '/ntp' },
  nat: { to: '/links' },
  wan_steering: { tab: 'blocks' },
  blocklist: { tab: 'blocks' },
  host_block: { to: '/hosts' },
  port_forward: { tab: 'portforward' },
  rule_groups: { tab: 'groups' },
};

function formatCount(bytes: number, unit: Unit): string {
  const value = unit === 'bits' ? bytes * 8 : bytes;
  const suffixes = unit === 'bits' ? ['b', 'Kb', 'Mb', 'Gb', 'Tb'] : ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = value;
  let i = 0;
  while (v >= 1000 && i < suffixes.length - 1) {
    v /= 1000;
    i++;
  }
  return `${i === 0 ? v.toFixed(0) : v.toFixed(1)} ${suffixes[i]}`;
}

// ruleVerb derives a short action label + color from the raw expression —
// the same ACTIONS palette convention used by the custom-rules tab, extended
// to the non accept/drop/reject actions LinkGuard's own chains use
// (masquerade, jump, dnat, mark).
//
// The labels are the nftables keywords themselves — accept, drop, reject,
// masquerade, dnat, jump — never translated. These are the trade's own
// vocabulary: a network admin reads `drop` on this screen and finds `drop`
// in `nft list ruleset`, with no second dictionary in between that exists
// only inside this panel. Same reasoning as showing rule conditions in raw
// nft syntax. The plain-Portuguese sentence beside the badge carries the
// meaning; the badge carries the identity.
function ruleVerb(expr: string): { label: string; color: string; ring: string; Icon: typeof Check } {
  if (/\baccept$/.test(expr)) return { label: 'accept', color: 'text-green-400', ring: 'border-green-500 bg-green-500/10', Icon: Check };
  if (/\bdrop$/.test(expr)) return { label: 'drop', color: 'text-red-400', ring: 'border-red-500 bg-red-500/10', Icon: Ban };
  if (/\breject/.test(expr)) return { label: 'reject', color: 'text-orange-400', ring: 'border-orange-500 bg-orange-500/10', Icon: Slash };
  if (/\bmasquerade\b/.test(expr)) return { label: 'masquerade', color: 'text-blue-400', ring: 'border-blue-500 bg-blue-500/10', Icon: ArrowRightLeft };
  if (/\bdnat\b/.test(expr)) return { label: 'dnat', color: 'text-blue-400', ring: 'border-blue-500 bg-blue-500/10', Icon: ArrowRightLeft };
  if (/^(counter )?jump /.test(expr)) return { label: 'jump', color: 'text-purple-400', ring: 'border-purple-500 bg-purple-500/10', Icon: CornerDownRight };
  if (/meta mark set/.test(expr)) return { label: 'mark', color: 'text-yellow-400', ring: 'border-yellow-500 bg-yellow-500/10', Icon: Tag };
  return { label: 'regra', color: 'text-gray-400', ring: 'border-gray-600 bg-gray-700/30', Icon: HelpCircle };
}

function RuleRow({
  rule, unit, expanded, onToggle, isUserRule, onOpenGroupsTab, onOpenBlocksTab, onOpenPortForwardTab,
}: {
  rule: NftChainRule; unit: Unit; expanded: boolean; onToggle: () => void;
  isUserRule: boolean; onOpenGroupsTab: () => void; onOpenBlocksTab: () => void; onOpenPortForwardTab: () => void;
}) {
  const v = ruleVerb(rule.expression);
  // Which control owns a managed rule decides where "abrir" takes the admin
  // — not the chain it lives in (the forward chain alone mixes blocklist
  // and host-block rules, each pointing somewhere different).
  const link = rule.owner.key ? OWNER_LINKS[rule.owner.key] : undefined;
  const openTab = link?.tab === 'groups' ? onOpenGroupsTab : link?.tab === 'blocks' ? onOpenBlocksTab : link?.tab === 'portforward' ? onOpenPortForwardTab : undefined;
  // A disabled admin rule exists in the DB but was never sent to nft
  // (Phase B, design spec §4.1) — shown here, not hidden, but visibly
  // dimmed and labelled so it can never be mistaken for an active rule.
  const disabled = rule.enabled === false;
  // C-3: a rule the admin left enabled but that the backend could not find
  // live in nft (a reconcile that failed partway, or hasn't caught up yet)
  // is a DISTINCT failure state from "Desativada" — that one is a
  // deliberate admin choice, this one is the firewall not actually doing
  // what's configured, which is exactly the state FEATURES.md's delivery
  // rule ("configured ≠ working") exists to surface, not hide behind a
  // green "Sua regra" badge that looks identical to a rule that really is
  // in effect.
  const configuredNotApplied = rule.enabled === true && rule.applied === false;

  return (
    <div className={`rounded-lg bg-gray-800/60 px-3 py-2 ${disabled ? 'opacity-50' : ''} ${configuredNotApplied ? 'ring-1 ring-yellow-500/40' : ''}`}>
      <div className="flex flex-wrap items-center gap-2">
        <button onClick={onToggle} className="text-gray-500 hover:text-gray-300 shrink-0" aria-label="Mostrar/ocultar expressão nft" title="Mostrar/ocultar expressão nft">
          {expanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
        </button>
        <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium border shrink-0 ${v.ring} ${v.color}`}>
          <v.Icon className="w-3 h-3" /><span className="font-mono">{v.label}</span>
        </span>
        <span className="text-gray-300 text-sm flex-1 min-w-0">{rule.description}</span>
        {disabled && (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium border border-gray-600 bg-gray-700/40 text-gray-400 shrink-0">
            Desativada
          </span>
        )}
        {configuredNotApplied && (
          <span
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium border border-yellow-500/40 bg-yellow-500/10 text-yellow-400 shrink-0"
            title="Está ativada aqui, mas o firewall não confirma que ela está em vigor — pode ser um erro ao aplicar; confira o aviso no topo da aba Regras."
          >
            Configurada, não aplicada
          </span>
        )}

        {rule.managed ? (
          <span className="inline-flex items-center gap-1.5 shrink-0 text-xs">
            <span className="px-2 py-0.5 rounded bg-gray-700/60 text-gray-400">{rule.owner.label}</span>
            {link?.to && (
              <Link to={link.to} className="inline-flex items-center gap-1 text-blue-400 hover:text-blue-300">
                abrir <ExternalLink className="w-3 h-3" />
              </Link>
            )}
            {openTab && (
              <button onClick={openTab} className="inline-flex items-center gap-1 text-blue-400 hover:text-blue-300">
                abrir <ExternalLink className="w-3 h-3" />
              </button>
            )}
          </span>
        ) : (
          <span className="inline-flex items-center gap-2 shrink-0 text-xs">
            <span className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/30">Sua regra</span>
            {isUserRule && (
              <button onClick={onOpenGroupsTab} className="inline-flex items-center gap-1 text-gray-400 hover:text-gray-200" title="Editar na aba Grupos de regras">
                <Pencil className="w-3.5 h-3.5" />
              </button>
            )}
          </span>
        )}

        <span className="text-xs text-gray-500 font-mono shrink-0 text-right w-28">
          {rule.has_counter ? `${rule.packets.toLocaleString('pt-BR')} pct` : '—'}
        </span>
        <span className="text-xs text-gray-500 font-mono shrink-0 text-right w-24">
          {rule.has_counter ? formatCount(rule.bytes, unit) : '—'}
        </span>
      </div>
      {expanded && (
        <pre className="mt-2 ml-6 text-[11px] font-mono text-gray-500 whitespace-pre-wrap break-all">{rule.expression}</pre>
      )}
    </div>
  );
}

/**
 * FirewallOverview is the Phase A "unified view" (design spec §3): every
 * chain in table inet linkguard, grouped by packet-path stage, each rule
 * showing its action, a plain-Portuguese description, its raw nft
 * expression (collapsed by default), and its counters — with a bytes/bits
 * selector, since network admins reason in Mbps while storage is measured
 * in bytes (§3.1). A rule without a counter shows "—", never "0": not
 * measured and measured-zero are different states.
 *
 * Read-only here by design (spec §2): a rule is either managed by
 * LinkGuard (shown with its owning control and a link to it — Phase B is
 * what makes user_rules itself editable inline) or the admin's own
 * (user_rules — still edited from the existing "Regras" tab, linked from
 * here via the pencil icon, so the CRUD/reorder controls already shipped
 * are not duplicated or regressed).
 */
export default function FirewallOverview({ chains, onOpenGroupsTab, onOpenBlocksTab, onOpenPortForwardTab }: Props) {
  const [unit, setUnit] = useState<Unit>('bytes');
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const toggle = (key: string) => setExpanded((e) => ({ ...e, [key]: !e[key] }));

  const byName = new Map(chains.map((c) => [c.name, c]));
  const usedNames = new Set<string>();
  const groups = STAGE_DEFS.map((def) => {
    const stageChains = def.chainNames
      .map((n) => byName.get(n))
      .filter((c): c is NftChainInfo => !!c);
    if (def.chainPrefix) {
      const prefix = def.chainPrefix;
      stageChains.push(...chains.filter((c) => c.name.startsWith(prefix)));
    }
    stageChains.forEach((c) => usedNames.add(c.name));
    return { ...def, stageChains };
  }).filter((g) => g.stageChains.length > 0);

  // Anything not covered by the fixed stage table above — an unexpected or
  // future chain — is still shown, never silently dropped (spec §2:
  // "mostrar tudo, mentir sobre nada").
  const others = chains.filter((c) => !usedNames.has(c.name));

  const totalRules = chains.reduce((n, c) => n + c.rules.length, 0);

  return (
    <div className="space-y-4">
      <div className="card flex flex-wrap items-center justify-between gap-3">
        <p className="text-gray-400 text-sm">
          {totalRules} regra{totalRules === 1 ? '' : 's'} em {chains.length} chain{chains.length === 1 ? '' : 's'}, na ordem em que o firewall avalia o tráfego.
        </p>
        <div className="flex items-center gap-2 text-xs">
          <span className="text-gray-500">Contadores em:</span>
          <div className="inline-flex rounded-lg border border-gray-700 overflow-hidden">
            <button
              onClick={() => setUnit('bytes')}
              className={`px-3 py-1.5 ${unit === 'bytes' ? 'bg-blue-500/20 text-blue-300' : 'text-gray-400 hover:text-gray-200'}`}
            >bytes (KB/MB/GB)</button>
            <button
              onClick={() => setUnit('bits')}
              className={`px-3 py-1.5 border-l border-gray-700 ${unit === 'bits' ? 'bg-blue-500/20 text-blue-300' : 'text-gray-400 hover:text-gray-200'}`}
            >bits (Kb/Mb/Gb)</button>
          </div>
        </div>
      </div>

      {groups.map((g) => (
        <div key={g.key} className="card">
          <div className="mb-3">
            <h3 className="text-white font-semibold">{g.label}</h3>
            <p className="text-gray-500 text-xs">{g.hint}</p>
          </div>
          <div className="space-y-4">
            {g.stageChains.map((chain) => (
              <div key={chain.name}>
                <div className="flex items-center gap-2 mb-1.5">
                  <span className="text-xs font-mono text-gray-500">
                    {CHAIN_LABELS[chain.name] ?? chain.name}
                    {chain.name.startsWith('grp_') && (
                      <span className="ml-2 font-sans text-gray-600">um dos seus grupos de regras</span>
                    )}
                  </span>
                  {chain.policy && (
                    <span className="text-[11px] text-gray-600">hook {chain.hook} · priority {chain.priority} · policy {chain.policy}</span>
                  )}
                  {chain.name === 'user_rules' && (
                    <button onClick={onOpenGroupsTab} className="ml-auto text-xs text-blue-400 hover:text-blue-300 inline-flex items-center gap-1">
                      gerenciar <ExternalLink className="w-3 h-3" />
                    </button>
                  )}
                </div>
                {chain.rules.length === 0 ? (
                  <p className="text-gray-600 text-sm py-1.5 pl-1">
                    {chain.name === 'user_rules' ? (
                      <>Nenhuma regra personalizada. <button onClick={onOpenGroupsTab} className="text-blue-400 hover:text-blue-300 underline">Criar uma</button>.</>
                    ) : 'Nenhuma regra.'}
                  </p>
                ) : (
                  <div className="space-y-1.5">
                    {chain.rules.map((r) => {
                      // A disabled admin rule has no nft handle (it was
                      // never sent to nft), so r.id — its stable DB id — is
                      // what keeps the key unique among several of them.
                      const key = `${chain.name}-${r.id || r.handle}`;
                      return (
                        <RuleRow
                          key={key}
                          rule={r}
                          unit={unit}
                          expanded={!!expanded[key]}
                          onToggle={() => toggle(key)}
                          isUserRule={chain.name === 'user_rules'}
                          onOpenGroupsTab={onOpenGroupsTab}
                          onOpenBlocksTab={onOpenBlocksTab}
                          onOpenPortForwardTab={onOpenPortForwardTab}
                        />
                      );
                    })}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      ))}

      {others.length > 0 && (
        <div className="card border-yellow-500/30">
          <h3 className="text-white font-semibold mb-1">Outras chains</h3>
          <p className="text-gray-500 text-xs mb-3">Não previstas no agrupamento acima — exibidas mesmo assim, para não esconder nada.</p>
          <div className="space-y-4">
            {others.map((chain) => (
              <div key={chain.name}>
                <span className="text-xs font-mono text-gray-500">{chain.name}</span>
                <div className="space-y-1.5 mt-1.5">
                  {chain.rules.map((r) => {
                    const key = `${chain.name}-${r.handle}`;
                    return (
                      <RuleRow
                        key={key}
                        rule={r}
                        unit={unit}
                        expanded={!!expanded[key]}
                        onToggle={() => toggle(key)}
                        isUserRule={false}
                        onOpenGroupsTab={onOpenGroupsTab}
                        onOpenBlocksTab={onOpenBlocksTab}
                        onOpenPortForwardTab={onOpenPortForwardTab}
                      />
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

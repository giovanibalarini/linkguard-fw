// API type definitions for LinkGuard FW

export type LinkStatus = 'online' | 'offline' | 'degraded' | 'unknown';
export type AlertSeverity = 'info' | 'warning' | 'critical';

// MsgLevel é como uma mensagem de tela deve SOAR. Os dois primeiros já
// existiam implicitamente (verde, ou vermelho quando o texto começa com
// "Erro"); 'warn' existe porque há um recado que não é nenhum dos dois: "o
// prazo acabou sem confirmação e a alteração foi revertida" não é uma boa
// notícia — em verde, ele induz o operador a achar que a mudança dele valeu.
export type MsgLevel = 'ok' | 'warn' | 'error';

export interface WanLink {
  id: string;
  name: string;
  interface: string;
  ip_address: string;
  gateway: string;
  weight: number;
  dns_test: string;
  monitor_hosts: string;
  status: LinkStatus;
  latency_ms: number;
  packet_loss: number;
  last_check: string | null;
  enabled: boolean;
  table_id: number;
  created_at: string;
  updated_at: string;
}

export interface TimelinePoint {
  ts: number;
  min: number;
  avg: number;
  max: number;
}

export interface TimelineSeries {
  name: string;
  label: string;
  points: TimelinePoint[];
}

export interface TimelineState {
  kind: string;
  label: string;
  state: string;
  started_at: number;
  ended_at?: number;
}

export interface TimelineAlert {
  ts: number;
  type: string;
  severity: string;
  title: string;
}

export interface TimelineResponse {
  step_seconds: number;
  series: TimelineSeries[];
  states: TimelineState[];
  alerts: TimelineAlert[];
}

export interface SystemMetrics {
  uptime_seconds: number;
  uptime_str: string;
  cpu_percent: number;
  mem_total_bytes: number;
  mem_used_bytes: number;
  mem_percent: number;
  disk_total_bytes: number;
  disk_used_bytes: number;
  disk_percent: number;
  load_avg: [number, number, number];
  interfaces: InterfaceMetrics[];
}

export interface InterfaceMetrics {
  name: string;
  alias?: string;
  addresses?: InterfaceAddress[];
  rx_bytes: number;
  tx_bytes: number;
  rx_packets: number;
  tx_packets: number;
  rx_errors: number;
  tx_errors: number;
  rx_dropped: number;
  tx_dropped: number;
}

export interface InterfaceAddress {
  family: string;
  ip: string;
  subnet: string;
  cidr: string;
}

export interface Alert {
  id: string;
  type: string;
  severity: AlertSeverity;
  title: string;
  message: string;
  link_id: string;
  resolved: boolean;
  created_at: string;
  resolved_at: string | null;
}

export interface AuditLog {
  id: string;
  user: string;
  action: string;
  resource: string;
  details: string;
  ip: string;
  created_at: string;
}

export interface FailoverEvent {
  id: string;
  link_id: string;
  link_name: string;
  from_status: string;
  to_status: string;
  reason: string;
  commands: string;
  dry_run: boolean;
  created_at: string;
}

export interface Route {
  destination: string;
  gateway: string;
  interface: string;
  metric: string;
  protocol: string;
  scope: string;
  raw: string;
}

export interface IpRule {
  priority: string;
  selector: string;
  action: string;
  table: string;
  fwmark?: string;
  raw: string;
}

export interface InterfaceOption {
  name: string;
}

export interface IptablesTable {
  name: string;
  chains: IptablesChain[];
}

export interface IptablesChain {
  name: string;
  policy: string;
  rules: IptablesRule[];
}

export interface IptablesRule {
  num: string;
  raw: string;
  pkts: string;
  bytes: string;
  target: string;
  prot: string;
  in: string;
  out: string;
  source: string;
  dest: string;
  options: string[];
}

export interface IptablesBackup {
  id: string;
  label: string;
  rules: string;
  created_at: string;
}

export interface LoginResponse {
  token: string;
  user: {
    id: string;
    username: string;
    role: string;
  };
}

export interface HealthStatus {
  status: string;
  link_count: number;
}

// ─── RBAC ──────────────────────────────────────────────────────────────────

export interface AppUser {
  id: string;
  username: string;
  role: string;
  role_ids: string[];
  created_at: string;
  updated_at: string;
}

export interface AppRole {
  id: string;
  name: string;
  description: string;
  builtin: boolean;
  permissions: string[];
  created_at: string;
  updated_at: string;
}

export interface PermissionCatalogEntry {
  key: string;
  area: string;
  label: string;
  description: string;
}

export interface MeResponse {
  id: string;
  username: string;
  role_ids: string[];
  permissions: string[];
}

export interface NftManaged {
  wan_hosts: { ip: string; mark: string }[];
  blocklist: string[];
  blocked_hosts: string[];
}

// FirewallRule is one of the admin's own rules (Phase B, design spec §4.1):
// it now lives in the DB, identified by a stable id, with an explicit
// position (order) and an enabled flag ("disable without deleting" —
// nftables itself has no such concept, so this is DB-only state) plus a
// free-text description. GET/POST/PUT/DELETE /api/nftables/rules,
// POST /api/nftables/rules/reorder and /rules/toggle.
export interface FirewallRule {
  id: string;
  position: number;
  // group_id is the group (nft chain) the rule lives in — required on
  // create since Fase C1: a rule with no group belongs to no chain and
  // therefore exists nowhere in the firewall. Position, note, is GLOBAL
  // across every group, not per group: /api/nftables/rules/reorder expects
  // the complete list of every rule of every group, in the new global
  // order, and refuses anything partial.
  group_id: string;
  enabled: boolean;
  action: 'accept' | 'drop' | 'reject' | string;
  iif: string;
  oif: string;
  saddr: string;
  daddr: string;
  proto: string;
  dport: string;
  description: string;
  created_at: string;
  updated_at: string;
}

// FirewallRulesData is GET /api/nftables/rules' response (C-3, design spec
// §4.1): the rules themselves plus the persisted outcome of the most recent
// user_rules reconcile — apply_status is undefined only when a reconcile
// has genuinely never run yet (never a synthetic "ok" standing in for
// "unknown"), same LastApply shape used by NTP/DHCP/DNS.
export interface FirewallRulesData {
  rules: FirewallRule[];
  apply_status?: FirewallApplyStatus;
}

// FirewallApplyStatus é o LastApply do firewall com a pergunta que só ele tem:
// "o que está valendo agora volta depois de um reboot?".
//
// boot_persist_error preenchido significa que as regras ENTRARAM no kernel e
// estão valendo, mas o arquivo que o nftables.service carrega no boot não foi
// gravado — medido em VM com /etc imutável, quando o painel dizia `ok: true` e
// a máquina voltaria de um reboot com outro firewall. `ok` vem falso junto,
// porque um verde nesse estado é a mentira que este campo existe para desfazer;
// quem desenha a tela precisa dos dois para não chamar de "apply que falhou"
// algo que o operador desfaria à toa (ver a faixa em FirewallGroups.tsx).
export interface FirewallApplyStatus extends LastApply {
  boot_persist_error?: string;
}

// ─── Firewall overview (GET /api/nftables/overview) ───────────────────────

// A descrição estruturada que o backend manda ao lado da frase pronta
// (issue #109): a chave do que a regra faz, e os valores dela.
export interface NftRuleDesc {
  key: string;
  vars?: Record<string, string>;
}

export interface NftRuleOwner {
  key?: string;
  label: string;
}

export interface NftChainRule {
  chain: string;
  handle: number;
  expression: string;
  has_counter: boolean;
  packets: number;
  bytes: number;
  managed: boolean;
  owner: NftRuleOwner;
  description: string;
  desc?: NftRuleDesc;
  // id/enabled are only ever populated for the user_rules chain (Phase B,
  // design spec §4.1): id is the rule's stable DB id (never nft's volatile
  // handle); enabled is undefined for every other chain, and explicitly
  // true/false for a user_rules entry — a disabled rule exists in the DB
  // but never reached nft, so it also has has_counter=false ("not
  // measured", not a fake zero).
  id?: string;
  enabled?: boolean;
  // applied is C-3's honest third state: true for every rule read straight
  // off the live table (any chain) and for a user_rules entry the backend
  // matched to a real live rule by identity; false ONLY for a user_rules
  // entry that is enabled=true in the DB but could not be found live — the
  // "configurada, não aplicada" state, distinct from enabled=false
  // ("Desativada", a deliberate admin choice). Never mix the two up: an
  // enabled rule that isn't applied is a firewall that doesn't match what
  // the admin configured, not a rule the admin chose to turn off.
  applied?: boolean;
}

export interface NftChainInfo {
  name: string;
  type?: string;
  hook?: string;
  priority?: string;
  policy?: string;
  rules: NftChainRule[];
}

// ─── Grupos de regras (GET /api/nftables/groups, design spec §2) ──────────

// GroupFallthrough is what the group does with traffic that entered it and
// that none of its rules decided: `continue` emits no final line (the jump
// returns and evaluation goes on), `accept`/`drop` emit that verdict as the
// chain's last line. The values are the nft keywords themselves, never
// translated — same discipline as the rule actions (spec §7.2.1).
export type GroupFallthrough = 'continue' | 'accept' | 'drop';

// FirewallGroupKind separa os grupos que o admin criou dos dois que o próprio
// LinkGuard mantém para os named sets de bloqueio (@blocked_hosts e
// @blocklist). Espelha as constantes do backend (internal/nftables/groups.go).
//
// String vazia conta como grupo do admin: é o valor que toda linha criada
// antes desta coluna existir carrega, e tratá-la como "do sistema" daria a ela
// proteções (não apagar, não renomear) que o admin nunca pediu. Um kind
// desconhecido cai no mesmo lado seguro — por isso a checagem é uma lista
// fechada dos dois kinds de sistema (isSystemGroup em lib/blockGroups.ts), e
// nunca `kind !== 'admin'`.
export type FirewallGroupKind = '' | 'admin' | 'blocked_hosts' | 'blocklist';

// GroupScope diz PARA QUAL TRÁFEGO o grupo vale, e é o que decide em qual
// chain o `jump` dele é escrito (Fase C2, espelha internal/nftables/groups.go):
//
//   - 'forward': tráfego ATRAVESSANDO o firewall — a LAN saindo para a
//     internet, uma VLAN falando com outra;
//   - 'input': tráfego DESTINADO ao próprio firewall — SSH, o painel, DNS,
//     Samba. É o escopo que pode trancar o operador para fora da máquina, e
//     por isso toda mudança nele abre a janela de confirmação de 90 segundos.
//
// String vazia conta como 'forward': é o valor de toda linha criada antes
// desta coluna existir, e todo grupo anterior à Fase C2 é de tráfego
// atravessando. É a mesma normalização de GroupScope no backend, e as duas não
// podem discordar — tratar vazio como input mostraria na tela um grupo na
// chain errada.
export type GroupScope = '' | 'forward' | 'input';

// GroupConnState diz PARA QUAIS CONEXÕES o grupo vale (espelha
// internal/nftables/groups.go):
//
//   - 'any': toda conexão que casar com a condição de entrada, esteja ela
//     começando agora ou já em curso. É a marreta, e é o padrão;
//   - 'new': só as conexões NOVAS. A linha de jump do grupo ganha
//     `ct state new`, e o que já está estabelecido segue até terminar sem
//     passar por ele.
//
// String vazia conta como 'any': é o valor de toda linha gravada antes desta
// coluna existir, e é o que toda máquina em produção faz hoje. A normalização
// é a mesma do backend (GroupConnState), e as duas não podem discordar — do
// contrário a tela mostraria uma escolha que o kernel não está fazendo.
export type GroupConnState = '' | 'any' | 'new';

// FirewallPendingChange é a janela de confirmação em aberto, como GET
// /api/nftables/pending a devolve (handlers.pendingView).
//
// `id` NÃO é decoração: confirmar e reverter o exigem no corpo, e ele é
// conferido contra a janela atual — sem ele, um admin confirmando cancelaria a
// rede de proteção de uma mudança de outro admin que ele nunca viu.
//
// `reverting` separa os dois estados possíveis, e a faixa PRECISA dos dois
// porque os botões que cabem são outros em cada um: aguardando confirmação
// cabem "Confirmar acesso" e "Reverter agora"; com a reversão já em curso não
// cabe nenhum dos dois (o backend recusa confirmar), e o texto tem que dizer
// que a reversão está acontecendo.
export interface FirewallPendingChange {
  id: string;
  summary: string;
  applied_by: string;
  // expires_at é o instante em que o LinkGuard reverte sozinho, em hora do
  // SERVIDOR. É a verdade persistida da janela.
  expires_at: string;
  // seconds_left é quanto falta, medido pelo relógio DO SERVIDOR e recalculado
  // a cada resposta. A contagem da tela parte daqui, e não de
  // `expires_at - Date.now()`: aquela conta mistura a hora do firewall com a da
  // estação do operador, e um relógio deslocado erra o número na mesma medida —
  // "45 s" quando restam 5 é o caso ruim, porque é esse número que ele usa para
  // decidir se ainda dá tempo de testar o SSH.
  seconds_left: number;
  created_at: string;
  reverting: boolean;
  reverting_at?: string;
  // new_connections_only é o aviso que torna esta janela honesta: a mudança
  // que está sendo testada deixou valendo um grupo de escopo input restrito a
  // `ct state new`, e um grupo desses NÃO derruba a sessão do operador. O
  // teste de 90 segundos feito na aba que já estava aberta, ou no SSH que já
  // estava conectado, passa mesmo quando o bloqueio existe — ele só morde na
  // próxima conexão, quando já não há reversão automática nenhuma.
  //
  // Quando é `false`, a faixa NÃO mostra o aviso: ali a sessão cai de verdade
  // se o operador se trancar para fora, o teste vale sozinho, e um aviso em
  // toda janela é um aviso que ninguém lê.
  new_connections_only: boolean;
}

// FirewallPendingResponse é o corpo do GET. `pending` é null explícito quando
// não há janela — a ausência do campo nunca deve ser lida como "não há nada".
export interface FirewallPendingResponse {
  pending: FirewallPendingChange | null;
}

// FirewallGroup is one group of rules: a chain of its own (`chain_name`,
// always derived server-side from the id, never from the typed name),
// reached from forward by an entry condition + `counter jump`.
//
// enabled vs applied is the same honest split as the rules: `enabled` is
// what the admin asked for, `applied` is whether the jump is really in the
// live forward chain. has_counter=false means "not measured" and must
// render as "—", never as a zero (spec §7.3).
//
// The counters are the JUMP's own — how much traffic actually entered the
// group — not the sum of the inner rules, which would overcount whatever
// matched two conditions and undercount whatever entered and matched none.
export interface FirewallGroup {
  id: string;
  name: string;
  chain_name: string;
  position: number;
  enabled: boolean;
  cond_saddr: string;
  cond_daddr: string;
  cond_iif: string;
  fallthrough: GroupFallthrough;
  // kind diz quem mantém este grupo. Para um grupo do sistema, `rules` volta
  // vazio de propósito: o conteúdo dele são os membros de um named set, não
  // uma lista de regras, e ele não tem chain própria — as linhas de drop dele
  // moram na própria forward, e `applied` vem de todas elas estarem vivas lá.
  kind: FirewallGroupKind;
  // scope decide em qual chain o jump deste grupo é escrito (ver GroupScope).
  // Vem vazio em todo grupo criado antes da Fase C2, e vazio é 'forward'.
  scope: GroupScope;
  // conn_state decide se a linha de jump carrega `ct state new` (ver
  // GroupConnState). Vem vazio em todo grupo anterior a esta escolha existir,
  // e vazio é 'any' — a marreta de sempre.
  conn_state: GroupConnState;
  applied: boolean;
  handle: number;
  packets: number;
  bytes: number;
  has_counter: boolean;
  // rules is the group's chain already merged with the live firewall. Watch
  // out: besides the admin's rules (each with an `id`), it can carry live
  // lines that have no DB row behind them — chiefly the group's own "e o
  // que sobrar" verdict, which is the `fallthrough` field above and not a
  // rule at all. Edit/delete must be gated on the presence of `id`, never
  // on `managed === false`.
  rules: NftChainInfo;
  // Janela de horário (#125): vazio = o grupo vale sempre.
  sched_days?: string;
  sched_start?: string;
  sched_end?: string;
}

export interface FirewallGroupsData {
  groups: FirewallGroup[];
  apply_status?: FirewallApplyStatus | null;
}

export interface PortForward {
  id: string;
  name: string;
  enabled: boolean;
  proto: 'tcp' | 'udp';
  interface: string; // WAN iif; empty = any
  ext_port: number;
  dest_ip: string;
  dest_port: number;
}

export interface NetsvcConfig {
  backend: string;
  interface: string;
  subnet_cidr: string;
  range_start: string;
  range_end: string;
  gateway: string;
  lease_hours: number;
  dns_to_clients: string[];
  upstreams: string[];
  log_queries: boolean;
  /** Entrega das RESPOSTAS de DNS ao coletor, que alimenta o mapa endereço → nome (#116). */
  dnstap_enabled?: boolean;
  domain_suffix: string;
  // Controle de fuga de DNS (#124). Ver a tela de DNS para o que cada um
  // realmente garante — e o que não garante.
  force_local_dns: boolean;
  block_dot: boolean;
  dns_except_ips: string[];
}
export interface DHCPReservation { mac: string; ip: string; hostname: string; created_at?: string; updated_at?: string; }
export interface DHCPLease { expiry: number; mac: string; ip: string; hostname: string; }
// warning (I-7): o apply terminou bem, mas o backend descartou entradas
// inválidas que a tela ainda mostra como configuradas (domínio de bloqueio,
// upstream de DNS, servidor NTP). É um terceiro estado entre "falhou" e
// "tudo em vigor" — nunca deve ser exibido como sucesso puro.
export interface LastApply { ok: boolean; error?: string; warning?: string; at: number; }
export interface DHCPData { config: NetsvcConfig; reservations: DHCPReservation[]; leases: DHCPLease[]; backend: string; last_apply?: LastApply; }
export interface DNSData { config: NetsvcConfig; blocklist: string[]; backend: string; last_apply?: LastApply; }

export interface NTPConfig { servers: string[]; timezone: string; serve_lan: boolean; allowed_networks: string[]; }
export interface NTPStatus { installed: boolean; synced: boolean; stratum?: number; offset_secs?: number; source?: string; }
export interface NTPData { config: NTPConfig; status: NTPStatus; timezones: string[]; last_apply?: LastApply; firewall_apply?: LastApply; suggested_network: string; }

export interface HostTraffic { ip: string; rx_bytes: number; tx_bytes: number; }

// ─── Link stress-test ────────────────────────────────────────────────────────

export interface StressSample { t: string; route: string; ping: boolean; dns: boolean; phase: string }
export interface StressTest {
  id: string;
  link_id: string;
  link_name: string;
  interface: string;
  mode: 'outage' | 'degrade';
  delay_ms: number;
  loss_pct: number;
  duration_sec: number;
  state: string; // idle | running | done | aborted | error
  message: string;
  started_at: string;
  ended_at: string;
  samples: StressSample[];
  ping_loss_pct: number;
  dns_loss_pct: number;
  restored: boolean;
}

// ─── Multi-WAN balancing ─────────────────────────────────────────────────────

export interface BalanceNexthop {
  link_id: string;
  name: string;
  gateway: string;
  interface: string;
  raw_weight: number;
  weight: number;
  online: boolean;
}

export interface BalanceSchedule {
  id: string;
  name: string;
  enabled: boolean;
  days: number[]; // 0=Sun .. 6=Sat
  at: string; // "HH:MM"
  weights: Record<string, number>; // link_id -> weight
}

export interface BalanceConfig {
  mode: 'failover' | 'balance';
  table: string;
  arm_seconds: number;
  schedules: BalanceSchedule[];
  evict_on_degrade: boolean;
  degraded_sustain_samples: number;
  evict_cooldown_seconds: number;
}

export interface BalancePlan {
  mode: 'failover' | 'balance';
  table: string;
  nexthops: BalanceNexthop[];
  excluded: BalanceNexthop[];
  command: string;
  current_default: string;
  pending: boolean;
  pending_expiry: number;
  arm_seconds: number;
}

export interface BalanceStatus {
  config: BalanceConfig;
  plan: BalancePlan;
}

export interface NetHost {
  ip: string;
  mac: string;
  interface: string;
  state: string;
  online: boolean;
  hostname?: string;
  alias?: string;
  blocked: boolean;
  first_seen?: string;
  last_seen?: string;
}

export interface TrafficHistoryPoint {
  interface: string;
  step_seconds: number;
  timestamp: number;
  /**
   * `null` é **não medido**, e nunca zero.
   *
   * O backend serializa isto como ponteiro e sem `omitempty`, de propósito
   * (`internal/tsdb`, commit 63dbd91): campo omitido desserializaria como `0`
   * aqui, que é o mesmo dado falso com outra cara. Um zero inventado faz um
   * link fora do ar parecer um link ocioso.
   */
  rx_bps: number | null;
  tx_bps: number | null;
}

export interface TrafficHistoryResponse {
  interface: string;
  range: string;
  step_seconds: number;
  points: TrafficHistoryPoint[];
}

export interface TrafficRetentionResponse {
  profile: '30d' | '1y' | '5y';
}

// ─── Monitoring (Vigia) ──────────────────────────────────────────────────────

export interface HealthItem { name: string; kind: 'service' | 'link' | 'resource'; up: boolean; since: number; }
export interface PendingPackage {
  name: string;
  current_version: string;
  new_version: string;
  origin: string;
  security: boolean;
}
export interface UpdatesReport { total: number; security: number; packages: PendingPackage[]; }
export interface MonitoringConfig {
  enabled: boolean;
  services: string[];
  disk_threshold_pct: number;
  smart_reallocated_threshold: number;
  smart_temp_threshold_c: number;
  boot_time_threshold_sec: number;
  journal_verify_interval_days: number;
}

// ─── Backup & Restore ──────────────────────────────────────────────────────

export interface RestoreResult {
  settings: number;
  reservations: number;
  blocklist: number;
  secrets_to_reconfigure: string[];
}

export interface BackupPassphraseStatusResponse {
  configured: boolean;
}

export type BackupSchedule = 'off' | 'daily' | 'weekly' | 'monthly';

export interface BackupScheduleResponse {
  schedule: BackupSchedule;
}

export interface BackupLastRunResponse {
  ok: boolean;
  error?: string;
  at: number; // unix seconds, 0 se nunca rodou
}

// ─── Assistente de IA (BYOK) ────────────────────────────────────────────────

export interface AIStatus {
  configured: boolean;
  hint: string;
  enabled: boolean;
  model: string;
  effort: string;
  monthly_budget_usd: number;
  spent_this_month_usd: number;
}

export interface AIConfig {
  enabled: boolean;
  model: string;
  effort: string;
  monthly_budget_usd: number;
  telemetry_consent: Record<string, boolean>;
  digest_hour: number;
}

// ─── Network interfaces (inventory) ─────────────────────────────────────────

export type IfaceKind = 'physical' | 'vlan' | 'bridge';
export type IfaceAddrMode = 'static' | 'dhcp' | 'none';
export type IfaceRole = 'wan' | 'lan' | 'unassigned';

export interface IfaceAddress {
  family: 'ipv4' | 'ipv6';
  ip: string;
  cidr: string;
}

export interface IfaceLiveState {
  carrier: boolean;
  mac?: string;
  mtu?: number;
  addresses?: IfaceAddress[];
  rx_errors: number;
  tx_errors: number;
  rx_dropped: number;
  tx_dropped: number;
  system: boolean;
}

export interface IfaceView {
  name: string;
  kind: IfaceKind;
  alias?: string;
  description?: string;
  parent?: string;
  vlan_id?: number;
  members?: string[];
  addr_mode: IfaceAddrMode;
  cidr?: string;
  gateway?: string;
  role: IfaceRole;
  managed: boolean;
  live: IfaceLiveState;
}

export interface StableNameEntry {
  interface: string;
  mac: string;
  link_name: string;
  stable_name: string;
}

export interface IfaceEdit {
  name: string;
  addr_mode: 'static' | 'dhcp' | 'none';
  cidr?: string;
  gateway?: string;
  description?: string;
}

export interface FileDiff {
  path: string;
  old_content: string;
  new_content: string;
}

export interface PreviewResult {
  files: FileDiff[];
  warnings: string[];
}

export interface PendingChange {
  interface: string;
  deadline_unix: number;
}

// ─── Captura de pacotes (issue #114) ─────────────────────────────────────────
// Só cabeçalho: o backend captura com snaplen curto e o parser descarta o
// texto que o tcpdump deriva de payload. Não existe campo de conteúdo aqui, e
// isso é proposital.

export interface CapturePacket {
  time: string;
  src: string;
  dst: string;
  proto: string;
  len: number;
  flags: string;
}

export interface CaptureCount {
  key: string;
  count: number;
  bytes: number;
}

export interface CaptureBucket {
  sec: number;
  packets: number;
  bytes: number;
}

export interface CaptureHandshake {
  src: string;
  dst: string;
  time: string;
  tries: number;
}

export interface CaptureSummary {
  packets: number;
  bytes: number;
  duration_sec: number;
  protos: CaptureCount[];
  pairs: CaptureCount[];
  ports: CaptureCount[];
  per_second: CaptureBucket[];
  unanswered: CaptureHandshake[];
  refused: CaptureHandshake[];
  unanswered_total: number;
  refused_total: number;
  retransmits: number;
}

export interface CaptureFilter {
  host: string;
  port: number;
  proto: string;
  direction: string;
}

export interface CaptureRun {
  id: string;
  interface: string;
  filter: CaptureFilter;
  filter_expr: string;
  duration_sec: number;
  max_packets: number;
  snaplen: number;
  state: string; // running | done | aborted | error
  message: string;
  started_by: string;
  started_at: string;
  ended_at: string;
  packets: CapturePacket[];
  rows_shown: number;
  truncated: boolean;
  summary: CaptureSummary;
  has_file: boolean;
  file_bytes: number;
}

export interface CaptureStatus {
  state: string; // idle quando nunca rodou
  available: boolean; // o tcpdump está instalado?
  limits: {
    max_duration_sec: number;
    max_packets: number;
    snaplen: number;
    file_ttl_sec: number;
  };
  capture?: CaptureRun;
}

// ─── Franquia por link (issue #126) ──────────────────────────────────────────
// limit_gb e o consumo são em GB DECIMAIS (10^9) — a unidade da fatura da
// operadora. Ver storage.LinkQuota no backend.

export interface LinkQuotaStatus {
  link_id: string;
  link_name: string;
  interface: string;
  configured: boolean;
  enabled: boolean;
  limit_gb: number;
  cycle_day: number;
  alert_pct: number;
  cycle_start: number;
  cycle_end: number;
  rx_bytes: number;
  tx_bytes: number;
  used_bytes: number;
  used_pct: number;
}

// ─── Registro de bloqueios (issue #122) ──────────────────────────────────────

export interface BlockLogEntry {
  time: string;
  kind: 'host' | 'dest';
  in: string;
  out: string;
  src: string;
  dst: string;
  proto: string;
  sport: string;
  dport: string;
}

// enabled vem junto da lista porque lista vazia com o registro DESLIGADO é
// "ninguém pediu para registrar", e com ele ligado é "nada foi bloqueado".
// São mensagens diferentes, e dizer a errada manda o admin procurar defeito
// onde não há.
export interface BlockLogResponse {
  enabled: boolean;
  entries: BlockLogEntry[];
}

// ─── DNS dinâmico por link (issue #129) ──────────────────────────────────────
// O segredo (token/senha do provedor) NUNCA volta do servidor: só existe
// secret_set, dizendo se há um guardado.

export interface DdnsState {
  link_id: string;
  public_ip: string;
  behind_nat: boolean;
  updated_at: number;
  last_error: string;
}

export interface DdnsView {
  link_id: string;
  enabled: boolean;
  hostname: string;
  url_template: string;
  username: string;
  state: DdnsState;
  link_name: string;
  interface: string;
  secret_set: boolean;
}

// ─── Cota por aparelho (issue #126) ──────────────────────────────────────────
// limit_gb e o consumo são em GB DECIMAIS (10^9). O consumo é medido dos
// contadores por endereço do nftables, que são IPv4 — a tela diz isso.
//
// Não existe campo de "cortar" nem de "limitar banda", e não é esquecimento:
// ver o cabeçalho de internal/hostquota no backend.

export type HostQuotaPeriod = 'monthly' | 'daily';

export interface HostQuotaStatus {
  mac: string;
  /** Apelido, com queda para nome de host, IP e MAC. */
  name: string;
  ip: string;
  configured: boolean;
  enabled: boolean;
  limit_gb: number;
  period: HostQuotaPeriod;
  cycle_day: number;
  alert_pct: number;
  cycle_start: number;
  cycle_end: number;
  rx_bytes: number;
  tx_bytes: number;
  used_bytes: number;
  used_pct: number;
  /** false = cota órfã: o aparelho não está mais no inventário. */
  present: boolean;
}

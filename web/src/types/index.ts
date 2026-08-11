// API type definitions for LinkGuard FW

export type LinkStatus = 'online' | 'offline' | 'degraded' | 'unknown';
export type AlertSeverity = 'info' | 'warning' | 'critical';

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

export interface NftUserRule {
  handle: number;
  raw: string;
  action: 'accept' | 'drop' | 'reject' | string;
  iif: string;
  oif: string;
  saddr: string;
  daddr: string;
  proto: string;
  dport: string;
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
  domain_suffix: string;
}
export interface DHCPReservation { mac: string; ip: string; hostname: string; created_at?: string; updated_at?: string; }
export interface DHCPLease { expiry: number; mac: string; ip: string; hostname: string; }
export interface LastApply { ok: boolean; error?: string; at: number; }
export interface DHCPData { config: NetsvcConfig; reservations: DHCPReservation[]; leases: DHCPLease[]; backend: string; last_apply?: LastApply; }
export interface DNSData { config: NetsvcConfig; blocklist: string[]; backend: string; last_apply?: LastApply; }

export interface NTPConfig { servers: string[]; timezone: string; serve_lan: boolean; allowed_networks: string[]; }
export interface NTPStatus { installed: boolean; synced: boolean; stratum?: number; offset_secs?: number; source?: string; }
export interface NTPData { config: NTPConfig; status: NTPStatus; timezones: string[]; last_apply?: LastApply; suggested_network: string; }

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
  rx_bps: number;
  tx_bps: number;
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

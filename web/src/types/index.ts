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
export interface DHCPData { config: NetsvcConfig; reservations: DHCPReservation[]; leases: DHCPLease[]; backend: string; }
export interface DNSData { config: NetsvcConfig; blocklist: string[]; backend: string; }

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

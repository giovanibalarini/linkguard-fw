import type { LinkStatus, AlertSeverity } from '../types';

interface StatusBadgeProps {
  status: LinkStatus | string;
  className?: string;
}

const statusConfig: Record<string, { label: string; color: string; dot: string }> = {
  online:   { label: 'Online',    color: 'bg-green-500/10 text-green-400 border-green-500/20',  dot: 'bg-green-400' },
  offline:  { label: 'Offline',   color: 'bg-red-500/10 text-red-400 border-red-500/20',        dot: 'bg-red-400' },
  degraded: { label: 'Degradado', color: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20', dot: 'bg-yellow-400' },
  unknown:  { label: 'Desconhecido', color: 'bg-gray-500/10 text-gray-400 border-gray-500/20',  dot: 'bg-gray-400' },
};

export default function StatusBadge({ status, className = '' }: StatusBadgeProps) {
  const cfg = statusConfig[status] ?? statusConfig.unknown;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${cfg.color} ${className}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot} animate-pulse`} />
      {cfg.label}
    </span>
  );
}

interface AlertBadgeProps {
  severity: AlertSeverity | string;
}

const severityConfig: Record<string, { label: string; color: string }> = {
  info:     { label: 'Info',     color: 'bg-blue-500/10 text-blue-400 border-blue-500/20' },
  warning:  { label: 'Aviso',    color: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20' },
  critical: { label: 'Crítico',  color: 'bg-red-500/10 text-red-400 border-red-500/20' },
};

export function AlertBadge({ severity }: AlertBadgeProps) {
  const cfg = severityConfig[severity] ?? severityConfig.info;
  return (
    <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${cfg.color}`}>
      {cfg.label}
    </span>
  );
}

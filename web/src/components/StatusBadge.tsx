import Tag, { type TagVariant } from './ui/Tag';
import type { LinkStatus, AlertSeverity } from '../types';

interface StatusBadgeProps {
  status: LinkStatus | string;
  className?: string;
}

const statusConfig: Record<string, { label: string; variant: TagVariant }> = {
  online: { label: 'Online', variant: 'ok' },
  offline: { label: 'Offline', variant: 'crit' },
  degraded: { label: 'Degradado', variant: 'warn' },
  unknown: { label: 'Desconhecido', variant: 'idle' },
};

export default function StatusBadge({ status, className = '' }: StatusBadgeProps) {
  const cfg = statusConfig[status] ?? statusConfig.unknown;
  return (
    <Tag variant={cfg.variant} dot className={className}>
      {cfg.label}
    </Tag>
  );
}

interface AlertBadgeProps {
  severity: AlertSeverity | string;
}

const severityConfig: Record<string, { label: string; variant: TagVariant }> = {
  info: { label: 'Info', variant: 'neutral' },
  warning: { label: 'Aviso', variant: 'warn' },
  critical: { label: 'Crítico', variant: 'crit' },
};

export function AlertBadge({ severity }: AlertBadgeProps) {
  const cfg = severityConfig[severity] ?? severityConfig.info;
  return <Tag variant={cfg.variant}>{cfg.label}</Tag>;
}

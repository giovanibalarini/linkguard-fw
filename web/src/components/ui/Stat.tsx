export type StatVariant = 'ok' | 'warn' | 'crit' | 'idle' | 'neutral';

interface StatProps {
  label: string;
  value: string | number;
  sub?: string;
  variant?: StatVariant;
}

const valueColor: Record<StatVariant, string> = {
  ok: 'text-emerald-400',
  warn: 'text-amber-400',
  crit: 'text-red-400',
  idle: 'text-gray-400',
  neutral: 'text-white',
};

export default function Stat({ label, value, sub, variant = 'neutral' }: StatProps) {
  return (
    <div className="card flex flex-col gap-1">
      <span className="text-gray-400 text-xs font-medium uppercase tracking-wide">{label}</span>
      <span className={`text-2xl font-bold ${valueColor[variant]}`}>{value}</span>
      {sub && <span className="text-gray-500 text-xs">{sub}</span>}
    </div>
  );
}

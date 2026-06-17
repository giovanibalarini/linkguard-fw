import type { LucideIcon } from 'lucide-react';

interface MetricCardProps {
  title: string;
  value: string | number;
  unit?: string;
  icon: LucideIcon;
  iconColor?: string;
  trend?: 'up' | 'down' | 'stable';
  subtitle?: string;
}

export default function MetricCard({
  title, value, unit, icon: Icon, iconColor = 'text-blue-400', subtitle
}: MetricCardProps) {
  return (
    <div className="card flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <span className="text-gray-400 text-sm font-medium">{title}</span>
        <div className={`p-2 bg-gray-800 rounded-lg ${iconColor}`}>
          <Icon className="w-4 h-4" />
        </div>
      </div>
      <div>
        <span className="text-2xl font-bold text-white">{value}</span>
        {unit && <span className="text-gray-400 text-sm ml-1">{unit}</span>}
      </div>
      {subtitle && <p className="text-gray-500 text-xs">{subtitle}</p>}
    </div>
  );
}

interface ProgressCardProps {
  title: string;
  percent: number;
  value: string;
  icon: LucideIcon;
  iconColor?: string;
}

export function ProgressCard({ title, percent, value, icon: Icon, iconColor = 'text-blue-400' }: ProgressCardProps) {
  const color = percent > 85 ? 'bg-red-500' : percent > 70 ? 'bg-yellow-500' : 'bg-blue-500';
  return (
    <div className="card flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <span className="text-gray-400 text-sm font-medium">{title}</span>
        <div className={`p-2 bg-gray-800 rounded-lg ${iconColor}`}>
          <Icon className="w-4 h-4" />
        </div>
      </div>
      <div className="flex items-end justify-between">
        <span className="text-2xl font-bold text-white">{percent.toFixed(1)}%</span>
        <span className="text-gray-500 text-xs">{value}</span>
      </div>
      <div className="w-full bg-gray-800 rounded-full h-1.5">
        <div className={`${color} h-1.5 rounded-full transition-all`} style={{ width: `${Math.min(percent, 100)}%` }} />
      </div>
    </div>
  );
}

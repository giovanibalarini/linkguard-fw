import type { ReactNode } from 'react';

export type TagVariant = 'ok' | 'warn' | 'crit' | 'idle' | 'neutral';

interface TagProps {
  variant: TagVariant;
  children: ReactNode;
  dot?: boolean;
  className?: string;
}

const variantStyles: Record<TagVariant, string> = {
  ok: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  warn: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  crit: 'bg-red-500/10 text-red-400 border-red-500/20',
  idle: 'bg-gray-500/10 text-gray-400 border-gray-500/20',
  neutral: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
};

const dotStyles: Record<TagVariant, string> = {
  ok: 'bg-emerald-400',
  warn: 'bg-amber-400',
  crit: 'bg-red-400',
  idle: 'bg-gray-400',
  neutral: 'bg-blue-400',
};

export default function Tag({ variant, children, dot = false, className = '' }: TagProps) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${variantStyles[variant]} ${className}`}
    >
      {dot && <span className={`w-1.5 h-1.5 rounded-full ${dotStyles[variant]} animate-pulse`} />}
      {children}
    </span>
  );
}

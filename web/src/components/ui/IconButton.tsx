import type { LucideIcon } from 'lucide-react';
import { Link } from 'react-router-dom';

interface IconButtonProps {
  icon: LucideIcon;
  // Either onClick (button) or to (real anchor via react-router Link) must
  // be provided. `to` is preferred for navigation actions so the browser's
  // native anchor affordances (middle-click/Ctrl-click to open in a new
  // tab, "copy link address", link semantics for a11y) keep working.
  onClick?: () => void;
  to?: string;
  label: string;
  variant?: 'default' | 'danger' | 'custom';
  disabled?: boolean;
  title?: string;
  className?: string;
}

export default function IconButton({ icon: Icon, onClick, to, label, variant = 'default', disabled, title, className }: IconButtonProps) {
  const colorClasses =
    variant === 'danger' ? 'text-gray-400 hover:text-red-400' :
    variant === 'custom' ? '' :
    'text-gray-400 hover:text-blue-400';
  const classes = `inline-flex items-center justify-center min-w-[44px] min-h-[44px] rounded-lg transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${colorClasses} ${className ?? ''}`;

  if (to && !disabled) {
    return (
      <Link to={to} aria-label={label} title={title ?? label} className={classes}>
        <Icon className="w-4 h-4" />
      </Link>
    );
  }

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      aria-label={label}
      title={title ?? label}
      className={classes}
    >
      <Icon className="w-4 h-4" />
    </button>
  );
}

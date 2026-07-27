import type { ReactNode } from 'react';

interface PanelProps {
  title?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}

export default function Panel({ title, action, children, className = '' }: PanelProps) {
  return (
    <div className={`card ${className}`}>
      {(title || action) && (
        <div className="flex items-center justify-between mb-4">
          {title &&
            (typeof title === 'string' ? (
              <h2 className="text-white font-semibold">{title}</h2>
            ) : (
              title
            ))}
          {action}
        </div>
      )}
      {children}
    </div>
  );
}

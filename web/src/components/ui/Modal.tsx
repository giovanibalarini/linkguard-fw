import type { ReactNode } from 'react';

interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
  size?: 'xs' | 'sm' | 'md' | 'lg';
  className?: string;
  action?: ReactNode;
  closeOnBackdropClick?: boolean;
}

const sizeClass: Record<NonNullable<ModalProps['size']>, string> = {
  xs: 'max-w-sm',
  sm: 'max-w-md',
  md: 'max-w-lg',
  lg: 'max-w-2xl',
};

export default function Modal({
  open, onClose, title, children, size = 'md', className = '', action, closeOnBackdropClick = false,
}: ModalProps) {
  if (!open) return null;
  return (
    <div
      className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4"
      onClick={closeOnBackdropClick ? onClose : undefined}
    >
      <div
        className={`w-full ${sizeClass[size]} max-h-[90vh] overflow-y-auto ${className}`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className={`px-6 py-4 border-b border-gray-800 ${action ? 'flex items-center justify-between' : ''}`}>
          {typeof title === 'string' ? <h2 className="text-white font-semibold">{title}</h2> : title}
          {action}
        </div>
        {children}
      </div>
    </div>
  );
}

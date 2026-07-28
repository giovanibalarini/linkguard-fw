import type { ReactNode } from 'react';

interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const sizeClass: Record<NonNullable<ModalProps['size']>, string> = {
  sm: 'max-w-md',
  md: 'max-w-lg',
  lg: 'max-w-2xl',
};

export default function Modal({ open, onClose, title, children, size = 'md', className = '' }: ModalProps) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className={`w-full ${sizeClass[size]} max-h-[90vh] overflow-y-auto ${className}`}>
        <div className="px-6 py-4 border-b border-gray-800">
          {typeof title === 'string' ? <h2 className="text-white font-semibold">{title}</h2> : title}
        </div>
        {children}
      </div>
    </div>
  );
}

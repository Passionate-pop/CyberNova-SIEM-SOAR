import type { ReactNode } from 'react';
import { X } from 'lucide-react';

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  size?: 'md' | 'lg' | 'xl';
}

const sizeMap = {
  md: 'max-w-lg',
  lg: 'max-w-2xl',
  xl: 'max-w-4xl',
};

export function Modal({ isOpen, onClose, title, children, size = 'lg' }: ModalProps) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div
        className={`relative ${sizeMap[size]} mx-4 w-full animate-slide-in rounded-2xl border border-cyber-border bg-cyber-surface shadow-2xl max-h-[85vh] flex flex-col`}
      >
        <div className="flex items-center justify-between border-b border-cyber-border px-6 py-4 shrink-0">
          <h2 className="text-lg font-semibold text-cyber-text">{title}</h2>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-cyber-muted hover:bg-cyber-border hover:text-cyber-text transition-colors"
          >
            <X size={18} />
          </button>
        </div>
        <div className="overflow-y-auto p-6">{children}</div>
      </div>
    </div>
  );
}

import { AlertTriangle } from 'lucide-react';

interface ConfirmDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  message: string;
  confirmLabel?: string;
  loading?: boolean;
}

export function ConfirmDialog({ isOpen, onClose, onConfirm, title, message, confirmLabel = 'Confirm', loading }: ConfirmDialogProps) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative mx-4 w-full max-w-md animate-slide-in rounded-2xl border border-cyber-border bg-cyber-surface shadow-2xl">
        <div className="p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="flex h-10 w-10 items-center justify-center rounded-full bg-amber-500/15">
              <AlertTriangle size={20} className="text-amber-400" />
            </div>
            <h3 className="text-lg font-semibold text-cyber-text">{title}</h3>
          </div>
          <p className="text-sm text-cyber-muted leading-relaxed">{message}</p>
        </div>
        <div className="flex items-center justify-end gap-3 border-t border-cyber-border px-6 py-4">
          <button
            onClick={onClose}
            disabled={loading}
            className="rounded-lg border border-cyber-border px-4 py-2 text-sm font-medium text-cyber-muted hover:bg-cyber-border/50 hover:text-cyber-text transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={loading}
            className="rounded-lg bg-red-600 px-4 py-2 text-sm font-semibold text-white hover:bg-red-700 transition-colors disabled:opacity-50"
          >
            {loading ? 'Executing...' : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

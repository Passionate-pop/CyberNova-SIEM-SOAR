import { cn } from '../../utils/cn';

const statusStyles: Record<string, string> = {
  open: 'bg-red-500/15 text-red-400 border-red-500/30',
  investigating: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  contained: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  closed: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  resolved: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  active: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  blocked: 'bg-red-500/15 text-red-400 border-red-500/30',
  pending: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  executing: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  completed: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  failed: 'bg-red-500/15 text-red-400 border-red-500/30',
};

export function StatusBadge({ status }: { status: string }) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider',
        statusStyles[status] || 'bg-slate-500/15 text-slate-400 border-slate-500/30'
      )}
    >
      {status}
    </span>
  );
}

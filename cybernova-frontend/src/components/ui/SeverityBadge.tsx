import type { Severity } from '../../types';
import { cn } from '../../utils/cn';

const severityStyles: Record<Severity, string> = {
  low: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  medium: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
};

export function SeverityBadge({ severity, size = 'sm' }: { severity: Severity; size?: 'sm' | 'md' }) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full border font-semibold uppercase tracking-wider',
        severityStyles[severity],
        size === 'sm' ? 'px-2 py-0.5 text-[10px]' : 'px-3 py-1 text-xs'
      )}
    >
      {severity === 'critical' && <span className="mr-1 h-1.5 w-1.5 rounded-full bg-red-400 animate-pulse" />}
      {severity}
    </span>
  );
}

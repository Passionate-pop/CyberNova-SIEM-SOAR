import { AlertTriangle, Shield, Eye, Zap, MessageSquare } from 'lucide-react';
import type { TimelineEvent } from '../../types';
import { SeverityBadge } from './SeverityBadge';
import { cn } from '../../utils/cn';

const typeConfig: Record<TimelineEvent['type'], { icon: React.ReactNode; color: string; bg: string }> = {
  alert: { icon: <AlertTriangle size={14} />, color: 'text-red-400', bg: 'bg-red-500/20 border-red-500/40' },
  detection: { icon: <Eye size={14} />, color: 'text-amber-400', bg: 'bg-amber-500/20 border-amber-500/40' },
  response: { icon: <Shield size={14} />, color: 'text-blue-400', bg: 'bg-blue-500/20 border-blue-500/40' },
  action: { icon: <Zap size={14} />, color: 'text-cyan-400', bg: 'bg-cyan-500/20 border-cyan-500/40' },
  note: { icon: <MessageSquare size={14} />, color: 'text-purple-400', bg: 'bg-purple-500/20 border-purple-500/40' },
};

export function Timeline({ events }: { events: TimelineEvent[] }) {
  return (
    <div className="relative space-y-0">
      {/* Timeline line */}
      <div className="absolute left-[17px] top-2 bottom-2 w-px bg-cyber-border" />

      {events.map((event, index) => {
        const config = typeConfig[event.type];
        return (
          <div key={event.id} className={cn('relative flex gap-4 pb-6', index === events.length - 1 && 'pb-0')}>
            {/* Dot */}
            <div className={cn('relative z-10 flex h-9 w-9 shrink-0 items-center justify-center rounded-full border', config.bg)}>
              <span className={config.color}>{config.icon}</span>
            </div>

            {/* Content */}
            <div className="min-w-0 flex-1 pt-0.5">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm font-semibold text-cyber-text">{event.title}</span>
                {event.severity && <SeverityBadge severity={event.severity} />}
              </div>
              <p className="mt-1 text-xs text-cyber-muted leading-relaxed">{event.description}</p>
              <p className="mt-1.5 text-[10px] font-mono text-cyber-muted/60">
                {new Date(event.timestamp).toLocaleString()}
              </p>
            </div>
          </div>
        );
      })}
    </div>
  );
}

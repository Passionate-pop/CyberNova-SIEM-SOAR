import type { ReactNode } from 'react';
import { cn } from '../../utils/cn';

interface CardProps {
  children: ReactNode;
  className?: string;
  title?: string;
  subtitle?: string;
  action?: ReactNode;
  noPadding?: boolean;
}

export function Card({ children, className, title, subtitle, action, noPadding }: CardProps) {
  return (
    <div
      className={cn(
        'rounded-xl border border-cyber-border bg-cyber-card/80 backdrop-blur-sm',
        className
      )}
    >
      {(title || action) && (
        <div className="flex items-center justify-between border-b border-cyber-border px-5 py-3.5">
          <div>
            {title && <h3 className="text-sm font-semibold text-cyber-text">{title}</h3>}
            {subtitle && <p className="mt-0.5 text-xs text-cyber-muted">{subtitle}</p>}
          </div>
          {action && <div>{action}</div>}
        </div>
      )}
      <div className={noPadding ? '' : 'p-5'}>{children}</div>
    </div>
  );
}

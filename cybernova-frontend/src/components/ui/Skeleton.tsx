import { cn } from '../../utils/cn';

interface SkeletonProps {
  className?: string;
  variant?: 'text' | 'circle' | 'rect';
  style?: React.CSSProperties;
}

export function Skeleton({ className, variant = 'text', style }: SkeletonProps) {
  return (
    <div
      className={cn(
        'animate-pulse rounded bg-cyber-border/40',
        variant === 'circle' && 'rounded-full',
        variant === 'rect' && 'rounded-lg',
        variant === 'text' && 'h-3',
        className
      )}
      style={style}
    />
  );
}

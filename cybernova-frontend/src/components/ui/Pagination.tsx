import { ChevronLeft, ChevronRight } from 'lucide-react';
import { cn } from '../../utils/cn';

interface PaginationProps {
  currentPage: number;
  totalPages: number;
  onPageChange: (page: number) => void;
  className?: string;
}

export function Pagination({ 
  currentPage, 
  totalPages, 
  onPageChange,
  className 
}: PaginationProps) {
  if (totalPages <= 1) return null;
  
  const pages = [];
  const maxVisible = 5;
  
  let start = Math.max(1, currentPage - Math.floor(maxVisible / 2));
  let end = Math.min(totalPages, start + maxVisible - 1);
  
  if (end - start < maxVisible - 1) {
    start = Math.max(1, end - maxVisible + 1);
  }
  
  for (let i = start; i <= end; i++) {
    pages.push(i);
  }
  
  return (
    <div className={cn('flex items-center gap-1', className)}>
      <button
        onClick={() => onPageChange(currentPage - 1)}
        disabled={currentPage === 1}
        className={cn(
          'flex items-center justify-center w-8 h-8 rounded-lg border text-xs',
          currentPage === 1 
            ? 'border-cyber-border text-cyber-muted cursor-not-allowed opacity-50'
            : 'border-cyber-border text-cyber-text hover:bg-cyber-accent/10 hover:text-cyber-accent'
        )}
      >
        <ChevronLeft size={14} />
      </button>
      
      {start > 1 && (
        <>
          <button
            onClick={() => onPageChange(1)}
            className="flex items-center justify-center w-8 h-8 rounded-lg border border-cyber-border text-xs text-cyber-text hover:bg-cyber-accent/10"
          >
            1
          </button>
          {start > 2 && (
            <span className="px-1 text-xs text-cyber-muted">...</span>
          )}
        </>
      )}
      
      {pages.map((page) => (
        <button
          key={page}
          onClick={() => onPageChange(page)}
          className={cn(
            'flex items-center justify-center w-8 h-8 rounded-lg border text-xs transition-colors',
            page === currentPage
              ? 'bg-cyber-accent border-cyber-accent text-white'
              : 'border-cyber-border text-cyber-text hover:bg-cyber-accent/10'
          )}
        >
          {page}
        </button>
      ))}
      
      {end < totalPages && (
        <>
          {end < totalPages - 1 && (
            <span className="px-1 text-xs text-cyber-muted">...</span>
          )}
          <button
            onClick={() => onPageChange(totalPages)}
            className="flex items-center justify-center w-8 h-8 rounded-lg border border-cyber-border text-xs text-cyber-text hover:bg-cyber-accent/10"
          >
            {totalPages}
          </button>
        </>
      )}
      
      <button
        onClick={() => onPageChange(currentPage + 1)}
        disabled={currentPage === totalPages}
        className={cn(
          'flex items-center justify-center w-8 h-8 rounded-lg border text-xs',
          currentPage === totalPages 
            ? 'border-cyber-border text-cyber-muted cursor-not-allowed opacity-50'
            : 'border-cyber-border text-cyber-text hover:bg-cyber-accent/10 hover:text-cyber-accent'
        )}
      >
        <ChevronRight size={14} />
      </button>
    </div>
  );
}
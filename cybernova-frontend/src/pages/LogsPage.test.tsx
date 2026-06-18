import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { LogsPage } from './LogsPage';

vi.mock('../hooks/useFetch', () => ({
  useFetch: vi.fn(),
}));

import { useFetch } from '../hooks/useFetch';

describe('LogsPage - empty & loading state', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('shows skeleton while loading', () => {
    (useFetch as any).mockReturnValue({ data: null, loading: true, refetch: vi.fn() });
    const { container } = render(<LogsPage />);
    expect(container.querySelector('.animate-pulse')).toBeTruthy();
  });

  it('shows empty state when no logs', () => {
    (useFetch as any).mockReturnValue({ data: [], loading: false, refetch: vi.fn() });
    render(<LogsPage />);
    // Should still render KPIs with 0 counts
    expect(screen.getByText('Total Logs')).toBeTruthy();
    expect(screen.getByText('0')).toBeTruthy();
  });
});

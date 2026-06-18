import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { AuditLogsPage } from './AuditLogsPage';

vi.mock('../hooks/useFetch', () => ({
  useFetch: vi.fn(),
}));

import { useFetch } from '../hooks/useFetch';

describe('AuditLogsPage - empty & loading state', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('shows skeleton while loading', () => {
    (useFetch as any).mockReturnValue({ data: null, loading: true, refetch: vi.fn() });
    const { container } = render(<AuditLogsPage />);
    expect(container.querySelector('.animate-pulse')).toBeTruthy();
  });

  it('shows empty state when no audit logs', () => {
    (useFetch as any).mockReturnValue({ data: [], loading: false, refetch: vi.fn() });
    render(<AuditLogsPage />);
    expect(screen.getByText('No audit logs found')).toBeTruthy();
  });
});

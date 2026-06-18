import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { IncidentsPage } from './IncidentsPage';

vi.mock('../hooks/useFetch', () => ({
  useFetch: vi.fn(),
}));

import { useFetch } from '../hooks/useFetch';

describe('IncidentsPage - empty state', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('shows skeleton while loading', () => {
    (useFetch as any).mockReturnValue({ data: null, loading: true, refetch: vi.fn() });
    const { container } = render(<IncidentsPage />);
    expect(container.querySelector('.animate-pulse')).toBeTruthy();
  });

  it('shows empty state when no incidents', () => {
    (useFetch as any).mockReturnValue({ data: [], loading: false, refetch: vi.fn() });
    render(<IncidentsPage />);
    expect(screen.getByText('No Active Incidents')).toBeTruthy();
    expect(screen.getByText(/All clear!/)).toBeTruthy();
  });
});

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { AlertsPage } from './AlertsPage';

// Mock the hooks and API
vi.mock('../hooks/useFetch', () => ({
  useFetch: vi.fn(),
}));

vi.mock('../hooks/useWebSocket', () => ({
  useWebSocket: vi.fn(),
}));

vi.mock('../stores/useAuthStore', () => ({
  useAuthStore: vi.fn(() => ({ token: 'test-token', user: { tenant_id: 'test-tenant' } })),
}));

import { useFetch } from '../hooks/useFetch';

describe('AlertsPage - empty state', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('shows skeleton while loading', () => {
    (useFetch as any).mockReturnValue({ data: null, loading: true, refetch: vi.fn() });
    const { container } = render(<AlertsPage />);
    // Should show skeleton/animated elements during loading
    expect(container.querySelector('.animate-pulse')).toBeTruthy();
  });

  it('shows empty state when no alerts', () => {
    (useFetch as any).mockReturnValue({ data: [], loading: false, refetch: vi.fn() });
    render(<AlertsPage />);
    expect(screen.getByText('No alerts found')).toBeTruthy();
    expect(screen.getByText(/Your system is monitoring/)).toBeTruthy();
  });
});

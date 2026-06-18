import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { DevicesPage } from './DevicesPage';

vi.mock('../hooks/useFetch', () => ({
  useFetch: vi.fn(),
}));

import { useFetch } from '../hooks/useFetch';

describe('DevicesPage - empty state', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('shows skeleton while loading', () => {
    (useFetch as any).mockReturnValue({ data: null, loading: true, refetch: vi.fn() });
    const { container } = render(<DevicesPage />);
    expect(container.querySelector('.animate-pulse')).toBeTruthy();
  });

  it('shows empty state when no devices', () => {
    (useFetch as any).mockReturnValue({ data: [], loading: false, refetch: vi.fn() });
    render(<DevicesPage />);
    expect(screen.getByText('No devices found')).toBeTruthy();
    expect(screen.getByText(/Install CyberNova agents/)).toBeTruthy();
  });
});

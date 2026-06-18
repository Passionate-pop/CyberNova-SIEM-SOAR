import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ThreatIntelPage } from './ThreatIntelPage';

vi.mock('../hooks/useFetch', () => ({
  useFetch: vi.fn(),
}));

import { useFetch } from '../hooks/useFetch';

describe('ThreatIntelPage - empty state', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('shows empty indicator state when no data in indicators tab', () => {
    (useFetch as any)
      .mockReturnValue({ data: [], loading: false, error: null, refetch: vi.fn() });
    
    render(<ThreatIntelPage />);
    expect(screen.getByText('No threat indicators')).toBeTruthy();
  });

  it('shows error state when fetch fails', () => {
    (useFetch as any)
      .mockReturnValue({ data: null, loading: false, error: 'Network error', refetch: vi.fn() });

    render(<ThreatIntelPage />);
    expect(screen.getByText('Unable to fetch threat data')).toBeTruthy();
  });
});

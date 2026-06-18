import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { UsersPage } from './UsersPage';

vi.mock('../hooks/useFetch', () => ({
  useFetch: vi.fn(),
}));

import { useFetch } from '../hooks/useFetch';

describe('UsersPage - empty state', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('shows skeleton while loading', () => {
    (useFetch as any).mockReturnValue({ data: null, loading: true, refetch: vi.fn() });
    const { container } = render(<UsersPage />);
    expect(container.querySelector('.animate-pulse')).toBeTruthy();
  });

  it('shows empty state when no users', () => {
    (useFetch as any).mockReturnValue({ data: [], loading: false, refetch: vi.fn() });
    render(<UsersPage />);
    expect(screen.getByText('No users found')).toBeTruthy();
    expect(screen.getByText(/Invite team members/)).toBeTruthy();
  });
});

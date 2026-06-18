/**
 * CyberNova - Auth Hook
 * Bridges local component state with global auth store
 */
import { useState, useCallback } from 'react';
import { useAuthStore } from '../stores/useAuthStore';
import { login, registerUser } from '../services/api';

export function useAuth() {
  const { user, isAuthenticated, isLoading, setUser, logout } = useAuthStore();
  const [localLoading, setLocalLoading] = useState(false);

  const loginUser = useCallback(async (credentials: { username: string; password: string }) => {
    setLocalLoading(true);
    try {
      const userData = await login(credentials);
      setUser(userData);
      return userData;
    } finally {
      setLocalLoading(false);
    }
  }, [setUser]);

  const registerNewUser = useCallback(async (
    username: string,
    email: string,
    password: string,
    role: 'admin' | 'analyst' | 'viewer' = 'viewer'
  ) => {
    setLocalLoading(true);
    try {
      const userData = await registerUser(username, email, password, role);
      setUser(userData);
      return userData;
    } finally {
      setLocalLoading(false);
    }
  }, [setUser]);

  const handleLogout = useCallback(() => {
    logout();
  }, [logout]);

  return {
    user,
    isAuthenticated,
    isLoading: isLoading || localLoading,
    loginUser,
    registerNewUser,
    logout: handleLogout,
    // Permission helpers
    hasPermission: useAuthStore.getState().hasPermission,
    isAdmin: useAuthStore.getState().isAdmin,
    isAnalyst: useAuthStore.getState().isAnalyst,
    isViewer: useAuthStore.getState().isViewer,
  };
}
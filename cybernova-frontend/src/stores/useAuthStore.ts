/**
 * CyberNova - Auth Store
 * Manages authentication state globally
 */
import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { User, UserRole } from '../types';
import { registerUser as registerUserAPI } from '../services/api';
import { hasPermission as checkPermission } from '../utils/permissions';

interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
}

interface AuthActions {
  setUser: (user: User | null) => void;
  setToken: (token: string | null) => void;
  logout: () => void;
  registerNewUser: (username: string, email: string, password: string, role: UserRole, orgKey?: string) => Promise<User>;
  hasPermission: (permission: string) => boolean;
  isRole: (role: UserRole) => boolean;
  isAdmin: () => boolean;
  isAnalyst: () => boolean;
  isViewer: () => boolean;
  isAdminOrAnalyst: () => boolean;
}

export const useAuthStore = create<AuthState & AuthActions>()(
  persist(
    (set, get) => ({
      // State
      user: null,
      token: null,
      isAuthenticated: false,
      isLoading: true,

      // Actions
      setUser: (user) => set({
        user,
        token: user?.token || null,
        isAuthenticated: !!user?.token,
      }),
      
      setToken: (token) => set({ token }),

      logout: () => set({
        user: null,
        token: null,
        isAuthenticated: false,
      }),

      registerNewUser: async (username, email, password, role, orgKey) => {
        const user = await registerUserAPI(username, email, password, role, orgKey);
        set({ user, token: user.token, isAuthenticated: true });
        return user;
      },

      // Permission helpers — delegates entirely to utils/permissions.ts
      hasPermission: (permission) => {
        const { user } = get();
        return checkPermission(user, permission);
      },

      isRole: (role) => {
        const { user } = get();
        return user?.role === role;
      },

      isAdmin: () => {
        const { user } = get();
        return user?.role === 'admin';
      },

      isAnalyst: () => {
        const { user } = get();
        return user?.role === 'analyst';
      },

      isViewer: () => {
        const { user } = get();
        return user?.role === 'viewer';
      },

      isAdminOrAnalyst: () => {
        const { user } = get();
        return user?.role === 'admin' || user?.role === 'analyst';
      },
    }),
    {
      name: 'cybernova-auth',
      partialize: (state) => ({
        user: state.user,
        token: state.token,
        isAuthenticated: state.isAuthenticated,
      }),
      // After rehydrating from localStorage, mark loading as complete
      onRehydrateStorage: () => (state) => {
        if (state) {
          state.isLoading = false;
        }
      },
    }
  )
);
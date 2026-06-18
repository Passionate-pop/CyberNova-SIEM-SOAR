/**
 * CyberNova - Global UI State Store
 * Manages sidebar state, notifications, and other global UI state
 */
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface UIState {
  sidebarCollapsed: boolean;
  notifications: {
    unread: number;
    lastFetched: string | null;
  };
}

interface UIActions {
  setSidebarCollapsed: (collapsed: boolean) => void;
  toggleSidebar: () => void;
  incrementUnread: () => void;
  markNotificationsRead: () => void;
}

export const useUIStore = create<UIState & UIActions>()(
  persist(
    (set, _get) => ({
      // State
      sidebarCollapsed: false,
      notifications: {
        unread: 0,
        lastFetched: null,
      },

      // Actions
      setSidebarCollapsed: (collapsed) => set({ sidebarCollapsed: collapsed }),
      
      toggleSidebar: () => set((state) => ({
        sidebarCollapsed: !state.sidebarCollapsed,
      })),
      
      incrementUnread: () => set((state) => ({
        notifications: {
          ...state.notifications,
          unread: state.notifications.unread + 1,
        },
      })),
      
      markNotificationsRead: () => set((state) => ({
        notifications: {
          ...state.notifications,
          unread: 0,
          lastFetched: new Date().toISOString(),
        },
      })),
    }),
    {
      name: 'cybernova-ui',
      partialize: (state) => ({
        sidebarCollapsed: state.sidebarCollapsed,
        notifications: {
          unread: state.notifications.unread,
          lastFetched: state.notifications.lastFetched,
        },
      }),
    }
  )
);
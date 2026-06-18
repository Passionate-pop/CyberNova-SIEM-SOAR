import { useState, useCallback, useEffect } from 'react';
import { Search, ExternalLink, User, Shield, Crown, Eye, Loader2, CheckCircle, XCircle } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Modal } from '../components/ui/Modal';
import { useFetch } from '../hooks/useFetch';
import { fetchUsers, updateUserRole, disableUser } from '../services/api';
import { ConfirmDialog } from '../components/ui/ConfirmDialog';
import type { User as UserType, UserRole } from '../types';

const ROLES: UserRole[] = ['admin', 'analyst', 'viewer'];

const roleColors: Record<UserRole, string> = {
  admin: 'text-purple-400 bg-purple-500/10 border-purple-500/30',
  viewer: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
  analyst: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30',
};

const roleIcons: Record<UserRole, React.ReactNode> = {
  admin: <Crown size={12} />,
  viewer: <Eye size={12} />,
  analyst: <Shield size={12} />,
};

export function UsersPage() {
  const { data: users, loading, refetch: refetchUsers } = useFetch(useCallback(() => fetchUsers(), []));
  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState<UserRole | 'all'>('all');
  const [selectedUser, setSelectedUser] = useState<UserType | null>(null);
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null);
  const [confirmAction, setConfirmAction] = useState<{ type: 'change_role' | 'disable_user'; user: UserType; newRole?: UserRole } | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  // Auto-dismiss toast
  useEffect(() => {
    if (toast) {
      const timer = setTimeout(() => setToast(null), 4000);
      return () => clearTimeout(timer);
    }
  }, [toast]);

  const handleConfirmAction = async () => {
    if (!confirmAction) return;

    if (confirmAction.type === 'change_role' && confirmAction.newRole) {
      setActionLoading('role');
      try {
        await updateUserRole(confirmAction.user.id, [confirmAction.newRole]);
        setToast({ message: `Role changed to ${confirmAction.newRole} for ${confirmAction.user.username}`, type: 'success' });
        refetchUsers();
        setSelectedUser(null);
      } catch (e) {
        setToast({ message: `Failed to change role: ${e instanceof Error ? e.message : 'unknown error'}`, type: 'error' });
      } finally {
        setActionLoading(null);
        setConfirmAction(null);
      }
    }

    if (confirmAction.type === 'disable_user') {
      setActionLoading('disable');
      try {
        await disableUser(confirmAction.user.id);
        setToast({ message: `User ${confirmAction.user.username} disabled`, type: 'success' });
        refetchUsers();
        setSelectedUser(null);
      } catch (e) {
        setToast({ message: `Failed to disable user: ${e instanceof Error ? e.message : 'unknown error'}`, type: 'error' });
      } finally {
        setActionLoading(null);
        setConfirmAction(null);
      }
    }
  };

  if (loading && !users) {
    return (
      <div className="space-y-6">
        {/* KPI skeleton */}
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="rounded-xl border border-cyber-border bg-cyber-card/50 p-4">
              <div className="animate-pulse h-3 w-12 bg-cyber-border/60 rounded mb-2" />
              <div className="animate-pulse h-8 w-16 bg-cyber-border/60 rounded" />
            </div>
          ))}
        </div>
        {/* Table skeleton */}
        <div className="rounded-xl border border-cyber-border bg-cyber-card/80 overflow-hidden">
          <div className="flex items-center gap-3 border-b border-cyber-border px-5 py-3">
            <div className="animate-pulse h-8 w-56 bg-cyber-border/60 rounded-lg" />
            <div className="animate-pulse h-8 w-28 bg-cyber-border/60 rounded-lg" />
            <div className="animate-pulse h-3 w-16 bg-cyber-border/60 rounded" />
          </div>
          <div className="p-5 space-y-4">
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="flex gap-4">
                <div className="animate-pulse h-4 w-28 bg-cyber-border/40 rounded" />
                <div className="animate-pulse h-4 w-20 bg-cyber-border/40 rounded" />
                <div className="animate-pulse h-4 w-24 bg-cyber-border/40 rounded" />
                <div className="animate-pulse h-4 w-28 bg-cyber-border/40 rounded" />
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }
  if (!users) return (
    <div className="flex flex-col items-center justify-center h-96 space-y-4">
      <div className="w-20 h-20 rounded-full bg-blue-500/10 flex items-center justify-center">
        <User size={40} className="text-blue-400" />
      </div>
      <h3 className="text-xl font-semibold text-cyber-text">No User Data Available</h3>
      <p className="text-sm text-cyber-muted max-w-md text-center">
        User accounts will appear here once the backend is connected. Ensure the API server is running.
      </p>
    </div>
  );

  const filtered = users
    .filter((u) => {
      if (roleFilter !== 'all' && u.role !== roleFilter) return false;
      if (search) {
        const s = search.toLowerCase();
        return u.username.toLowerCase().includes(s);
      }
      return true;
    });

  const adminCount = users.filter(u => u.role === 'admin').length;
  const viewerCount = users.filter(u => u.role === 'viewer').length;

  return (
    <div className="space-y-6">
      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
        <div className="rounded-xl border bg-cyber-card/50 px-4 py-3 border-cyber-border">
          <p className="text-2xl font-bold text-cyber-text">{users.length}</p>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Total Users</p>
        </div>
        <div className="rounded-xl border bg-purple-500/10 border-purple-500/30 px-4 py-3">
          <p className="text-2xl font-bold text-purple-400">{adminCount}</p>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-purple-400">Admins</p>
        </div>
        <div className="rounded-xl border bg-blue-500/10 border-blue-500/30 px-4 py-3">
          <p className="text-2xl font-bold text-blue-400">{viewerCount}</p>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-blue-400">Viewers</p>
        </div>
      </div>

      {/* Filters */}
      <Card noPadding>
        <div className="flex flex-wrap items-center gap-3 border-b border-cyber-border px-5 py-3">
          <div className="relative flex-1 min-w-[200px]">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-cyber-muted" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search users by name..."
              className="w-full rounded-lg border border-cyber-border bg-cyber-bg py-2 pl-9 pr-4 text-xs text-cyber-text placeholder-cyber-muted focus:border-cyber-accent focus:outline-none"
            />
          </div>
          <div className="flex items-center gap-2">
            <select
              value={roleFilter}
              onChange={(e) => setRoleFilter(e.target.value as UserRole | 'all')}
              className="rounded-lg border border-cyber-border bg-cyber-bg px-3 py-2 text-xs text-cyber-text focus:border-cyber-accent focus:outline-none appearance-none cursor-pointer"
            >
              <option value="all">All Roles</option>
              <option value="admin">Admin</option>
              <option value="analyst">Analyst</option>
              <option value="viewer">Viewer</option>
            </select>
          </div>
          <span className="text-xs text-cyber-muted">{filtered.length} users</span>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-cyber-border text-left">
                <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Name</th>
                <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Role</th>
                <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">User ID</th>
                <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Last Login</th>
                <th className="px-5 py-3"></th>
              </tr>
            </thead>
            <tbody>
              {filtered.length > 0 ? (
                filtered.map((user) => (
                  <tr
                    key={user.id}
                    className="border-b border-cyber-border/50 hover:bg-cyber-accent/5 transition-colors cursor-pointer"
                    onClick={() => setSelectedUser(user)}
                  >
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-2">
                        <div className="flex h-8 w-8 items-center justify-center rounded-full bg-cyber-border">
                          <User size={16} className="text-cyber-muted" />
                        </div>
                        <span className="font-medium text-cyber-text">{user.username}</span>
                      </div>
                    </td>
                    <td className="px-5 py-3">
                      <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs border ${roleColors[user.role as UserRole]}`}>
                        {roleIcons[user.role as UserRole]}
                        <span className="capitalize">{user.role}</span>
                      </span>
                    </td>
                    <td className="px-5 py-3 text-xs text-cyber-muted font-mono">{user.id}</td>
                    <td className="px-5 py-3 text-xs text-cyber-muted font-mono">-</td>
                    <td className="px-5 py-3">
                      <ExternalLink size={14} className="text-cyber-muted hover:text-cyber-accent" />
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5} className="px-5 py-16 text-center">
                    <div className="flex flex-col items-center gap-4">
                      <div className="flex items-center justify-center w-16 h-16 rounded-full bg-cyber-accent/10">
                        <User size={32} className="text-cyber-accent" />
                      </div>
                      <div>
                        <p className="text-sm font-medium text-cyber-text">No users found</p>
                        <p className="text-xs text-cyber-muted mt-1">Invite team members to collaborate.</p>
                      </div>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Confirm Action Dialog */}
      <ConfirmDialog
        isOpen={!!confirmAction}
        onClose={() => setConfirmAction(null)}
        onConfirm={handleConfirmAction}
        title={confirmAction?.type === 'change_role' ? 'Change User Role' : 'Disable User'}
        message={
          confirmAction?.type === 'change_role'
            ? `Are you sure you want to change ${confirmAction?.user?.username}'s role from ${confirmAction?.user?.role} to ${confirmAction?.newRole}?`
            : `Are you sure you want to disable user ${confirmAction?.user?.username}? This will prevent them from logging in.`
        }
        confirmLabel={confirmAction?.type === 'change_role' ? 'Change Role' : 'Disable'}
        loading={actionLoading === 'role' || actionLoading === 'disable'}
      />

      {/* User Detail Modal */}
      <Modal
        isOpen={!!selectedUser}
        onClose={() => setSelectedUser(null)}
        title={`User: ${selectedUser?.username || ''}`}
        size="lg"
      >
        {selectedUser && (
          <>
          <div className="space-y-6">
            <div className="flex items-center gap-3">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-cyber-border">
                <User size={24} className="text-cyber-muted" />
              </div>
              <div>
                <p className="text-lg font-medium text-cyber-text">{selectedUser.username}</p>
                <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs border ${roleColors[selectedUser.role as UserRole]}`}>
                  {roleIcons[selectedUser.role as UserRole]}
                  <span className="capitalize">{selectedUser.role}</span>
                </span>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="rounded-lg border border-cyber-border bg-cyber-bg/50 px-4 py-3">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">User ID</p>
                <p className="mt-1 text-sm text-cyber-text font-mono">{selectedUser.id}</p>
              </div>
              <div className="rounded-lg border border-cyber-border bg-cyber-bg/50 px-4 py-3">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Role</p>
                <p className="mt-1 text-sm text-cyber-text flex items-center gap-2">
                  {selectedUser.role === 'admin' ? <Crown size={14} className="text-purple-400" /> : <Eye size={14} className="text-blue-400" />}
                  <span className="capitalize">{selectedUser.role}</span>
                </p>
              </div>
            </div>

            {/* Role Selection */}
            <div className="space-y-2">
              <p className="text-xs font-semibold uppercase tracking-wider text-cyber-muted">Current Role</p>
              <div className="flex flex-wrap gap-2">
                {ROLES.map((r) => (
                  <button
                    key={r}
                    onClick={() => {
                      if (r !== selectedUser.role) {
                        setConfirmAction({ type: 'change_role', user: selectedUser, newRole: r });
                      }
                    }}
                    disabled={r === selectedUser.role}
                    className={`flex items-center gap-1.5 rounded-full px-3 py-1.5 text-xs border transition-colors ${
                      r === selectedUser.role
                        ? `${roleColors[r]} cursor-default`
                        : 'border-cyber-border text-cyber-muted hover:text-cyber-text hover:border-cyber-accent/50'
                    }`}
                  >
                    {roleIcons[r]}
                    <span className="capitalize">{r}</span>
                  </button>
                ))}
              </div>
            </div>

            <div className="flex gap-3 pt-2 border-t border-cyber-border">
              <button
                onClick={() => setConfirmAction({ type: 'disable_user', user: selectedUser })}
                disabled={actionLoading === 'disable'}
                className="flex items-center gap-2 rounded-lg bg-red-500/20 border border-red-500/30 px-4 py-2 text-sm text-red-400 hover:bg-red-500/30 transition-colors disabled:opacity-50"
              >
                {actionLoading === 'disable' ? <Loader2 size={16} className="animate-spin" /> : <Shield size={16} />}
                Disable User
              </button>
            </div>
          </div>


          </>
        )}
      </Modal>

      {/* Toast notification */}
      {toast && (
        <div className={`fixed bottom-6 right-6 z-[100] flex items-center gap-2 rounded-lg border px-4 py-3 shadow-xl text-sm animate-slide-in ${
          toast.type === 'success' ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400' : 'border-red-500/30 bg-red-500/10 text-red-400'
        }`}>
          {toast.type === 'success' ? <CheckCircle size={16} /> : <XCircle size={16} />}
          {toast.message}
        </div>
      )}
    </div>
  );
}
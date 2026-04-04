import { create } from 'zustand';

function safeSessionGet(key) {
  try {
    return sessionStorage.getItem(key);
  } catch {
    return null;
  }
}

function safeSessionSet(key, value) {
  try {
    sessionStorage.setItem(key, value);
  } catch {
    // Ignore storage failures so the app can still render.
  }
}

function safeSessionRemove(key) {
  try {
    sessionStorage.removeItem(key);
  } catch {
    // Ignore storage failures so logout still clears in-memory state.
  }
}

const useStore = create((set, get) => ({
  // ─── Auth State ───────────────────────────────────────────────
  wallet: safeSessionGet('sentinelx_wallet') || null,
  token: safeSessionGet('sentinelx_token') || null,
  isAuthenticated: !!safeSessionGet('sentinelx_token'),
  riskLevel: null,
  riskScore: null,

  // ─── Security Enforcement State ─────────────────────────────
  securityStatus: 'active',  // active, step_up_required, restricted, locked
  trustScore: null,
  lockedUntil: null,

  setAuth: (wallet, token, riskLevel, riskScore) => {
    safeSessionSet('sentinelx_token', token);
    safeSessionSet('sentinelx_wallet', wallet);
    set({
      wallet,
      token,
      isAuthenticated: true,
      riskLevel,
      riskScore,
    });
  },

  setEnforcement: (enforcement) => {
    if (!enforcement) return;
    set({
      securityStatus: enforcement.security_status || 'active',
      trustScore: enforcement.trust_score ?? null,
      lockedUntil: enforcement.locked_until || null,
    });
  },

  logout: () => {
    safeSessionRemove('sentinelx_token');
    safeSessionRemove('sentinelx_wallet');
    set({
      wallet: null,
      token: null,
      isAuthenticated: false,
      riskLevel: null,
      riskScore: null,
      dashboardData: null,
      securityStatus: 'active',
      trustScore: null,
      lockedUntil: null,
    });
  },

  // ─── Dashboard State ──────────────────────────────────────────
  dashboardData: null,
  isLoading: false,

  setDashboardData: (data) => set({ dashboardData: data }),
  setLoading: (loading) => set({ isLoading: loading }),

  // ─── Notifications ────────────────────────────────────────────
  notifications: [],

  addNotification: (notification) => {
    const id = Date.now();
    set((state) => ({
      notifications: [...state.notifications, { ...notification, id }],
    }));
    // Auto-remove after 5 seconds
    setTimeout(() => {
      set((state) => ({
        notifications: state.notifications.filter((n) => n.id !== id),
      }));
    }, 5000);
  },

  removeNotification: (id) =>
    set((state) => ({
      notifications: state.notifications.filter((n) => n.id !== id),
    })),
}));

export default useStore;

import { create } from 'zustand';

const useStore = create((set, get) => ({
  // ─── Auth State ───────────────────────────────────────────────
  wallet: null,
  token: localStorage.getItem('sentinelx_token') || null,
  isAuthenticated: !!localStorage.getItem('sentinelx_token'),
  riskLevel: null,
  riskScore: null,

  setAuth: (wallet, token, riskLevel, riskScore) => {
    localStorage.setItem('sentinelx_token', token);
    localStorage.setItem('sentinelx_wallet', wallet);
    set({
      wallet,
      token,
      isAuthenticated: true,
      riskLevel,
      riskScore,
    });
  },

  logout: () => {
    localStorage.removeItem('sentinelx_token');
    localStorage.removeItem('sentinelx_wallet');
    set({
      wallet: null,
      token: null,
      isAuthenticated: false,
      riskLevel: null,
      riskScore: null,
      dashboardData: null,
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

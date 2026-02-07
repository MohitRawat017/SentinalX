import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add auth token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('sentinelx_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// ─── Auth ───────────────────────────────────────────────────────
export const authAPI = {
  getNonce: () => api.get('/auth/nonce'),
  verify: (data) => api.post('/auth/verify', data),
  getSession: () => api.get('/auth/session'),
  challenge: (data) => api.post('/auth/challenge', data),
  logout: () => api.post('/auth/logout'),
};

// ─── Risk ───────────────────────────────────────────────────────
export const riskAPI = {
  score: (data) => api.post('/risk/score', data),
  timeline: (wallet) => api.get('/risk/timeline', { params: { wallet_address: wallet } }),
  map: (wallet) => api.get('/risk/map', { params: { wallet_address: wallet } }),
  stats: (wallet) => api.get('/risk/stats', { params: { wallet_address: wallet } }),
};

// ─── Guard ──────────────────────────────────────────────────────
export const guardAPI = {
  scan: (data) => api.post('/guard/scan', data),
  override: (data) => api.post('/guard/override', data),
  events: (wallet) => api.get('/guard/events', { params: { wallet_address: wallet } }),
  stats: (wallet) => api.get('/guard/stats', { params: { wallet_address: wallet } }),
};

// ─── Audit ──────────────────────────────────────────────────────
export const auditAPI = {
  stats: () => api.get('/audit/stats'),
  batches: () => api.get('/audit/batches'),
  createBatch: () => api.post('/audit/batch', { force: true }),
  getProof: (root, hash) => api.get(`/audit/proof/${root}/${hash}`),
  verify: (data) => api.post('/audit/verify', data),
  pending: () => api.get('/audit/pending'),
};

// ─── Simulation ─────────────────────────────────────────────────
export const simulationAPI = {
  run: (data) => api.post('/simulation/run', data),
  scenarios: () => api.get('/simulation/scenarios'),
};

// ─── Dashboard ──────────────────────────────────────────────────
export const dashboardAPI = {
  overview: (wallet) => api.get('/dashboard/overview', { params: { wallet_address: wallet } }),
  securityReport: (wallet) => api.get('/dashboard/security-report', { params: { wallet_address: wallet } }),
};

// ─── Chat ───────────────────────────────────────────────────────
export const chatAPI = {
  send: (data) => api.post('/chat/send', data),
  redact: (data) => api.post('/chat/redact', data),
  messages: (wallet, peer, limit = 50) =>
    api.get('/chat/messages', { params: { wallet, peer, limit } }),
  contacts: (wallet) =>
    api.get('/chat/contacts', { params: { wallet } }),
  wsUrl: (wallet) => {
    const base = API_BASE.replace(/^http/, 'ws');
    return `${base}/chat/ws/${wallet}`;
  },
};

export default api;

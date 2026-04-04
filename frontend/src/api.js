import axios from 'axios';

const configuredApiUrl = import.meta.env.VITE_API_URL?.trim();
const isProductionApiConfigured = Boolean(configuredApiUrl);
const isLoopbackUrl = /^(https?:\/\/)?(localhost|127(?:\.\d{1,3}){3}|\[::1\])(?::\d+)?(\/|$)/i.test(
  configuredApiUrl || '',
);
const API_BASE =
  configuredApiUrl && (!import.meta.env.PROD || !isLoopbackUrl)
    ? configuredApiUrl.replace(/\/+$/, '')
    : import.meta.env.PROD
      ? ''
      : 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

function buildMissingApiUrlMessage() {
  return 'Production frontend is missing VITE_API_URL. Point it to the FastAPI backend, rebuild, and redeploy.';
}

function isLikelyFrontendRewriteResponse(response) {
  if (!response || import.meta.env.DEV || isProductionApiConfigured) {
    return false;
  }

  const contentType =
    response.headers?.['content-type'] ||
    response.headers?.['Content-Type'] ||
    '';

  return typeof response.data === 'string' && contentType.includes('text/html');
}

// Add auth token to requests
api.interceptors.request.use((config) => {
  let token = null;

  try {
    token = sessionStorage.getItem('sentinelx_token');
  } catch {
    token = null;
  }

  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => {
    if (isLikelyFrontendRewriteResponse(response)) {
      const configError = new Error(buildMissingApiUrlMessage());
      configError.data = { type: 'API_CONFIG' };
      configError.response = response;
      throw configError;
    }

    return response;
  },
  (error) => {
    if (error.code === 'ECONNABORTED') {
      error.message = 'The SentinelX backend did not respond in time. Check your API URL or backend status.';
    }

    if (
      !import.meta.env.DEV &&
      !isProductionApiConfigured &&
      (error.response?.status === 404 || isLikelyFrontendRewriteResponse(error.response))
    ) {
      error.message = buildMissingApiUrlMessage();
      error.data = { type: 'API_CONFIG' };
    }

    return Promise.reject(error);
  },
);

// ─── Auth ───────────────────────────────────────────────────────
export const authAPI = {
  getNonce: () => api.get('/auth/nonce'),
  verify: (data) => api.post('/auth/verify', data),
  getSession: () => api.get('/auth/session'),
  challenge: (data) => api.post('/auth/challenge', data),
  stepUpVerify: (data) => api.post('/auth/step-up-verify', data),
  logout: () => api.post('/auth/logout'),
  securityState: (wallet) => api.get('/auth/security-state', { params: { wallet_address: wallet } }),
  refreshSecurityState: (wallet) => api.post('/auth/security-state/refresh', null, { params: { wallet_address: wallet } }),
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
  trustScore: (wallet) => api.get('/dashboard/trust-score', { params: { wallet_address: wallet } }),
};

// ─── Transactions ───────────────────────────────────────────────
export const transactionAPI = {
  evaluate: (data) => api.post('/transactions/evaluate', data),
  confirm: (data) => api.post('/transactions/confirm', data),
  history: (wallet, limit = 50) =>
    api.get('/transactions/history', { params: { wallet, limit } }),
  stats: (wallet) => api.get('/transactions/stats', { params: { wallet } }),
};

// ─── Chat ───────────────────────────────────────────────────────
export const chatAPI = {
  conversations: (wallet) =>
    api.get('/chat/conversations', { params: { wallet } }),
  messages: (conversationId, limit = 50) =>
    api.get(`/chat/conversations/${conversationId}/messages`, { params: { limit } }),
  wsUrl: (token) => {
    const base = API_BASE.replace(/^http/, 'ws');
    return `${base}/chat/ws?token=${encodeURIComponent(token)}`;
  },
};

export default api;

/**
 * SentinelX SDK — Authentication Module
 * Drop-in wallet-based authentication for any web app
 */

export class SentinelXAuth {
  constructor(config = {}) {
    this.apiUrl = config.apiUrl || 'http://localhost:8000';
    this.appId = config.appId || 'default';
    this.token = null;
    this.wallet = null;
    this.onAuth = config.onAuth || null;
    this.onRisk = config.onRisk || null;
  }

  /**
   * Connect wallet and authenticate via SIWE
   * @returns {Promise<Object>} Auth result with token, risk score, etc.
   */
  async login() {
    if (typeof window === 'undefined' || !window.ethereum) {
      throw new Error('MetaMask or compatible wallet not found');
    }

    // Request account access
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
    const wallet = accounts[0];

    // Get nonce from SentinelX backend
    const nonceRes = await fetch(`${this.apiUrl}/auth/nonce`);
    const { nonce } = await nonceRes.json();

    // Create SIWE message
    const message = [
      `${window.location.host} wants you to sign in with your Ethereum account:`,
      wallet,
      '',
      'Sign in to SentinelX-powered application',
      '',
      `URI: ${window.location.origin}`,
      'Version: 1',
      'Chain ID: 11155111',
      `Nonce: ${nonce}`,
      `Issued At: ${new Date().toISOString()}`,
    ].join('\n');

    // Request signature
    const signature = await window.ethereum.request({
      method: 'personal_sign',
      params: [message, wallet],
    });

    // Verify with backend
    const verifyRes = await fetch(`${this.apiUrl}/auth/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message,
        signature,
        wallet_address: wallet,
        user_agent: navigator.userAgent,
      }),
    });

    const result = await verifyRes.json();

    if (result.success) {
      this.token = result.token;
      this.wallet = result.wallet_address;

      if (this.onAuth) this.onAuth(result);
      if (this.onRisk && result.risk_score > 0.5) this.onRisk(result);
    }

    return result;
  }

  /**
   * Check if current session is valid
   */
  async checkSession() {
    if (!this.token) return { valid: false };

    const res = await fetch(`${this.apiUrl}/auth/session`, {
      headers: { Authorization: `Bearer ${this.token}` },
    });
    return res.json();
  }

  /**
   * Logout
   */
  logout() {
    this.token = null;
    this.wallet = null;
  }

  /**
   * Get the current auth token
   */
  getToken() {
    return this.token;
  }
}

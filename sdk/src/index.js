/**
 * SentinelX SDK — Main Entry Point
 * 
 * Usage:
 *   import SentinelX from '@sentinelx/sdk';
 * 
 *   const sx = new SentinelX({
 *     apiUrl: 'http://localhost:8000',
 *     autoGuard: true,
 *   });
 * 
 *   // Login with wallet
 *   const result = await sx.auth.login();
 * 
 *   // Scan content
 *   const scan = await sx.guard.scan('My credit card is 4532015112830366');
 * 
 *   // Initialize auto-scanning on all inputs
 *   sx.guard.init();
 */

import { SentinelXAuth } from './auth.js';
import { GuardLayer } from './guardlayer.js';

export default class SentinelX {
  constructor(config = {}) {
    this.config = {
      apiUrl: config.apiUrl || 'http://localhost:8000',
      appId: config.appId || 'default',
      autoGuard: config.autoGuard !== false,
      ...config,
    };

    // Initialize modules
    this.auth = new SentinelXAuth(this.config);
    this.guard = new GuardLayer(this.config);

    // Auto-connect guard after auth
    this.auth.onAuth = (result) => {
      this.guard.token = result.token;
      this.guard.wallet = result.wallet_address;
      if (this.config.autoGuard) {
        this.guard.init();
      }
    };

    console.log('🛡️ SentinelX SDK initialized');
  }

  /**
   * Quick setup: login + activate guard
   */
  async connect() {
    const result = await this.auth.login();
    if (result.success) {
      this.guard.init();
    }
    return result;
  }

  /**
   * Cleanup
   */
  destroy() {
    this.guard.destroy();
    this.auth.logout();
  }
}

export { SentinelXAuth, GuardLayer };

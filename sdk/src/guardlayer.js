/**
 * SentinelX SDK — GuardLayer Module
 * Drop-in data leak prevention for any web app
 * Uses MutationObserver to intercept text inputs and scan for sensitive data
 */

export class GuardLayer {
  constructor(config = {}) {
    this.apiUrl = config.apiUrl || 'http://localhost:8000';
    this.token = config.token || null;
    this.wallet = config.wallet || null;
    this.autoScan = config.autoScan !== false;
    this.showModal = config.showModal !== false;
    this.onThreat = config.onThreat || null;
    this.onClean = config.onClean || null;
    this.observer = null;
    this.modalEl = null;
    this._currentResolve = null;
  }

  /**
   * Initialize GuardLayer — attaches to all inputs/textareas on the page
   */
  init() {
    if (typeof window === 'undefined') return;

    // Inject modal CSS
    this._injectStyles();

    // Create modal element
    this._createModal();

    // Observe DOM for new inputs
    this.observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === 1) {
            this._attachToInputs(node);
          }
        });
      });
    });

    this.observer.observe(document.body, { childList: true, subtree: true });

    // Attach to existing inputs
    this._attachToInputs(document.body);

    console.log('🛡️ SentinelX GuardLayer initialized');
  }

  /**
   * Scan text content for sensitive data
   * @param {string} text - Content to scan
   * @returns {Promise<Object>} Scan result
   */
  async scan(text) {
    const res = await fetch(`${this.apiUrl}/guard/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}),
      },
      body: JSON.stringify({
        text,
        wallet_address: this.wallet,
        use_llm: true,
      }),
    });
    return res.json();
  }

  /**
   * Destroy GuardLayer and cleanup
   */
  destroy() {
    if (this.observer) {
      this.observer.disconnect();
    }
    if (this.modalEl) {
      this.modalEl.remove();
    }
  }

  // ─── Private Methods ─────────────────────────────────────────

  _attachToInputs(root) {
    const inputs = root.querySelectorAll
      ? root.querySelectorAll('input[type="text"], textarea, [contenteditable="true"]')
      : [];

    inputs.forEach((input) => {
      if (input._sentinelxGuard) return; // Already attached
      input._sentinelxGuard = true;

      input.addEventListener('blur', async (e) => {
        const text = e.target.value || e.target.textContent || '';
        if (text.length < 5) return;

        const result = await this.scan(text);

        if (result.is_risky) {
          if (this.onThreat) this.onThreat(result);

          if (this.showModal) {
            const allowed = await this._showWarningModal(result);
            if (!allowed) {
              e.target.value = '';
              e.target.textContent = '';
            }
          }
        } else {
          if (this.onClean) this.onClean(result);
        }
      });
    });
  }

  _showWarningModal(result) {
    return new Promise((resolve) => {
      this._currentResolve = resolve;
      const modal = this.modalEl;

      const categories = result.categories?.join(', ') || 'Unknown';
      const findings = result.regex_findings?.map(f => `• ${f.label}: "${f.sample}"`).join('\n') || '';

      modal.querySelector('.sx-modal-severity').textContent = result.severity?.toUpperCase();
      modal.querySelector('.sx-modal-message').textContent =
        `Sensitive data detected: ${categories}`;
      modal.querySelector('.sx-modal-details').textContent = findings;
      modal.querySelector('.sx-modal-hash').textContent =
        `Event Hash: ${result.event_hash?.slice(0, 20)}...`;

      modal.style.display = 'flex';
    });
  }

  _createModal() {
    const modal = document.createElement('div');
    modal.className = 'sx-guard-modal';
    modal.style.display = 'none';
    modal.innerHTML = `
      <div class="sx-modal-backdrop"></div>
      <div class="sx-modal-content">
        <div class="sx-modal-header">
          <span class="sx-modal-icon">🛡️</span>
          <span>SentinelX GuardLayer</span>
          <span class="sx-modal-severity"></span>
        </div>
        <p class="sx-modal-message"></p>
        <pre class="sx-modal-details"></pre>
        <p class="sx-modal-hash"></p>
        <p class="sx-modal-question">Are you sure you want to send this?</p>
        <div class="sx-modal-actions">
          <button class="sx-btn-block">Block & Clear</button>
          <button class="sx-btn-override">Send Anyway</button>
        </div>
      </div>
    `;

    modal.querySelector('.sx-btn-block').addEventListener('click', () => {
      modal.style.display = 'none';
      if (this._currentResolve) this._currentResolve(false);
    });

    modal.querySelector('.sx-btn-override').addEventListener('click', () => {
      modal.style.display = 'none';
      if (this._currentResolve) this._currentResolve(true);
    });

    modal.querySelector('.sx-modal-backdrop').addEventListener('click', () => {
      modal.style.display = 'none';
      if (this._currentResolve) this._currentResolve(false);
    });

    document.body.appendChild(modal);
    this.modalEl = modal;
  }

  _injectStyles() {
    const style = document.createElement('style');
    style.textContent = `
      .sx-guard-modal {
        position: fixed; top: 0; left: 0; right: 0; bottom: 0;
        display: flex; align-items: center; justify-content: center;
        z-index: 99999;
      }
      .sx-modal-backdrop {
        position: absolute; top: 0; left: 0; right: 0; bottom: 0;
        background: rgba(0,0,0,0.7); backdrop-filter: blur(4px);
      }
      .sx-modal-content {
        position: relative; background: #111827; border: 1px solid #374151;
        border-radius: 16px; padding: 24px; max-width: 480px; width: 90%;
        color: #e2e8f0; font-family: system-ui, sans-serif;
      }
      .sx-modal-header {
        display: flex; align-items: center; gap: 8px;
        font-size: 16px; font-weight: 600; margin-bottom: 16px;
      }
      .sx-modal-icon { font-size: 24px; }
      .sx-modal-severity {
        margin-left: auto; font-size: 11px; padding: 2px 8px;
        border-radius: 8px; background: rgba(239,68,68,0.2);
        color: #f87171; border: 1px solid rgba(239,68,68,0.3);
      }
      .sx-modal-message { font-size: 14px; color: #f87171; margin-bottom: 12px; }
      .sx-modal-details {
        font-size: 12px; color: #9ca3af; background: #0a0e1a;
        padding: 12px; border-radius: 8px; margin-bottom: 12px;
        white-space: pre-wrap; font-family: monospace;
      }
      .sx-modal-hash { font-size: 11px; color: #6b7280; font-family: monospace; margin-bottom: 8px; }
      .sx-modal-question { font-size: 14px; color: #e2e8f0; margin-bottom: 16px; }
      .sx-modal-actions { display: flex; gap: 8px; }
      .sx-btn-block {
        flex: 1; padding: 10px; border-radius: 10px; border: 1px solid rgba(16,185,129,0.3);
        background: rgba(16,185,129,0.1); color: #34d399; font-weight: 500;
        cursor: pointer; font-size: 14px;
      }
      .sx-btn-block:hover { background: rgba(16,185,129,0.2); }
      .sx-btn-override {
        flex: 1; padding: 10px; border-radius: 10px; border: 1px solid rgba(239,68,68,0.3);
        background: rgba(239,68,68,0.1); color: #f87171; font-weight: 500;
        cursor: pointer; font-size: 14px;
      }
      .sx-btn-override:hover { background: rgba(239,68,68,0.2); }
    `;
    document.head.appendChild(style);
  }
}

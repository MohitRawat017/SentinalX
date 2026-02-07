import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import useStore from '../store';
import { authAPI } from '../api';
import { HiShieldCheck, HiBolt, HiCpuChip, HiLockClosed, HiCommandLine } from 'react-icons/hi2';

export default function LoginPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [authResult, setAuthResult] = useState(null);
  const { setAuth, setEnforcement, addNotification } = useStore();
  const navigate = useNavigate();

  const handleWalletLogin = async () => {
    setLoading(true);
    setError('');

    try {
      if (typeof window.ethereum !== 'undefined') {
        const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
        const wallet = accounts[0];

        const nonceRes = await authAPI.getNonce();
        const nonce = nonceRes.data.nonce;

        const message = `SentinelX wants you to sign in with your Ethereum account:\n${wallet}\n\nSign in to SentinelX Security Platform\n\nURI: ${window.location.origin}\nVersion: 1\nChain ID: 11155111\nNonce: ${nonce}\nIssued At: ${new Date().toISOString()}`;

        const signature = await window.ethereum.request({
          method: 'personal_sign',
          params: [message, wallet],
        });

        const verifyRes = await authAPI.verify({
          message,
          signature,
          wallet_address: wallet,
          user_agent: navigator.userAgent,
        });

        if (verifyRes.data.success) {
          setAuth(
            verifyRes.data.wallet_address,
            verifyRes.data.token,
            verifyRes.data.risk_level,
            verifyRes.data.risk_score
          );
          setEnforcement({
            security_status: verifyRes.data.security_status,
            trust_score: verifyRes.data.trust_score,
            locked_until: verifyRes.data.locked_until,
          });
          setAuthResult(verifyRes.data);
          addNotification({
            type: verifyRes.data.risk_level === 'high' ? 'warning' : 'success',
            title: 'Authenticated',
            message: verifyRes.data.message,
          });
          setTimeout(() => navigate('/dashboard'), 1500);
        } else {
          // Enforcement lockout
          if (verifyRes.data.security_status === 'locked') {
            setError(`Account locked: ${verifyRes.data.message}`);
            setAuthResult(verifyRes.data);
          } else {
            setError(verifyRes.data.message);
          }
        }
      } else {
        await handleDemoLogin();
      }
    } catch (err) {
      console.error('Login error:', err);
      if (err.code === 4001) {
        setError('Signature rejected. Please try again.');
      } else {
        await handleDemoLogin();
      }
    }

    setLoading(false);
  };

  const handleDemoLogin = async () => {
    setLoading(true);
    try {
      const demoWallet = '0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28';
      const nonceRes = await authAPI.getNonce();

      const message = `SentinelX Demo Login\nWallet: ${demoWallet}\nNonce: ${nonceRes.data.nonce}`;
      const signature = '0x' + 'a'.repeat(130);

      const verifyRes = await authAPI.verify({
        message,
        signature,
        wallet_address: demoWallet,
        user_agent: navigator.userAgent,
        geo_lat: 37.7749,
        geo_lng: -122.4194,
        geo_country: 'United States',
        geo_city: 'San Francisco',
      });

      if (verifyRes.data.success) {
        setAuth(
          verifyRes.data.wallet_address,
          verifyRes.data.token,
          verifyRes.data.risk_level,
          verifyRes.data.risk_score
        );
        setEnforcement({
          security_status: verifyRes.data.security_status,
          trust_score: verifyRes.data.trust_score,
          locked_until: verifyRes.data.locked_until,
        });
        setAuthResult(verifyRes.data);
        addNotification({
          type: 'success',
          title: 'Demo Login Successful',
          message: `Risk Score: ${verifyRes.data.risk_score} (${verifyRes.data.risk_level})`,
        });
        setTimeout(() => navigate('/dashboard'), 1500);
      } else if (verifyRes.data.security_status === 'locked') {
        setError(`Account locked: ${verifyRes.data.message}`);
        setAuthResult(verifyRes.data);
      }
    } catch (err) {
      setError('Backend not reachable. Please start the FastAPI server first.');
    }
    setLoading(false);
  };

  const features = [
    { icon: HiShieldCheck, title: 'Wallet Security', desc: 'SIWE authentication' },
    { icon: HiBolt, title: 'Real-time Analysis', desc: 'Instant risk scoring' },
    { icon: HiCommandLine, title: 'Multiple SDKs', desc: 'Python, JavaScript & Go' },
  ];

  return (
    <div className="landing-container">
      {/* Left Panel - Dark (Sign In) */}
      <div className="landing-left">
        {/* Logo */}
        <div className="landing-logo">
          <div className="landing-logo-icon">
            <HiShieldCheck className="w-5 h-5 text-white" />
          </div>
          <span className="landing-logo-text">SentinelX</span>
        </div>

        {/* Sign In Content */}
        <div className="landing-signin-content">
          <h1 className="landing-title">Sign in to SentinelX</h1>
          <p className="landing-subtitle">Get started with Web3 security protection</p>

          {/* Error Message */}
          {error && (
            <div className="landing-error">
              {error}
            </div>
          )}

          {/* Auth Result */}
          {authResult && (
            <div className={`landing-success ${authResult.security_status === 'locked' ? '!border-red-500/30 !bg-red-500/5' : ''}`}>
              <div className="flex items-center gap-2 mb-2">
                <div className={`w-2 h-2 rounded-full ${
                  authResult.security_status === 'locked' ? 'bg-red-500' :
                  authResult.security_status === 'restricted' ? 'bg-yellow-500' : 'bg-emerald-500'
                }`} />
                <span className={`text-sm font-medium ${
                  authResult.security_status === 'locked' ? 'text-red-400' :
                  authResult.security_status === 'restricted' ? 'text-yellow-400' : 'text-emerald-400'
                }`}>
                  {authResult.security_status === 'locked' ? 'Account Locked' :
                   authResult.security_status === 'restricted' ? 'Session Restricted' : 'Authenticated'}
                </span>
              </div>
              <div className="space-y-1 text-xs text-gray-400">
                <p>Risk Score: <span className="text-white font-mono">{authResult.risk_score}</span></p>
                <p>Risk Level: <span className={`font-medium ${authResult.risk_level === 'low' ? 'text-emerald-400' :
                  authResult.risk_level === 'medium' ? 'text-yellow-400' : 'text-red-400'
                  }`}>{authResult.risk_level?.toUpperCase()}</span></p>
                {authResult.trust_score != null && (
                  <p>Trust Score: <span className={`font-bold ${
                    authResult.trust_score >= 80 ? 'text-emerald-400' :
                    authResult.trust_score >= 50 ? 'text-yellow-400' : 'text-red-400'
                  }`}>{authResult.trust_score}/100</span></p>
                )}
                {authResult.security_status && authResult.security_status !== 'active' && (
                  <p>Status: <span className={`font-medium ${
                    authResult.security_status === 'locked' ? 'text-red-400' :
                    authResult.security_status === 'restricted' ? 'text-red-400' : 'text-yellow-400'
                  }`}>{authResult.security_status.replace('_', ' ').toUpperCase()}</span></p>
                )}
                {authResult.locked_until && (
                  <p className="text-red-400">Unlocks: {new Date(authResult.locked_until).toLocaleTimeString()}</p>
                )}
              </div>
            </div>
          )}

          {/* Buttons */}
          <div className="landing-buttons">
            <button
              onClick={handleWalletLogin}
              disabled={loading}
              className="landing-btn-primary"
            >
              {loading ? (
                <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              ) : (
                <>
                  <img src="https://upload.wikimedia.org/wikipedia/commons/3/36/MetaMask_Fox.svg" className="w-5 h-5" alt="" />
                  Continue with MetaMask
                </>
              )}
            </button>

            <button
              onClick={handleDemoLogin}
              disabled={loading}
              className="landing-btn-secondary"
            >
              <HiBolt className="w-4 h-4 text-yellow-400" />
              Demo Mode (No Wallet)
            </button>
          </div>

          {/* Footer Text */}
          <p className="landing-footer-text">
            SentinelX uses SIWE (EIP-4361) for secure wallet authentication.
            <br />No passwords. No emails. Just your wallet.
          </p>
        </div>
      </div>

      {/* Right Panel - Light Card */}
      <div className="landing-right">
        <div className="landing-right-card">
          {/* Shield Grid Icon */}
          <div className="landing-icon-grid">
            <div className="shield-grid">
              <div className="shield-icon"><HiShieldCheck /></div>
              <div className="shield-icon"><HiShieldCheck /></div>
              <div className="shield-icon"><HiShieldCheck /></div>
              <div className="shield-icon"><HiShieldCheck /></div>
              <div className="shield-icon center"><HiLockClosed /></div>
              <div className="shield-icon"><HiShieldCheck /></div>
              <div className="shield-icon"><HiShieldCheck /></div>
              <div className="shield-icon"><HiShieldCheck /></div>
              <div className="shield-icon"><HiShieldCheck /></div>
            </div>
          </div>

          {/* Headline */}
          <h2 className="landing-headline">
            Adaptive Security<br />with SentinelX
          </h2>
          <p className="landing-description">
            Verify identity, analyze behavior, protect data — and record every decision on-chain.
            Powered by AI-driven risk analysis.
          </p>

          {/* Feature Icons */}
          <div className="landing-features">
            {features.map(({ icon: Icon, title, desc }) => (
              <div key={title} className="landing-feature">
                <div className="landing-feature-icon">
                  <Icon />
                </div>
                <span className="landing-feature-title">{title}</span>
                <span className="landing-feature-desc">{desc}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

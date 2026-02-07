import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import useStore from '../store';
import { authAPI } from '../api';
import { HiShieldCheck, HiBolt, HiCpuChip, HiLockClosed, HiCommandLine, HiExclamationTriangle, HiFingerPrint } from 'react-icons/hi2';

export default function LoginPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [authResult, setAuthResult] = useState(null);
  const [stepUpState, setStepUpState] = useState(null); // { wallet, challenge, hasMetaMask }
  const [stepUpLoading, setStepUpLoading] = useState(false);
  const { setAuth, setEnforcement, addNotification } = useStore();
  const navigate = useNavigate();

  const proceedAfterLogin = (data) => {
    setAuth(data.wallet_address, data.token, data.risk_level, data.risk_score);
    setEnforcement({
      security_status: data.security_status,
      trust_score: data.trust_score,
      locked_until: data.locked_until,
    });
    setAuthResult(data);
    addNotification({
      type: data.risk_level === 'high' ? 'warning' : 'success',
      title: 'Authenticated',
      message: data.message,
    });
  };

  const handleStepUp = async () => {
    if (!stepUpState) return;
    setStepUpLoading(true);
    setError('');

    try {
      // 1. Request a step-up challenge from backend
      const challengeRes = await authAPI.challenge({
        wallet_address: stepUpState.wallet,
        challenge_type: 're-sign',
      });
      const { nonce, message } = challengeRes.data;

      let signature;
      if (stepUpState.hasMetaMask) {
        // 2. MetaMask re-sign
        signature = await window.ethereum.request({
          method: 'personal_sign',
          params: [message, stepUpState.wallet],
        });
      } else {
        // Demo mode: simulated signature
        signature = '0x' + 'b'.repeat(130);
      }

      // 3. Verify with backend
      const verifyRes = await authAPI.stepUpVerify({
        wallet_address: stepUpState.wallet,
        signature,
        nonce,
      });

      if (verifyRes.data.success) {
        // Update enforcement with boosted score
        setEnforcement(verifyRes.data.enforcement);
        addNotification({
          type: 'success',
          title: 'Verification Complete',
          message: `Trust score boosted: ${verifyRes.data.enforcement.previous_score} → ${verifyRes.data.enforcement.trust_score}`,
        });
        setStepUpState(null);
        navigate('/dashboard');
      }
    } catch (err) {
      console.error('Step-up error:', err);
      if (err.code === 4001) {
        setError('Signature rejected. You can skip verification and continue with restricted access.');
      } else {
        setError(err.response?.data?.detail || 'Step-up verification failed. Try again or skip.');
      }
    }

    setStepUpLoading(false);
  };

  const skipStepUp = () => {
    setStepUpState(null);
    addNotification({
      type: 'warning',
      title: 'Step-Up Skipped',
      message: 'Some sensitive actions may require additional verification.',
    });
    navigate('/dashboard');
  };

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
          proceedAfterLogin(verifyRes.data);

          if (verifyRes.data.step_up_required) {
            // Intercept: show step-up challenge instead of navigating
            setStepUpState({ wallet, hasMetaMask: true });
          } else {
            setTimeout(() => navigate('/dashboard'), 1500);
          }
        } else {
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
        proceedAfterLogin(verifyRes.data);

        if (verifyRes.data.step_up_required) {
          // Intercept: show step-up challenge
          setStepUpState({ wallet: demoWallet, hasMetaMask: false });
        } else {
          setTimeout(() => navigate('/dashboard'), 1500);
        }
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
      {/* Step-Up Verification Overlay */}
      {stepUpState && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 backdrop-blur-sm">
          <div className="glass-card p-8 max-w-md w-full mx-4 border border-yellow-500/30">
            {/* Header */}
            <div className="flex items-center gap-3 mb-4">
              <div className="w-12 h-12 rounded-xl bg-yellow-500/20 flex items-center justify-center">
                <HiExclamationTriangle className="w-6 h-6 text-yellow-400" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-white">Step-Up Verification Required</h2>
                <p className="text-sm text-yellow-400">Elevated risk detected on your account</p>
              </div>
            </div>

            {/* Explanation */}
            <div className="mb-6 p-4 rounded-lg bg-yellow-500/5 border border-yellow-500/20">
              <p className="text-sm text-gray-300 leading-relaxed">
                SentinelX has detected elevated risk on your account. To restore full access and boost your trust score,
                please confirm your identity by signing a verification message with your wallet.
              </p>
            </div>

            {/* Trust Score Info */}
            {authResult?.trust_score != null && (
              <div className="mb-6 flex items-center justify-between p-3 rounded-lg bg-sentinel-dark/50 border border-sentinel-border">
                <span className="text-sm text-gray-400">Current Trust Score</span>
                <span className={`text-lg font-bold font-mono ${authResult.trust_score >= 80 ? 'text-emerald-400' :
                    authResult.trust_score >= 50 ? 'text-yellow-400' : 'text-red-400'
                  }`}>
                  {authResult.trust_score}/100
                </span>
              </div>
            )}

            {/* Error */}
            {error && (
              <div className="mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-sm text-red-400">
                {error}
              </div>
            )}

            {/* Action Buttons */}
            <div className="space-y-3">
              <button
                onClick={handleStepUp}
                disabled={stepUpLoading}
                className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-gradient-to-r from-yellow-500 to-amber-600 hover:opacity-90 text-white font-semibold text-sm transition-all disabled:opacity-50"
              >
                {stepUpLoading ? (
                  <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                ) : (
                  <>
                    <HiFingerPrint className="w-5 h-5" />
                    {stepUpState.hasMetaMask ? 'Verify with Wallet Signature' : 'Verify Identity (Demo)'}
                  </>
                )}
              </button>

              <button
                onClick={skipStepUp}
                disabled={stepUpLoading}
                className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl border border-gray-600/50 text-gray-400 hover:text-white hover:border-gray-500 text-sm transition-all disabled:opacity-50"
              >
                Skip for now (restricted access)
              </button>
            </div>

            <p className="text-xs text-gray-500 mt-4 text-center">
              Completing verification will boost your trust score by +20 points
            </p>
          </div>
        </div>
      )}

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
          {error && !stepUpState && (
            <div className="landing-error">
              {error}
            </div>
          )}

          {/* Auth Result */}
          {authResult && !stepUpState && (
            <div className={`landing-success ${authResult.security_status === 'locked' ? '!border-red-500/30 !bg-red-500/5' : ''}`}>
              <div className="flex items-center gap-2 mb-2">
                <div className={`w-2 h-2 rounded-full ${authResult.security_status === 'locked' ? 'bg-red-500' :
                    authResult.security_status === 'restricted' ? 'bg-yellow-500' : 'bg-emerald-500'
                  }`} />
                <span className={`text-sm font-medium ${authResult.security_status === 'locked' ? 'text-red-400' :
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
                  <p>Trust Score: <span className={`font-bold ${authResult.trust_score >= 80 ? 'text-emerald-400' :
                      authResult.trust_score >= 50 ? 'text-yellow-400' : 'text-red-400'
                    }`}>{authResult.trust_score}/100</span></p>
                )}
                {authResult.security_status && authResult.security_status !== 'active' && (
                  <p>Status: <span className={`font-medium ${authResult.security_status === 'locked' ? 'text-red-400' :
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
              <svg className="w-4 h-4" viewBox="0 0 24 24">
                <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
                <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
              </svg>
              Login with Google
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

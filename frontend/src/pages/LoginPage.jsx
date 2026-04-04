import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  HiBolt,
  HiCommandLine,
  HiExclamationTriangle,
  HiFingerPrint,
  HiLockClosed,
  HiShieldCheck,
} from 'react-icons/hi2';

import { authAPI } from '../api';
import {
  buildSignInMessage,
  connectPeraWallet,
  DEMO_LOGIN_SIGNATURE,
  DEMO_STEP_UP_SIGNATURE,
  DEMO_WALLET,
  signMessageWithPera,
} from '../api/blockchain';
import useStore from '../store';


async function getGeolocation() {
  let coords = { lat: null, lng: null };
  let locationInfo = { country: null, city: null };

  if (navigator.geolocation) {
    try {
      const pos = await new Promise((resolve, reject) => {
        navigator.geolocation.getCurrentPosition(resolve, reject, {
          timeout: 10000,
          enableHighAccuracy: true,
          maximumAge: 60000,
        });
      });
      coords.lat = pos.coords.latitude;
      coords.lng = pos.coords.longitude;

      try {
        const geoRes = await fetch(
          `https://nominatim.openstreetmap.org/reverse?lat=${coords.lat}&lon=${coords.lng}&format=json`,
          { headers: { 'User-Agent': 'SentinelX-App' } },
        );
        const geoData = await geoRes.json();
        locationInfo.city =
          geoData.address?.city ||
          geoData.address?.town ||
          geoData.address?.village ||
          geoData.address?.state_district;
        locationInfo.country = geoData.address?.country;
        if (geoData.address?.state) {
          locationInfo.city = `${locationInfo.city}, ${geoData.address.state}`;
        }
      } catch {
        // Reverse geocoding is optional.
      }
    } catch {
      // Browser geolocation is optional.
    }
  }

  if (!coords.lat || !coords.lng) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const res = await fetch('https://ipapi.co/json/', { signal: controller.signal });
      clearTimeout(timeout);
      const data = await res.json();
      coords.lat = data.latitude;
      coords.lng = data.longitude;
      locationInfo.country = data.country_name;
      locationInfo.city = data.city;
      if (data.region) {
        locationInfo.city = `${data.city}, ${data.region}`;
      }
    } catch {
      // IP geolocation is optional.
    }
  }

  return {
    geo_lat: coords.lat,
    geo_lng: coords.lng,
    geo_country: locationInfo.country,
    geo_city: locationInfo.city,
  };
}

function getErrorMessage(err, fallback) {
  if (err?.response?.data?.detail) {
    return err.response.data.detail;
  }

  const message = err?.message || '';
  if (message.toLowerCase().includes('cancel')) {
    return 'Signature rejected. Please try again.';
  }

  return fallback;
}

export default function LoginPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [authResult, setAuthResult] = useState(null);
  const [stepUpState, setStepUpState] = useState(null);
  const [stepUpLoading, setStepUpLoading] = useState(false);
  const { setAuth, setEnforcement, addNotification } = useStore();
  const navigate = useNavigate();

  const finalizeLogin = (data, enforcementOverride) => {
    setAuth(data.wallet_address, data.token, data.risk_level, data.risk_score);
    const enforcement = enforcementOverride || {
      security_status: data.security_status,
      trust_score: data.trust_score,
      locked_until: data.locked_until,
    };
    setEnforcement(enforcement);
    navigate('/dashboard');
  };

  const handleStepUp = async () => {
    if (!stepUpState) {
      return;
    }

    setStepUpLoading(true);
    setError('');

    try {
      const challengeRes = await authAPI.challenge({
        wallet_address: stepUpState.signerWallet,
        challenge_type: 're-sign',
      });
      const { nonce, message } = challengeRes.data;

      const signature =
        stepUpState.mode === 'demo'
          ? DEMO_STEP_UP_SIGNATURE
          : await signMessageWithPera(message, stepUpState.signerWallet);

      const verifyRes = await authAPI.stepUpVerify({
        wallet_address: stepUpState.signerWallet,
        signature,
        nonce,
      });

      if (verifyRes.data.success) {
        addNotification({
          type: 'success',
          title: 'Verification Complete',
          message: `Trust score boosted: ${verifyRes.data.enforcement.previous_score} -> ${verifyRes.data.enforcement.trust_score}`,
        });
        finalizeLogin(stepUpState.pendingAuth, verifyRes.data.enforcement);
      }
    } catch (err) {
      setError(getErrorMessage(err, 'Step-up verification failed. Try again or continue with restricted access.'));
    }

    setStepUpLoading(false);
  };

  const skipStepUp = () => {
    addNotification({
      type: 'warning',
      title: 'Step-Up Skipped',
      message: 'Some sensitive actions may require additional verification.',
    });
    finalizeLogin(stepUpState.pendingAuth);
  };

  const handleAuthResponse = (data, stepUpMode, signerWallet) => {
    if (data.success) {
      if (data.step_up_required) {
        setAuthResult(data);
        setStepUpState({
          mode: stepUpMode,
          signerWallet,
          pendingAuth: data,
        });
        return;
      }

      addNotification({
        type: data.risk_level === 'high' ? 'warning' : 'success',
        title: stepUpMode === 'demo' ? 'Demo Login Successful' : 'Authenticated',
        message: data.message,
      });
      setAuthResult(data);
      finalizeLogin(data);
      return;
    }

    if (data.security_status === 'locked') {
      setError(`Account locked: ${data.message}`);
      setAuthResult(data);
      return;
    }

    setError(data.message || 'Authentication failed.');
  };

  const handleWalletLogin = async () => {
    setLoading(true);
    setError('');
    setAuthResult(null);
    setStepUpState(null);

    try {
      const wallet = await connectPeraWallet();
      const nonceRes = await authAPI.getNonce();
      const issuedAt = new Date().toISOString();
      const message = buildSignInMessage({
        walletAddress: wallet,
        nonce: nonceRes.data.nonce,
        issuedAt,
        origin: window.location.origin,
      });
      const signature = await signMessageWithPera(message, wallet);

      const verifyRes = await authAPI.verify({
        message,
        signature,
        wallet_address: wallet,
        user_agent: navigator.userAgent,
        ...(await getGeolocation()),
      });

      handleAuthResponse(verifyRes.data, 'pera', wallet);
    } catch (err) {
      setError(
        getErrorMessage(
          err,
          'Unable to complete Pera Wallet sign-in. Make sure Pera Wallet is installed and unlocked.',
        ),
      );
    }

    setLoading(false);
  };

  const handleDemoLogin = async () => {
    setLoading(true);
    setError('');
    setAuthResult(null);
    setStepUpState(null);

    try {
      const nonceRes = await authAPI.getNonce();
      const message = `SentinelX Demo Login\nWallet: ${DEMO_WALLET}\nNonce: ${nonceRes.data.nonce}`;

      const verifyRes = await authAPI.verify({
        message,
        signature: DEMO_LOGIN_SIGNATURE,
        wallet_address: DEMO_WALLET,
        user_agent: navigator.userAgent,
        ...(await getGeolocation()),
      });

      handleAuthResponse(verifyRes.data, 'demo', DEMO_WALLET);
    } catch (err) {
      setError(getErrorMessage(err, 'Backend not reachable. Please start the FastAPI server first.'));
    }

    setLoading(false);
  };

  const features = [
    { icon: HiShieldCheck, title: 'Wallet Security', desc: 'Algorand wallet auth' },
    { icon: HiBolt, title: 'Real-time Analysis', desc: 'Instant risk scoring' },
    { icon: HiCommandLine, title: 'Anchored Proofs', desc: 'Merkle roots on Algorand' },
  ];

  return (
    <div className="landing-container">
      {stepUpState && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 backdrop-blur-sm">
          <div className="glass-card mx-4 w-full max-w-md border border-yellow-500/30 p-8">
            <div className="mb-4 flex items-center gap-3">
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-yellow-500/20">
                <HiExclamationTriangle className="h-6 w-6 text-yellow-400" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-white">Step-Up Verification Required</h2>
                <p className="text-sm text-yellow-400">Elevated risk detected on your account</p>
              </div>
            </div>

            <div className="mb-6 rounded-lg border border-yellow-500/20 bg-yellow-500/5 p-4">
              <p className="text-sm leading-relaxed text-gray-300">
                SentinelX detected elevated risk on this session. Sign one more message with your
                wallet to restore full access and raise your trust score.
              </p>
            </div>

            {authResult?.trust_score != null && (
              <div className="mb-6 flex items-center justify-between rounded-lg border border-sentinel-border bg-sentinel-dark/50 p-3">
                <span className="text-sm text-gray-400">Current Trust Score</span>
                <span
                  className={`font-mono text-lg font-bold ${
                    authResult.trust_score >= 80
                      ? 'text-emerald-400'
                      : authResult.trust_score >= 50
                        ? 'text-yellow-400'
                        : 'text-red-400'
                  }`}
                >
                  {authResult.trust_score}/100
                </span>
              </div>
            )}

            {error && (
              <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-400">
                {error}
              </div>
            )}

            <div className="space-y-3">
              <button
                onClick={handleStepUp}
                disabled={stepUpLoading}
                className="w-full rounded-xl bg-gradient-to-r from-yellow-500 to-amber-600 px-4 py-3 text-sm font-semibold text-white transition-all hover:opacity-90 disabled:opacity-50"
              >
                {stepUpLoading ? (
                  <div className="mx-auto h-5 w-5 animate-spin rounded-full border-2 border-white/30 border-t-white" />
                ) : (
                  <span className="flex items-center justify-center gap-2">
                    <HiFingerPrint className="h-5 w-5" />
                    {stepUpState.mode === 'demo' ? 'Verify Identity (Demo)' : 'Verify with Pera Wallet'}
                  </span>
                )}
              </button>

              <button
                onClick={skipStepUp}
                disabled={stepUpLoading}
                className="w-full rounded-xl border border-gray-600/50 px-4 py-2.5 text-sm text-gray-400 transition-all hover:border-gray-500 hover:text-white disabled:opacity-50"
              >
                Skip for now (restricted access)
              </button>
            </div>

            <p className="mt-4 text-center text-xs text-gray-500">
              Completing verification will boost your trust score by +20 points
            </p>
          </div>
        </div>
      )}

      <div className="landing-left">
        <div className="landing-logo">
          <div className="landing-logo-icon">
            <HiShieldCheck className="h-5 w-5 text-white" />
          </div>
          <span className="landing-logo-text">SentinelX</span>
        </div>

        <div className="landing-signin-content">
          <h1 className="landing-title">Sign in to SentinelX</h1>
          <p className="landing-subtitle">Protect sessions with Algorand-native wallet identity</p>

          {error && !stepUpState && <div className="landing-error">{error}</div>}

          {authResult && !stepUpState && (
            <div
              className={`landing-success ${
                authResult.security_status === 'locked' ? '!border-red-500/30 !bg-red-500/5' : ''
              }`}
            >
              <div className="mb-2 flex items-center gap-2">
                <div
                  className={`h-2 w-2 rounded-full ${
                    authResult.security_status === 'locked'
                      ? 'bg-red-500'
                      : authResult.security_status === 'restricted'
                        ? 'bg-yellow-500'
                        : 'bg-emerald-500'
                  }`}
                />
                <span
                  className={`text-sm font-medium ${
                    authResult.security_status === 'locked'
                      ? 'text-red-400'
                      : authResult.security_status === 'restricted'
                        ? 'text-yellow-400'
                        : 'text-emerald-400'
                  }`}
                >
                  {authResult.security_status === 'locked'
                    ? 'Account Locked'
                    : authResult.security_status === 'restricted'
                      ? 'Session Restricted'
                      : 'Authenticated'}
                </span>
              </div>
              <div className="space-y-1 text-xs text-gray-400">
                <p>
                  Risk Score: <span className="font-mono text-white">{authResult.risk_score}</span>
                </p>
                <p>
                  Risk Level:{' '}
                  <span
                    className={`font-medium ${
                      authResult.risk_level === 'low'
                        ? 'text-emerald-400'
                        : authResult.risk_level === 'medium'
                          ? 'text-yellow-400'
                          : 'text-red-400'
                    }`}
                  >
                    {authResult.risk_level?.toUpperCase()}
                  </span>
                </p>
                {authResult.trust_score != null && (
                  <p>
                    Trust Score:{' '}
                    <span
                      className={`font-bold ${
                        authResult.trust_score >= 80
                          ? 'text-emerald-400'
                          : authResult.trust_score >= 50
                            ? 'text-yellow-400'
                            : 'text-red-400'
                      }`}
                    >
                      {authResult.trust_score}/100
                    </span>
                  </p>
                )}
                {authResult.security_status && authResult.security_status !== 'active' && (
                  <p>
                    Status:{' '}
                    <span
                      className={`font-medium ${
                        authResult.security_status === 'locked'
                          ? 'text-red-400'
                          : authResult.security_status === 'restricted'
                            ? 'text-red-400'
                            : 'text-yellow-400'
                      }`}
                    >
                      {authResult.security_status.replace('_', ' ').toUpperCase()}
                    </span>
                  </p>
                )}
                {authResult.locked_until && (
                  <p className="text-red-400">
                    Unlocks: {new Date(authResult.locked_until).toLocaleTimeString()}
                  </p>
                )}
              </div>
            </div>
          )}

          <div className="landing-buttons">
            <button onClick={handleWalletLogin} disabled={loading} className="landing-btn-primary">
              {loading ? (
                <div className="h-5 w-5 animate-spin rounded-full border-2 border-white/30 border-t-white" />
              ) : (
                <>
                  <HiShieldCheck className="h-5 w-5" />
                  Continue with Pera Wallet
                </>
              )}
            </button>

            <button onClick={handleDemoLogin} disabled={loading} className="landing-btn-secondary">
              <HiFingerPrint className="h-4 w-4" />
              Try the Demo Flow
            </button>
          </div>

          <p className="landing-footer-text">
            SentinelX uses Algorand ed25519 signatures via Pera Wallet for secure authentication.
            <br />
            No passwords. No emails. Just your wallet approval.
          </p>
        </div>
      </div>

      <div className="landing-right">
        <div className="landing-right-card">
          <div className="landing-icon-grid">
            <div className="shield-grid">
              <div className="shield-icon">
                <HiShieldCheck />
              </div>
              <div className="shield-icon">
                <HiShieldCheck />
              </div>
              <div className="shield-icon">
                <HiShieldCheck />
              </div>
              <div className="shield-icon">
                <HiShieldCheck />
              </div>
              <div className="shield-icon center">
                <HiLockClosed />
              </div>
              <div className="shield-icon">
                <HiShieldCheck />
              </div>
              <div className="shield-icon">
                <HiShieldCheck />
              </div>
              <div className="shield-icon">
                <HiShieldCheck />
              </div>
              <div className="shield-icon">
                <HiShieldCheck />
              </div>
            </div>
          </div>

          <h2 className="landing-headline">
            Adaptive Security
            <br />
            with SentinelX
          </h2>
          <p className="landing-description">
            Verify identity, analyze behavior, protect data, and anchor every security batch on
            Algorand with AI-driven risk analysis.
          </p>

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

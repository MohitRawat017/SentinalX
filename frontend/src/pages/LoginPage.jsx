import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import useStore from '../store';
import { authAPI } from '../api';
import { HiShieldCheck, HiFingerPrint, HiGlobeAlt, HiCpuChip, HiBolt } from 'react-icons/hi2';

export default function LoginPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [authResult, setAuthResult] = useState(null);
  const { setAuth, addNotification } = useStore();
  const navigate = useNavigate();

  const handleWalletLogin = async () => {
    setLoading(true);
    setError('');

    try {
      // Check if MetaMask is available
      if (typeof window.ethereum !== 'undefined') {
        // Real MetaMask flow
        const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
        const wallet = accounts[0];

        // Get nonce from backend
        const nonceRes = await authAPI.getNonce();
        const nonce = nonceRes.data.nonce;

        // Create SIWE message
        const message = `SentinelX wants you to sign in with your Ethereum account:\n${wallet}\n\nSign in to SentinelX Security Platform\n\nURI: ${window.location.origin}\nVersion: 1\nChain ID: 11155111\nNonce: ${nonce}\nIssued At: ${new Date().toISOString()}`;

        // Request signature
        const signature = await window.ethereum.request({
          method: 'personal_sign',
          params: [message, wallet],
        });

        // Verify with backend
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
          setAuthResult(verifyRes.data);
          addNotification({
            type: verifyRes.data.risk_level === 'high' ? 'warning' : 'success',
            title: 'Authenticated',
            message: verifyRes.data.message,
          });
          setTimeout(() => navigate('/dashboard'), 1500);
        } else {
          setError(verifyRes.data.message);
        }
      } else {
        // Demo mode — simulate wallet login
        await handleDemoLogin();
      }
    } catch (err) {
      console.error('Login error:', err);
      if (err.code === 4001) {
        setError('Signature rejected. Please try again.');
      } else {
        // Fallback to demo mode
        await handleDemoLogin();
      }
    }

    setLoading(false);
  };

  const handleDemoLogin = async () => {
    try {
      const demoWallet = '0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28';
      const nonceRes = await authAPI.getNonce();

      const message = `SentinelX Demo Login\nWallet: ${demoWallet}\nNonce: ${nonceRes.data.nonce}`;
      const signature = '0x' + 'a'.repeat(130); // Mock signature

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
        setAuthResult(verifyRes.data);
        addNotification({
          type: 'success',
          title: 'Demo Login Successful',
          message: `Risk Score: ${verifyRes.data.risk_score} (${verifyRes.data.risk_level})`,
        });
        setTimeout(() => navigate('/dashboard'), 1500);
      }
    } catch (err) {
      setError('Backend not reachable. Please start the FastAPI server first.');
    }
  };

  const features = [
    { icon: HiFingerPrint, title: 'SIWE Wallet Auth', desc: 'Passwordless login with Ethereum' },
    { icon: HiCpuChip, title: 'AI Risk Engine', desc: 'IsolationForest anomaly detection' },
    { icon: HiShieldCheck, title: 'GuardLayer DLP', desc: 'LLM + regex data leak prevention' },
    { icon: HiGlobeAlt, title: 'On-Chain Audit', desc: 'Merkle-batched Ethereum proofs' },
  ];

  return (
    <div className="min-h-[calc(100vh-5rem)] flex items-center justify-center">
      <div className="max-w-5xl w-full grid grid-cols-1 lg:grid-cols-2 gap-12">
        {/* Left: Hero */}
        <div className="flex flex-col justify-center">
          <div className="mb-6">
            <span className="px-3 py-1 rounded-full text-xs font-medium bg-blue-500/20 text-blue-400 border border-blue-500/30">
              🛡️ Web3 Security Platform
            </span>
          </div>
          <h1 className="text-5xl font-bold mb-4">
            <span className="bg-gradient-to-r from-blue-400 via-purple-400 to-cyan-400 bg-clip-text text-transparent">
              SentinelX
            </span>
          </h1>
          <p className="text-xl text-gray-400 mb-8 leading-relaxed">
            Adaptive security that verifies identity, analyzes behavior, 
            protects your data — and records every decision on-chain.
          </p>

          <div className="grid grid-cols-2 gap-4">
            {features.map(({ icon: Icon, title, desc }) => (
              <div key={title} className="glass-card p-4 hover:border-blue-500/30 transition-all group">
                <Icon className="w-6 h-6 text-blue-400 mb-2 group-hover:text-blue-300" />
                <h3 className="text-sm font-semibold text-white">{title}</h3>
                <p className="text-xs text-gray-500 mt-1">{desc}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Login Card */}
        <div className="flex items-center justify-center">
          <div className="glass-card p-8 w-full max-w-md glow-blue">
            <div className="text-center mb-8">
              <div className="w-16 h-16 mx-auto bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl flex items-center justify-center mb-4 shadow-lg shadow-blue-500/25">
                <HiShieldCheck className="w-8 h-8 text-white" />
              </div>
              <h2 className="text-2xl font-bold text-white">Sign In</h2>
              <p className="text-gray-400 text-sm mt-2">Connect your wallet to continue</p>
            </div>

            {error && (
              <div className="mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
                {error}
              </div>
            )}

            {authResult && (
              <div className="mb-4 p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/30">
                <div className="flex items-center gap-2 mb-2">
                  <div className="w-2 h-2 rounded-full bg-emerald-500" />
                  <span className="text-sm font-medium text-emerald-400">Authenticated</span>
                </div>
                <div className="space-y-1 text-xs text-gray-400">
                  <p>Risk Score: <span className="text-white font-mono">{authResult.risk_score}</span></p>
                  <p>Risk Level: <span className={`font-medium ${
                    authResult.risk_level === 'low' ? 'text-emerald-400' : 
                    authResult.risk_level === 'medium' ? 'text-yellow-400' : 'text-red-400'
                  }`}>{authResult.risk_level?.toUpperCase()}</span></p>
                  <p>Event Hash: <span className="text-white font-mono">{authResult.event_hash?.slice(0, 16)}...</span></p>
                </div>
              </div>
            )}

            {/* MetaMask Login */}
            <button
              onClick={handleWalletLogin}
              disabled={loading}
              className="w-full flex items-center justify-center gap-3 px-6 py-3 rounded-xl bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 text-white font-semibold transition-all hover:shadow-lg hover:shadow-blue-500/25 disabled:opacity-50 disabled:cursor-not-allowed mb-3"
            >
              {loading ? (
                <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              ) : (
                <>
                  <img src="https://upload.wikimedia.org/wikipedia/commons/3/36/MetaMask_Fox.svg" className="w-5 h-5" alt="" />
                  Connect with MetaMask
                </>
              )}
            </button>

            <button
              onClick={handleDemoLogin}
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-gray-300 font-medium transition-all disabled:opacity-50"
            >
              <HiBolt className="w-4 h-4 text-yellow-400" />
              Demo Mode (No Wallet)
            </button>

            <p className="text-center text-xs text-gray-500 mt-6">
              SentinelX uses SIWE (EIP-4361) for secure wallet authentication.
              <br />No passwords. No emails. Just your wallet.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

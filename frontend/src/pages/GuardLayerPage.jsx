import React, { useState, useEffect } from 'react';
import useStore from '../store';
import { guardAPI } from '../api';
import { HiShieldCheck, HiExclamationTriangle, HiPaperAirplane, HiEye } from 'react-icons/hi2';

export default function GuardLayerPage() {
  const { wallet, addNotification } = useStore();
  const [text, setText] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState(null);

  const fetchEvents = async () => {
    try {
      const [eventsRes, statsRes] = await Promise.all([
        guardAPI.events(wallet),
        guardAPI.stats(wallet),
      ]);
      setEvents(eventsRes.data.events || []);
      setStats(statsRes.data);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [wallet]);

  const handleScan = async () => {
    if (!text.trim()) return;
    setScanning(true);
    setResult(null);

    try {
      const res = await guardAPI.scan({
        text,
        wallet_address: wallet,
        use_llm: true,
      });
      setResult(res.data);
      addNotification({
        type: res.data.is_risky ? 'warning' : 'success',
        title: res.data.is_risky ? 'Threat Detected' : 'Content Clean',
        message: res.data.message,
      });
      fetchEvents();
    } catch (err) {
      addNotification({ type: 'error', message: 'Scan failed. Is the backend running?' });
    }

    setScanning(false);
  };

  const handleOverride = async () => {
    if (!result) return;
    try {
      await guardAPI.override({
        event_hash: result.event_hash,
        wallet_address: wallet,
        confirmed: true,
      });
      addNotification({
        type: 'info',
        title: 'Override Recorded',
        message: 'Your decision to send despite the warning has been logged on the audit trail.',
      });
      setResult(null);
      setText('');
      fetchEvents();
    } catch (err) {
      console.error(err);
    }
  };

  const sampleTexts = [
    { label: '💳 Credit Card', text: 'My card is 4532015112830366, CVV 123' },
    { label: '🔑 Password', text: 'Password: Admin123! for admin@corp.com' },
    { label: '🆔 SSN', text: 'SSN: 123-45-6789, DOB: 01/15/1990' },
    { label: '🔐 API Key', text: 'API key: sk_live_FAKE_KEY_FOR_DEMO' },
    { label: '📋 Confidential', text: 'CONFIDENTIAL: Q3 revenue was $4.2M' },
    { label: '✅ Clean', text: 'Hey, the meeting is at 3pm tomorrow!' },
  ];

  const severityColors = {
    critical: 'text-red-400 bg-red-500/10 border-red-500/30',
    high: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
    medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
    low: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">🛡️ GuardLayer — Data Leak Prevention</h1>
        <p className="text-gray-400 text-sm mt-1">
          Dual-layer scanning: fast regex patterns + LLM deep analysis
        </p>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-4 gap-4">
          {[
            { label: 'Total Scans', value: stats.total_scans, color: 'text-blue-400' },
            { label: 'Threats Found', value: stats.threats_detected, color: 'text-red-400' },
            { label: 'Overridden', value: stats.overrides, color: 'text-yellow-400' },
            { label: 'Blocked', value: stats.blocked, color: 'text-emerald-400' },
          ].map(({ label, value, color }) => (
            <div key={label} className="glass-card p-4">
              <p className="text-xs text-gray-500">{label}</p>
              <p className={`text-2xl font-bold ${color}`}>{value}</p>
            </div>
          ))}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Scanner */}
        <div className="glass-card p-6 space-y-4">
          <h3 className="text-lg font-semibold text-white flex items-center gap-2">
            <HiEye className="w-5 h-5 text-purple-400" />
            Content Scanner
          </h3>

          {/* Quick fill buttons */}
          <div className="flex flex-wrap gap-2">
            {sampleTexts.map(({ label, text: t }) => (
              <button
                key={label}
                onClick={() => setText(t)}
                className="px-2 py-1 text-xs rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-gray-400 hover:text-white transition-all"
              >
                {label}
              </button>
            ))}
          </div>

          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Type or paste text to scan for sensitive data..."
            className="w-full h-32 bg-sentinel-dark border border-sentinel-border rounded-xl p-4 text-white placeholder-gray-600 focus:border-blue-500/50 focus:outline-none resize-none font-mono text-sm"
          />

          <button
            onClick={handleScan}
            disabled={scanning || !text.trim()}
            className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 text-white font-semibold transition-all disabled:opacity-50"
          >
            {scanning ? (
              <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            ) : (
              <>
                <HiShieldCheck className="w-5 h-5" />
                Scan Content
              </>
            )}
          </button>

          {/* Scan Result */}
          {result && (
            <div className={`p-4 rounded-xl border ${result.is_risky ? 'border-red-500/30 bg-red-500/5' : 'border-emerald-500/30 bg-emerald-500/5'}`}>
              <div className="flex items-center gap-2 mb-3">
                {result.is_risky ? (
                  <HiExclamationTriangle className="w-5 h-5 text-red-400" />
                ) : (
                  <HiShieldCheck className="w-5 h-5 text-emerald-400" />
                )}
                <span className={`font-semibold ${result.is_risky ? 'text-red-400' : 'text-emerald-400'}`}>
                  {result.message}
                </span>
              </div>

              {result.regex_findings?.length > 0 && (
                <div className="space-y-2 mb-3">
                  <p className="text-xs text-gray-400 font-medium">Regex Findings:</p>
                  {result.regex_findings.map((f, i) => (
                    <div key={i} className={`flex items-center gap-2 px-3 py-2 rounded-lg border ${severityColors[f.severity]}`}>
                      <span className="text-xs font-medium">{f.severity.toUpperCase()}</span>
                      <span className="text-sm">{f.label}</span>
                      <span className="text-xs text-gray-500 font-mono ml-auto">
                        "{f.sample}"
                      </span>
                    </div>
                  ))}
                </div>
              )}

              <div className="flex gap-2 text-xs text-gray-500 mb-3">
                <span>Scan: {result.scan_type}</span>
                <span>•</span>
                <span className="font-mono">Hash: {result.event_hash?.slice(0, 16)}...</span>
              </div>

              {result.is_risky && (
                <div className="flex gap-2">
                  <button
                    onClick={handleOverride}
                    className="flex-1 flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-red-500/20 text-red-400 border border-red-500/30 hover:bg-red-500/30 text-sm font-medium"
                  >
                    <HiPaperAirplane className="w-4 h-4" />
                    Send Anyway (Override)
                  </button>
                  <button
                    onClick={() => { setResult(null); setText(''); }}
                    className="flex-1 px-3 py-2 rounded-lg bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/30 text-sm font-medium"
                  >
                    Cancel & Block
                  </button>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Event Log */}
        <div className="glass-card p-6">
          <h3 className="text-lg font-semibold text-white mb-4">📋 Guard Event Log</h3>
          <div className="space-y-2 max-h-[500px] overflow-y-auto">
            {events.length === 0 ? (
              <p className="text-gray-500 text-sm">No guard events yet. Try scanning some content.</p>
            ) : (
              events.map((event) => (
                <div
                  key={event.id}
                  className="p-3 rounded-lg bg-sentinel-dark/50 border border-sentinel-border"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${event.risk_detected ? 'bg-red-500' : 'bg-emerald-500'}`} />
                      <span className="text-sm text-white">
                        {event.risk_detected ? '⚠️ Threat' : '✅ Clean'}
                      </span>
                      {event.user_override && (
                        <span className="text-xs px-1.5 py-0.5 rounded bg-yellow-500/20 text-yellow-400">
                          overridden
                        </span>
                      )}
                    </div>
                    <span className="text-xs text-gray-600 font-mono">
                      {event.event_hash?.slice(0, 10)}...
                    </span>
                  </div>
                  {event.risk_categories?.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      {event.risk_categories.map((cat, i) => (
                        <span key={i} className="text-xs px-2 py-0.5 rounded-full bg-white/5 text-gray-400">
                          {cat}
                        </span>
                      ))}
                    </div>
                  )}
                  <p className="text-xs text-gray-600 mt-1">
                    {new Date(event.timestamp).toLocaleString()}
                  </p>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

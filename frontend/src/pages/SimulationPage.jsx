import React, { useState, useEffect } from 'react';
import useStore from '../store';
import { simulationAPI } from '../api';
import { HiBolt, HiPlay, HiShieldExclamation, HiUser, HiDocumentText, HiCheck, HiFire, HiCurrencyDollar, HiBanknotes, HiLockClosed, HiExclamationTriangle, HiShieldCheck } from 'react-icons/hi2';

export default function SimulationPage() {
  const { wallet, addNotification, setEnforcement } = useStore();
  const [scenarios, setScenarios] = useState([]);
  const [running, setRunning] = useState(null);
  const [results, setResults] = useState(null);

  useEffect(() => {
    simulationAPI.scenarios().then(res => setScenarios(res.data.scenarios)).catch(() => {});
  }, []);

  const runScenario = async (scenarioId) => {
    setRunning(scenarioId);
    setResults(null);

    try {
      const res = await simulationAPI.run({
        scenario: scenarioId,
        wallet_address: wallet || '0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28',
        count: scenarioId === 'full_demo' ? 1 : 3,
      });

      setResults(res.data);
      // Sync enforcement state from simulation response
      if (res.data.enforcement) {
        setEnforcement(res.data.enforcement);
      }
      addNotification({
        type: 'success',
        title: 'Simulation Complete',
        message: `${scenarioId}: ${res.data.results?.length || res.data.results?.total_events || 0} events generated`,
      });
    } catch (err) {
      addNotification({ type: 'error', message: 'Simulation failed. Is the backend running?' });
    }

    setRunning(null);
  };

  const scenarioIcons = {
    suspicious_login: HiShieldExclamation,
    normal_login: HiUser,
    data_leak: HiDocumentText,
    clean_text: HiCheck,
    burst_attack: HiFire,
    risky_transaction: HiCurrencyDollar,
    safe_transaction: HiBanknotes,
    full_demo: HiBolt,
  };

  const scenarioColors = {
    suspicious_login: 'from-red-600 to-orange-600',
    normal_login: 'from-emerald-600 to-teal-600',
    data_leak: 'from-yellow-600 to-amber-600',
    clean_text: 'from-green-600 to-emerald-600',
    burst_attack: 'from-red-600 to-pink-600',
    risky_transaction: 'from-orange-600 to-red-600',
    safe_transaction: 'from-teal-600 to-cyan-600',
    full_demo: 'from-purple-600 to-blue-600',
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">🎮 Attack Simulation Lab</h1>
        <p className="text-gray-400 text-sm mt-1">
          Simulate real-world attack scenarios to test SentinelX defenses in real-time
        </p>
      </div>

      {/* Scenario Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {scenarios.map((scenario) => {
          const Icon = scenarioIcons[scenario.id] || HiBolt;
          const gradient = scenarioColors[scenario.id] || 'from-blue-600 to-purple-600';

          return (
            <div key={scenario.id} className="glass-card p-6 hover:border-blue-500/30 transition-all group">
              <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${gradient} flex items-center justify-center mb-4 group-hover:shadow-lg transition-all`}>
                <Icon className="w-6 h-6 text-white" />
              </div>
              <h3 className="text-lg font-semibold text-white mb-1">{scenario.name}</h3>
              <p className="text-sm text-gray-400 mb-4">{scenario.description}</p>
              <button
                onClick={() => runScenario(scenario.id)}
                disabled={running !== null}
                className={`w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r ${gradient} hover:opacity-90 text-white font-medium text-sm transition-all disabled:opacity-50`}
              >
                {running === scenario.id ? (
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                ) : (
                  <>
                    <HiPlay className="w-4 h-4" />
                    Run Simulation
                  </>
                )}
              </button>
            </div>
          );
        })}
      </div>

      {/* Results */}
      {results && (
        <div className="glass-card p-6">
          <h3 className="text-lg font-semibold text-white mb-4">
            📊 Simulation Results — <span className="text-blue-400">{results.scenario}</span>
          </h3>

          {/* Enforcement State after simulation */}
          {(results.enforcement || results.results?.enforcement) && (() => {
            const enf = results.enforcement || results.results?.enforcement;
            const isActive = enf.security_status === 'active';
            const isStepUp = enf.security_status === 'step_up_required';
            const bgClass = isActive ? 'bg-emerald-500/10 border-emerald-500/30' :
              isStepUp ? 'bg-yellow-500/10 border-yellow-500/30' : 'bg-red-500/10 border-red-500/30';
            const textClass = isActive ? 'text-emerald-400' : isStepUp ? 'text-yellow-400' : 'text-red-400';
            return (
              <div className={`mb-4 p-4 rounded-lg border ${bgClass}`}>
                <div className="flex items-center gap-2 mb-1">
                  {isActive ? <HiShieldCheck className={`w-5 h-5 ${textClass}`} /> :
                   isStepUp ? <HiExclamationTriangle className={`w-5 h-5 ${textClass}`} /> :
                   <HiLockClosed className={`w-5 h-5 ${textClass}`} />}
                  <span className={`text-sm font-bold ${textClass}`}>
                    Enforcement: {enf.security_status.replace('_', ' ').toUpperCase()}
                  </span>
                  <span className={`text-xs ml-auto font-mono ${textClass}`}>
                    Trust: {enf.trust_score}/100
                  </span>
                </div>
                {enf.cooldown_reason && (
                  <p className="text-xs text-gray-400 mt-1">{enf.cooldown_reason}</p>
                )}
              </div>
            );
          })()}

          {/* Full demo has special structure */}
          {results.scenario === 'full_demo' && results.results?.summary && (
            <div className="mb-4 p-4 rounded-lg bg-purple-500/10 border border-purple-500/30">
              <p className="text-sm text-purple-300">{results.results.summary}</p>
              {results.results.merkle_batch && (
                <p className="text-xs text-gray-400 mt-2 font-mono">
                  Merkle Root: {results.results.merkle_batch.merkle_root?.slice(0, 24)}...
                  ({results.results.merkle_batch.event_count} events)
                </p>
              )}
            </div>
          )}

          <div className="space-y-2 max-h-96 overflow-y-auto">
            {(Array.isArray(results.results) ? results.results : results.results?.phases || []).map((event, i) => (
              <div
                key={i}
                className="flex items-center justify-between p-3 rounded-lg bg-sentinel-dark/50 border border-sentinel-border"
              >
                <div className="flex items-center gap-3">
                  <div className={`w-2.5 h-2.5 rounded-full ${
                    event.risk_level === 'high' || event.is_risky ? 'bg-red-500' :
                    event.risk_level === 'medium' ? 'bg-yellow-500' : 'bg-emerald-500'
                  }`} />
                  <div>
                    <p className="text-sm text-white">
                      {event.type === 'suspicious_login' ? '🔴 Suspicious Login' :
                       event.type === 'normal_login' ? '🟢 Normal Login' :
                       event.type === 'data_leak' ? '🟡 Data Leak' :
                       event.type === 'burst_attack' ? '⚡ Burst Attack' :
                       event.type === 'clean_text' ? '✅ Clean Text' :
                       event.type === 'risky_transaction' ? '🔴 Risky Transaction' :
                       event.type === 'safe_transaction' ? '🟢 Safe Transaction' : event.type}
                      {event.phase && <span className="text-xs text-gray-500 ml-2">({event.phase})</span>}
                    </p>
                    <p className="text-xs text-gray-500">
                      {event.country && `${event.city || ''}, ${event.country}`}
                      {event.text_preview && `"${event.text_preview}"`}
                      {event.attempt && `Attempt #${event.attempt}`}
                      {event.amount_eth && `${event.amount_eth} ETH → ${event.recipient || ''}`}
                      {event.status && event.type?.includes('transaction') && ` [${event.status}]`}
                    </p>
                  </div>
                </div>
                <div className="text-right">
                  {event.risk_score !== undefined && (
                    <span className={`text-sm font-mono font-bold ${
                      event.risk_level === 'high' ? 'text-red-400' :
                      event.risk_level === 'medium' ? 'text-yellow-400' : 'text-emerald-400'
                    }`}>
                      {event.risk_score?.toFixed(3)}
                    </span>
                  )}
                  {event.severity && (
                    <span className={`text-xs px-2 py-0.5 rounded-full ${
                      event.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                      event.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                      'bg-yellow-500/20 text-yellow-400'
                    }`}>
                      {event.severity}
                    </span>
                  )}
                  {event.event_hash && (
                    <p className="text-xs text-gray-600 font-mono">{event.event_hash?.slice(0, 10)}...</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

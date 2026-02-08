import React, { useEffect, useState, useRef, useCallback } from 'react';
import useStore from '../store';
import { dashboardAPI, simulationAPI } from '../api';
import RiskTimeline from '../components/RiskTimeline';
import LoginMap from '../components/LoginMap';
import StatsCards from '../components/StatsCards';
import RecentEvents from '../components/RecentEvents';
import SecurityReport from '../components/SecurityReport';
import { HiArrowPath, HiBolt, HiShieldCheck, HiLockClosed, HiExclamationTriangle, HiShieldExclamation } from 'react-icons/hi2';

const POLL_INTERVAL = 15000; // 15 seconds

export default function Dashboard() {
  const { wallet, dashboardData, setDashboardData, setLoading, isLoading, addNotification, setEnforcement } = useStore();
  const [report, setReport] = useState(null);
  const pollRef = useRef(null);

  const fetchDashboard = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const res = await dashboardAPI.overview(wallet);
      setDashboardData(res.data);
      // Sync enforcement state from dashboard
      if (res.data.enforcement) {
        setEnforcement(res.data.enforcement);
      }
    } catch (err) {
      console.error('Dashboard fetch error:', err);
    }
    if (!silent) setLoading(false);
  }, [wallet]);

  useEffect(() => {
    fetchDashboard();
    // Auto-refresh every 15s (silent — no loading spinner)
    pollRef.current = setInterval(() => fetchDashboard(true), POLL_INTERVAL);
    return () => clearInterval(pollRef.current);
  }, [wallet, fetchDashboard]);

  const seedDemoData = async () => {
    setLoading(true);
    try {
      const simRes = await simulationAPI.run({
        scenario: 'full_demo',
        wallet_address: wallet || '0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28',
      });
      // Sync enforcement from simulation if available
      if (simRes.data.enforcement) {
        setEnforcement(simRes.data.enforcement);
      }
      addNotification({ type: 'success', title: 'Demo Data', message: 'Full demo simulation completed!' });
      await fetchDashboard();
    } catch (err) {
      addNotification({ type: 'error', message: 'Failed to seed demo data' });
    }
    setLoading(false);
  };

  const fetchReport = async () => {
    try {
      const res = await dashboardAPI.securityReport(wallet);
      setReport(res.data);
    } catch (err) {
      console.error('Report fetch error:', err);
    }
  };

  const data = dashboardData;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Dashboard</h1>
          <p className="text-gray-400 text-sm mt-1">Real-time threat monitoring and analytics</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={seedDemoData}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-teal-500/20 text-teal-400 border border-teal-500/30 hover:bg-teal-500/30 transition-all text-sm font-medium"
          >
            <HiBolt className="w-4 h-4" />
            Seed Demo Data
          </button>
          <button
            onClick={fetchReport}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/30 transition-all text-sm font-medium"
          >
            📊 Security Report
          </button>
          <button
            onClick={() => fetchDashboard(false)}
            disabled={isLoading}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-white/5 text-gray-300 border border-white/10 hover:bg-white/10 transition-all text-sm font-medium"
          >
            <HiArrowPath className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Trust Score + Stats Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Trust Score Card */}
        <div className={`bg-white/[0.03] backdrop-blur-sm rounded-2xl p-6 border flex flex-col items-center justify-center ${data?.trust_score?.level === 'trusted' ? 'border-emerald-500/30' :
            data?.trust_score?.level === 'monitoring' ? 'border-yellow-500/30' :
              data?.trust_score?.level === 'high_risk' ? 'border-red-500/30' : 'border-white/10'
          }`}>
          <div className="flex items-center gap-2 mb-2">
            <HiShieldCheck className={`w-6 h-6 ${data?.trust_score?.level === 'trusted' ? 'text-emerald-400' :
                data?.trust_score?.level === 'monitoring' ? 'text-yellow-400' : 'text-red-400'
              }`} />
            <span className="text-sm font-semibold text-gray-300">Trust Score</span>
          </div>
          <p className={`text-4xl font-bold ${data?.trust_score?.level === 'trusted' ? 'text-emerald-400' :
              data?.trust_score?.level === 'monitoring' ? 'text-yellow-400' : 'text-red-400'
            }`}>
            {data?.trust_score?.score ?? '--'}
          </p>
          <span className={`text-xs font-medium mt-1 px-2 py-0.5 rounded-full ${data?.trust_score?.level === 'trusted' ? 'bg-emerald-500/20 text-emerald-400' :
              data?.trust_score?.level === 'monitoring' ? 'bg-yellow-500/20 text-yellow-400' :
                data?.trust_score?.level === 'high_risk' ? 'bg-red-500/20 text-red-400' : 'bg-gray-500/20 text-gray-400'
            }`}>
            {data?.trust_score?.level === 'trusted' ? 'TRUSTED' :
              data?.trust_score?.level === 'monitoring' ? 'MONITORING' :
                data?.trust_score?.level === 'high_risk' ? 'HIGH RISK' : 'N/A'}
          </span>

          {/* Enforcement Status Badge */}
          {data?.enforcement && data.enforcement.security_status !== 'active' && (
            <div className={`mt-3 flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold ${data.enforcement.security_status === 'locked' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                data.enforcement.security_status === 'restricted' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                  'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
              }`}>
              {data.enforcement.security_status === 'locked' ? (
                <><HiLockClosed className="w-3 h-3" /> LOCKED</>
              ) : data.enforcement.security_status === 'restricted' ? (
                <><HiShieldExclamation className="w-3 h-3" /> RESTRICTED</>
              ) : (
                <><HiExclamationTriangle className="w-3 h-3" /> STEP-UP</>
              )}
            </div>
          )}
          {data?.enforcement && data.enforcement.security_status === 'active' && (
            <div className="mt-3 flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
              <HiShieldCheck className="w-3 h-3" /> ACTIVE
            </div>
          )}
        </div>

        {/* Stats Cards in remaining 3 cols */}
        <div className="lg:col-span-3">
          <StatsCards stats={data?.stats} />
        </div>
      </div>

      {/* Security Report */}
      {report && <SecurityReport report={report} />}

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <RiskTimeline timeline={data?.risk_timeline || []} />
        <LoginMap points={data?.map_points || []} />
      </div>

      {/* Events Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <RecentEvents
          title="🔐 Recent Logins"
          events={data?.recent_logins || []}
          type="login"
        />
        <RecentEvents
          title="🛡️ Guard Events"
          events={data?.recent_guard_events || []}
          type="guard"
        />
      </div>
    </div>
  );
}

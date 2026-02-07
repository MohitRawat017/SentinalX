import React, { useEffect, useState } from 'react';
import useStore from '../store';
import { dashboardAPI, simulationAPI } from '../api';
import RiskTimeline from '../components/RiskTimeline';
import LoginMap from '../components/LoginMap';
import StatsCards from '../components/StatsCards';
import RecentEvents from '../components/RecentEvents';
import SecurityReport from '../components/SecurityReport';
import { HiArrowPath, HiBolt } from 'react-icons/hi2';

export default function Dashboard() {
  const { wallet, dashboardData, setDashboardData, setLoading, isLoading, addNotification } = useStore();
  const [report, setReport] = useState(null);

  const fetchDashboard = async () => {
    setLoading(true);
    try {
      const res = await dashboardAPI.overview(wallet);
      setDashboardData(res.data);
    } catch (err) {
      console.error('Dashboard fetch error:', err);
    }
    setLoading(false);
  };

  const seedDemoData = async () => {
    setLoading(true);
    try {
      await simulationAPI.run({
        scenario: 'full_demo',
        wallet_address: wallet || '0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28',
      });
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

  useEffect(() => {
    fetchDashboard();
  }, [wallet]);

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
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-purple-500/20 text-purple-400 border border-purple-500/30 hover:bg-purple-500/30 transition-all text-sm font-medium"
          >
            <HiBolt className="w-4 h-4" />
            Seed Demo Data
          </button>
          <button
            onClick={fetchReport}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/30 transition-all text-sm font-medium"
          >
            📊 Security Report
          </button>
          <button
            onClick={fetchDashboard}
            disabled={isLoading}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-500/20 text-blue-400 border border-blue-500/30 hover:bg-blue-500/30 transition-all text-sm font-medium"
          >
            <HiArrowPath className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <StatsCards stats={data?.stats} />

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

import React from 'react';
import { HiShieldCheck, HiExclamationTriangle, HiEye, HiLink, HiUsers, HiArrowTrendingUp, HiCurrencyDollar } from 'react-icons/hi2';

export default function StatsCards({ stats }) {
  if (!stats) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
        {[...Array(6)].map((_, i) => (
          <div key={i} className="bg-white/[0.03] backdrop-blur-sm rounded-2xl border border-white/10 p-4 animate-pulse">
            <div className="h-4 bg-gray-700 rounded w-2/3 mb-2" />
            <div className="h-8 bg-gray-700 rounded w-1/2" />
          </div>
        ))}
      </div>
    );
  }

  const cards = [
    {
      label: 'Total Logins',
      value: stats.total_logins,
      icon: HiUsers,
      color: 'text-blue-400',
      bg: 'bg-blue-500/10',
      border: 'border-blue-500/20',
    },
    {
      label: 'Avg Risk',
      value: stats.avg_risk_score?.toFixed(2),
      icon: HiArrowTrendingUp,
      color: stats.avg_risk_score > 0.5 ? 'text-red-400' : 'text-emerald-400',
      bg: stats.avg_risk_score > 0.5 ? 'bg-red-500/10' : 'bg-emerald-500/10',
      border: stats.avg_risk_score > 0.5 ? 'border-red-500/20' : 'border-emerald-500/20',
    },
    {
      label: 'High Risk',
      value: stats.high_risk_logins,
      icon: HiExclamationTriangle,
      color: 'text-red-400',
      bg: 'bg-red-500/10',
      border: 'border-red-500/20',
    },
    {
      label: 'Guard Scans',
      value: stats.total_guard_scans,
      icon: HiEye,
      color: 'text-purple-400',
      bg: 'bg-purple-500/10',
      border: 'border-purple-500/20',
    },
    {
      label: 'Threats Blocked',
      value: stats.threats_detected,
      icon: HiShieldCheck,
      color: 'text-yellow-400',
      bg: 'bg-yellow-500/10',
      border: 'border-yellow-500/20',
    },
    {
      label: 'On-Chain Events',
      value: stats.events_on_chain,
      icon: HiLink,
      color: 'text-cyan-400',
      bg: 'bg-cyan-500/10',
      border: 'border-cyan-500/20',
    },
    {
      label: 'Transactions',
      value: stats.total_transactions,
      icon: HiCurrencyDollar,
      color: 'text-emerald-400',
      bg: 'bg-emerald-500/10',
      border: 'border-emerald-500/20',
    },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
      {cards.map(({ label, value, icon: Icon, color, bg, border }) => (
        <div key={label} className={`bg-white/[0.03] backdrop-blur-sm rounded-2xl p-4 border ${border} hover:scale-105 transition-transform`}>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-gray-500 font-medium">{label}</span>
            <div className={`p-1.5 rounded-lg ${bg}`}>
              <Icon className={`w-3.5 h-3.5 ${color}`} />
            </div>
          </div>
          <p className={`text-2xl font-bold ${color}`}>{value ?? 0}</p>
        </div>
      ))}
    </div>
  );
}

import React from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import useStore from '../store';
import { HiShieldCheck, HiChartBar, HiChatBubbleLeftRight, HiLink, HiBeaker, HiArrowRightOnRectangle } from 'react-icons/hi2';

export default function Navbar() {
  const { isAuthenticated, wallet, riskLevel, dashboardData, logout } = useStore();
  const location = useLocation();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  const navItems = [
    { path: '/dashboard', label: 'Dashboard', icon: HiChartBar },
    { path: '/chat', label: 'Chat', icon: HiChatBubbleLeftRight },
    { path: '/audit', label: 'Audit Trail', icon: HiLink },
    { path: '/simulation', label: 'Simulation', icon: HiBeaker },
  ];

  const isActive = (path) => location.pathname === path;

  const riskColor = {
    low: 'bg-emerald-500',
    medium: 'bg-yellow-500',
    high: 'bg-red-500',
  };

  return (
    <nav className="border-b border-sentinel-border bg-sentinel-darker/80 backdrop-blur-lg sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <Link to="/" className="flex items-center gap-2 group">
            <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center group-hover:shadow-lg group-hover:shadow-blue-500/25 transition-all">
              <HiShieldCheck className="w-5 h-5 text-white" />
            </div>
            <span className="text-lg font-bold bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
              SentinelX
            </span>
          </Link>

          {/* Navigation */}
          {isAuthenticated && (
            <div className="flex items-center gap-1">
              {navItems.map(({ path, label, icon: Icon }) => (
                <Link
                  key={path}
                  to={path}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${
                    isActive(path)
                      ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                      : 'text-gray-400 hover:text-white hover:bg-white/5'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  {label}
                </Link>
              ))}
            </div>
          )}

          {/* Wallet Info */}
          <div className="flex items-center gap-3">
            {isAuthenticated && wallet && (
              <>
                {dashboardData?.trust_score && (
                  <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg border ${
                    dashboardData.trust_score.level === 'trusted' ? 'bg-emerald-500/10 border-emerald-500/30' :
                    dashboardData.trust_score.level === 'monitoring' ? 'bg-yellow-500/10 border-yellow-500/30' :
                    'bg-red-500/10 border-red-500/30'
                  }`}>
                    <HiShieldCheck className={`w-3.5 h-3.5 ${
                      dashboardData.trust_score.level === 'trusted' ? 'text-emerald-400' :
                      dashboardData.trust_score.level === 'monitoring' ? 'text-yellow-400' : 'text-red-400'
                    }`} />
                    <span className={`text-xs font-bold ${
                      dashboardData.trust_score.level === 'trusted' ? 'text-emerald-400' :
                      dashboardData.trust_score.level === 'monitoring' ? 'text-yellow-400' : 'text-red-400'
                    }`}>
                      {dashboardData.trust_score.score}
                    </span>
                  </div>
                )}
                {riskLevel && !dashboardData?.trust_score && (
                  <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                    riskLevel === 'low' ? 'risk-low' : riskLevel === 'medium' ? 'risk-medium' : 'risk-high'
                  }`}>
                    {riskLevel.toUpperCase()}
                  </span>
                )}
                <div className="flex items-center gap-2 bg-sentinel-card border border-sentinel-border rounded-lg px-3 py-1.5">
                  <div className={`w-2 h-2 rounded-full ${riskColor[riskLevel] || 'bg-blue-500'} pulse-dot`} />
                  <span className="text-sm font-mono text-gray-300">
                    {wallet.slice(0, 6)}...{wallet.slice(-4)}
                  </span>
                </div>
                <button
                  onClick={handleLogout}
                  className="p-2 text-gray-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-all"
                  title="Disconnect"
                >
                  <HiArrowRightOnRectangle className="w-4 h-4" />
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    </nav>
  );
}

import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import useStore from './store';
import Navbar from './components/Navbar';
import Notifications from './components/Notifications';
import LoginPage from './pages/LoginPage';
import Dashboard from './pages/Dashboard';
import ChatPage from './pages/ChatPage';
import AuditPage from './pages/AuditPage';
import SimulationPage from './pages/SimulationPage';
import LandingPage from './components/modal-style/LandingPage';
import { HiShieldExclamation, HiLockClosed, HiExclamationTriangle } from 'react-icons/hi2';

function EnforcementBanner() {
  const { securityStatus, lockedUntil } = useStore();

  if (securityStatus === 'active') return null;

  const config = {
    step_up_required: {
      icon: HiExclamationTriangle,
      bg: 'bg-yellow-500/10 border-yellow-500/30',
      text: 'text-yellow-400',
      message: 'Step-up verification required. Some sensitive actions need wallet re-confirmation.',
    },
    restricted: {
      icon: HiShieldExclamation,
      bg: 'bg-red-500/10 border-red-500/30',
      text: 'text-red-400',
      message: 'Suspicious behavior detected. SentinelX has temporarily restricted sensitive actions to protect your assets.',
    },
    locked: {
      icon: HiLockClosed,
      bg: 'bg-red-500/10 border-red-500/30',
      text: 'text-red-400',
      message: `Account temporarily locked.${lockedUntil ? ` Unlocks at ${new Date(lockedUntil).toLocaleTimeString()}.` : ''}`,
    },
  };

  const c = config[securityStatus];
  if (!c) return null;
  const Icon = c.icon;

  return (
    <div className={`border-b ${c.bg} px-4 py-2`}>
      <div className="max-w-7xl mx-auto flex items-center gap-2">
        <Icon className={`w-4 h-4 ${c.text} flex-shrink-0`} />
        <span className={`text-sm font-medium ${c.text}`}>{c.message}</span>
      </div>
    </div>
  );
}

function App() {
  const { isAuthenticated } = useStore();

  // Full-screen landing page when not authenticated
  if (!isAuthenticated) {
    return (
      <>
        <Notifications />
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </>
    );
  }

  // Authenticated layout with navbar
  return (
    <div className="min-h-screen bg-[#0a0a0f]">
      <Navbar />
      <EnforcementBanner />
      <Notifications />
      <main className="max-w-7xl mx-auto px-4 py-6">
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" />} />
          <Route path="/login" element={<Navigate to="/dashboard" />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/chat" element={<ChatPage />} />
          <Route path="/audit" element={<AuditPage />} />
          <Route path="/simulation" element={<SimulationPage />} />
        </Routes>
      </main>
    </div>
  );
}

export default App;

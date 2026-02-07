import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import useStore from './store';
import Navbar from './components/Navbar';
import Notifications from './components/Notifications';
import LoginPage from './pages/LoginPage';
import Dashboard from './pages/Dashboard';
import GuardLayerPage from './pages/GuardLayerPage';
import AuditPage from './pages/AuditPage';
import SimulationPage from './pages/SimulationPage';

function App() {
  const { isAuthenticated } = useStore();

  return (
    <div className="min-h-screen animated-gradient">
      <Navbar />
      <Notifications />
      <main className="max-w-7xl mx-auto px-4 py-6">
        <Routes>
          <Route path="/" element={
            isAuthenticated ? <Navigate to="/dashboard" /> : <LoginPage />
          } />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/guard" element={<GuardLayerPage />} />
          <Route path="/audit" element={<AuditPage />} />
          <Route path="/simulation" element={<SimulationPage />} />
        </Routes>
      </main>
    </div>
  );
}

export default App;

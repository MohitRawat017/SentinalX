import React, { useState, useEffect } from 'react';
import { auditAPI } from '../api';
import useStore from '../store';
import { HiLink, HiCheckCircle, HiXCircle, HiArrowPath } from 'react-icons/hi2';

export default function AuditPage() {
  const { addNotification } = useStore();
  const [stats, setStats] = useState(null);
  const [batches, setBatches] = useState([]);
  const [pending, setPending] = useState([]);
  const [verifyHash, setVerifyHash] = useState('');
  const [verifyRoot, setVerifyRoot] = useState('');
  const [verifyResult, setVerifyResult] = useState(null);

  const fetchData = async () => {
    try {
      const [statsRes, batchesRes, pendingRes] = await Promise.all([
        auditAPI.stats(),
        auditAPI.batches(),
        auditAPI.pending(),
      ]);
      setStats(statsRes.data);
      setBatches(batchesRes.data.batches || []);
      setPending(pendingRes.data.pending || []);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => { fetchData(); }, []);

  const handleCreateBatch = async () => {
    try {
      const res = await auditAPI.createBatch();
      addNotification({
        type: res.data.success ? 'success' : 'warning',
        title: 'Merkle Batch',
        message: res.data.message,
      });
      fetchData();
    } catch (err) {
      addNotification({ type: 'error', message: 'Failed to create batch' });
    }
  };

  const handleVerify = async () => {
    if (!verifyHash || !verifyRoot) return;
    try {
      const res = await auditAPI.getProof(verifyRoot, verifyHash);
      setVerifyResult(res.data);
    } catch (err) {
      setVerifyResult({ success: false, message: 'Verification failed' });
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">⛓️ On-Chain Audit Trail</h1>
          <p className="text-gray-400 text-sm mt-1">
            Merkle-batched event proofs on Ethereum Sepolia
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleCreateBatch}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/30 transition-all text-sm font-medium"
          >
            <HiLink className="w-4 h-4" />
            Create Batch Now
          </button>
          <button
            onClick={fetchData}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-500/20 text-blue-400 border border-blue-500/30 hover:bg-blue-500/30 transition-all text-sm font-medium"
          >
            <HiArrowPath className="w-4 h-4" />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-3 gap-4">
          <div className="glass-card p-4">
            <p className="text-xs text-gray-500">Pending Events</p>
            <p className="text-2xl font-bold text-yellow-400">{stats.pending_events}</p>
          </div>
          <div className="glass-card p-4">
            <p className="text-xs text-gray-500">Total Batches</p>
            <p className="text-2xl font-bold text-cyan-400">{stats.total_batches}</p>
          </div>
          <div className="glass-card p-4">
            <p className="text-xs text-gray-500">Events On-Chain</p>
            <p className="text-2xl font-bold text-emerald-400">{stats.total_events_batched}</p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Batches */}
        <div className="glass-card p-6">
          <h3 className="text-lg font-semibold text-white mb-4">🌲 Merkle Batches</h3>
          <div className="space-y-3 max-h-96 overflow-y-auto">
            {batches.length === 0 ? (
              <p className="text-gray-500 text-sm">No batches created yet.</p>
            ) : (
              batches.map((batch) => (
                <div key={batch.id} className="p-4 rounded-lg bg-sentinel-dark/50 border border-sentinel-border">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-white">{batch.id}</span>
                    <span className={`text-xs px-2 py-0.5 rounded-full ${
                      batch.status === 'confirmed' ? 'bg-emerald-500/20 text-emerald-400' :
                      batch.status === 'submitted' ? 'bg-blue-500/20 text-blue-400' :
                      'bg-yellow-500/20 text-yellow-400'
                    }`}>
                      {batch.status}
                    </span>
                  </div>
                  <p className="text-xs font-mono text-gray-400 mb-1 break-all">
                    Root: {batch.merkle_root}
                  </p>
                  <div className="flex items-center justify-between text-xs text-gray-500">
                    <span>{batch.event_count} events</span>
                    <span>{new Date(batch.created_at).toLocaleString()}</span>
                  </div>
                  {batch.tx_hash && (
                    <a
                      href={`https://sepolia.etherscan.io/tx/${batch.tx_hash}`}
                      target="_blank"
                      rel="noreferrer"
                      className="text-xs text-blue-400 hover:underline mt-1 block"
                    >
                      View on Etherscan →
                    </a>
                  )}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Verify */}
        <div className="space-y-6">
          <div className="glass-card p-6">
            <h3 className="text-lg font-semibold text-white mb-4">🔍 Verify Event Inclusion</h3>
            <div className="space-y-3">
              <div>
                <label className="text-xs text-gray-400 block mb-1">Event Hash</label>
                <input
                  type="text"
                  value={verifyHash}
                  onChange={(e) => setVerifyHash(e.target.value)}
                  placeholder="0xabc123..."
                  className="w-full bg-sentinel-dark border border-sentinel-border rounded-lg p-3 text-white text-sm font-mono focus:border-blue-500/50 focus:outline-none"
                />
              </div>
              <div>
                <label className="text-xs text-gray-400 block mb-1">Merkle Root</label>
                <input
                  type="text"
                  value={verifyRoot}
                  onChange={(e) => setVerifyRoot(e.target.value)}
                  placeholder="0xdef456..."
                  className="w-full bg-sentinel-dark border border-sentinel-border rounded-lg p-3 text-white text-sm font-mono focus:border-blue-500/50 focus:outline-none"
                />
                {batches.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-2">
                    {batches.slice(0, 3).map((b) => (
                      <button
                        key={b.id}
                        onClick={() => setVerifyRoot(b.merkle_root)}
                        className="text-xs px-2 py-0.5 rounded bg-white/5 text-gray-400 hover:text-white"
                      >
                        {b.id}: {b.merkle_root.slice(0, 12)}...
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <button
                onClick={handleVerify}
                className="w-full px-4 py-2 rounded-lg bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/30 text-sm font-medium"
              >
                Verify Inclusion Proof
              </button>
              {verifyResult && (
                <div className={`p-3 rounded-lg border ${
                  verifyResult.success ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-red-500/30 bg-red-500/5'
                }`}>
                  <div className="flex items-center gap-2">
                    {verifyResult.success ? (
                      <HiCheckCircle className="w-5 h-5 text-emerald-400" />
                    ) : (
                      <HiXCircle className="w-5 h-5 text-red-400" />
                    )}
                    <span className="text-sm">{verifyResult.message}</span>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Pending Events */}
          <div className="glass-card p-6">
            <h3 className="text-lg font-semibold text-white mb-4">
              ⏳ Pending Events ({pending.length})
            </h3>
            <div className="space-y-2 max-h-48 overflow-y-auto">
              {pending.length === 0 ? (
                <p className="text-gray-500 text-sm">No pending events.</p>
              ) : (
                pending.map((event, i) => (
                  <div key={i} className="flex justify-between p-2 rounded bg-sentinel-dark/50 text-xs">
                    <span className="text-gray-400 font-mono">{event.event_hash?.slice(0, 20)}...</span>
                    <span className="text-gray-500">{event.event_type}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

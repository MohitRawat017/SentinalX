import React, { useState, useEffect } from 'react';
import { auditAPI } from '../api';
import useStore from '../store';
import { HiLink, HiCheckCircle, HiXCircle, HiArrowPath, HiBeaker } from 'react-icons/hi2';

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
      setVerifyResult({ success: false, message: 'Event not found in this batch' });
    }
  };

  const handleUseSample = () => {
    if (!batches || batches.length === 0) {
      addNotification({ type: 'warning', title: 'No Data', message: 'No sample events available. Create a batch first.' });
      return;
    }
    const firstBatch = batches[0];
    const hashes = firstBatch.event_hashes || [];
    if (hashes.length === 0) {
      addNotification({ type: 'warning', title: 'No Events', message: 'This batch has no event hashes to verify.' });
      return;
    }
    setVerifyHash(hashes[0]);
    setVerifyRoot(firstBatch.merkle_root || '');
    setVerifyResult(null);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-white">Security Evidence & Blockchain Proofs</h1>
          <p className="text-sm text-gray-400 mt-1">
            Tamper-proof security logs anchored on Ethereum
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleCreateBatch}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/30 transition-all text-sm font-medium"
          >
            <HiLink className="w-4 h-4" />
            Create Batch Now
          </button>
          <button
            onClick={fetchData}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-white/5 text-gray-300 border border-white/10 hover:bg-white/10 transition-all text-sm font-medium"
          >
            <HiArrowPath className="w-4 h-4" />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-3 gap-4">
          <div className="bg-white/[0.03] backdrop-blur-sm rounded-2xl border border-white/10 p-4">
            <p className="text-xs text-gray-500">Pending Events</p>
            <p className="text-2xl font-bold text-yellow-400">{stats.pending_events}</p>
          </div>
          <div className="bg-white/[0.03] backdrop-blur-sm rounded-2xl border border-white/10 p-4">
            <p className="text-xs text-gray-500">Total Batches</p>
            <p className="text-2xl font-bold text-cyan-400">{stats.total_batches}</p>
          </div>
          <div className="bg-white/[0.03] backdrop-blur-sm rounded-2xl border border-white/10 p-4">
            <p className="text-xs text-gray-500">Events On-Chain</p>
            <p className="text-2xl font-bold text-emerald-400">{stats.total_events_batched}</p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Batches */}
        <div className="bg-white/[0.03] backdrop-blur-sm rounded-2xl border border-white/10 p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Proof Batches</h3>
          <div className="space-y-3 max-h-96 overflow-y-auto">
            {batches.length === 0 ? (
              <p className="text-gray-500 text-sm">No batches created yet. Click "Create Batch Now" to start.</p>
            ) : (
              batches.map((batch) => (
                <div key={batch.id} className="p-4 rounded-lg bg-white/[0.02] border border-white/5">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-white">{batch.id}</span>
                    <span className={`text-xs px-2 py-0.5 rounded-full ${batch.status === 'confirmed' ? 'bg-emerald-500/20 text-emerald-400' :
                        batch.status === 'submitted' ? 'bg-blue-500/20 text-blue-400' :
                          'bg-yellow-500/20 text-yellow-400'
                      }`}>
                      {batch.status}
                    </span>
                  </div>
                  <p className="text-xs font-mono text-gray-400 mb-1 break-all">
                    Batch Proof Root: {batch.merkle_root}
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
                      className="text-xs text-emerald-400 hover:underline mt-1 block"
                    >
                      View on Etherscan
                    </a>
                  )}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Verify */}
        <div className="space-y-6">
          <div className="bg-white/[0.03] backdrop-blur-sm rounded-2xl border border-white/10 p-6">
            <h3 className="text-lg font-semibold text-white mb-4">Verify Security Event Proof</h3>
            <div className="space-y-3">
              <div>
                <label className="text-xs text-gray-400 block mb-1">Event ID (Event Hash)</label>
                <input
                  type="text"
                  value={verifyHash}
                  onChange={(e) => { setVerifyHash(e.target.value); setVerifyResult(null); }}
                  placeholder="0xabc123..."
                  className="w-full bg-white/5 border border-white/10 rounded-lg p-3 text-white text-sm font-mono focus:border-emerald-500/50 focus:outline-none"
                />
                <p className="text-xs text-gray-500 mt-1">Unique fingerprint of a single security event</p>
              </div>
              <div>
                <label className="text-xs text-gray-400 block mb-1">Batch Proof Root</label>
                <input
                  type="text"
                  value={verifyRoot}
                  onChange={(e) => { setVerifyRoot(e.target.value); setVerifyResult(null); }}
                  placeholder="0xdef456..."
                  className="w-full bg-white/5 border border-white/10 rounded-lg p-3 text-white text-sm font-mono focus:border-emerald-500/50 focus:outline-none"
                />
                <p className="text-xs text-gray-500 mt-1">Blockchain proof representing a batch of events</p>
                {batches.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-2">
                    {batches.slice(0, 3).map((b) => (
                      <button
                        key={b.id}
                        onClick={() => { setVerifyRoot(b.merkle_root); setVerifyResult(null); }}
                        className="text-xs px-2 py-0.5 rounded bg-white/5 text-gray-400 hover:text-white"
                      >
                        {b.id}: {b.merkle_root.slice(0, 12)}...
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <div className="flex gap-2">
                <button
                  onClick={handleVerify}
                  disabled={!verifyHash || !verifyRoot}
                  className="flex-1 px-4 py-2 rounded-lg bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/30 text-sm font-medium disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  Verify Proof
                </button>
                <button
                  onClick={handleUseSample}
                  disabled={!batches?.length}
                  className="px-4 py-2 rounded-lg border border-gray-500/50 text-gray-300 hover:bg-white/5 text-sm font-medium disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2"
                >
                  <HiBeaker className="w-4 h-4" />
                  Use Sample Event
                </button>
              </div>
              {verifyResult && (
                <div className={`p-3 rounded-lg border ${verifyResult.success ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-red-500/30 bg-red-500/5'
                  }`}>
                  <div className="flex items-center gap-2">
                    {verifyResult.success ? (
                      <HiCheckCircle className="w-5 h-5 text-emerald-400" />
                    ) : (
                      <HiXCircle className="w-5 h-5 text-red-400" />
                    )}
                    <span className={`text-sm ${verifyResult.success ? 'text-emerald-400' : 'text-red-400'}`}>
                      {verifyResult.success
                        ? 'Event is cryptographically proven to exist on-chain'
                        : 'Event not found in this batch'}
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Pending Events */}
          <div className="glass-card p-6">
            <h3 className="text-lg font-semibold text-white mb-4">
              Pending Events ({pending.length})
            </h3>
            <div className="space-y-2 max-h-48 overflow-y-auto">
              {pending.length === 0 ? (
                <p className="text-gray-500 text-sm">No pending events.</p>
              ) : (
                pending.map((event, i) => (
                  <div key={i} className="flex justify-between p-2 rounded bg-white/[0.02] text-xs">
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

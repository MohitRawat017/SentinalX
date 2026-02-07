import React from 'react';
import ReactMarkdown from 'react-markdown';

export default function SecurityReport({ report }) {
  if (!report) return null;

  const levelColors = {
    '🟢 LOW': 'border-emerald-500/30 bg-emerald-500/5',
    '🟡 MEDIUM': 'border-yellow-500/30 bg-yellow-500/5',
    '🔴 HIGH': 'border-red-500/30 bg-red-500/5',
  };

  return (
    <div className={`glass-card p-6 border ${levelColors[report.threat_level] || 'border-sentinel-border'}`}>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-white">🤖 AI Security Report</h3>
        <span className="text-sm font-medium">{report.threat_level}</span>
      </div>
      <div className="prose prose-invert prose-sm max-w-none">
        <ReactMarkdown>{report.report}</ReactMarkdown>
      </div>
    </div>
  );
}

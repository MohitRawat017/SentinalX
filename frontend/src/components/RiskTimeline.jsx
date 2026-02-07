import React from 'react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, ReferenceLine,
} from 'recharts';

export default function RiskTimeline({ timeline }) {
  const data = timeline.map((point, i) => ({
    ...point,
    index: i,
    time: point.timestamp ? new Date(point.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : `#${i}`,
  }));

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      const d = payload[0].payload;
      return (
        <div className="glass-card p-3 text-sm">
          <p className="text-white font-medium">Risk Score: {d.risk_score?.toFixed(3)}</p>
          <p className="text-gray-400">Level: <span className={
            d.risk_level === 'low' ? 'text-emerald-400' :
            d.risk_level === 'medium' ? 'text-yellow-400' : 'text-red-400'
          }>{d.risk_level?.toUpperCase()}</span></p>
          {d.country && <p className="text-gray-400">Location: {d.city}, {d.country}</p>}
          <p className="text-gray-500 text-xs">{d.time}</p>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="glass-card p-6">
      <h3 className="text-lg font-semibold text-white mb-4">📈 Risk Score Timeline</h3>
      {data.length === 0 ? (
        <div className="h-64 flex items-center justify-center text-gray-500">
          No login events yet. Run a simulation to see data.
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={280}>
          <AreaChart data={data}>
            <defs>
              <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
            <XAxis dataKey="time" stroke="#4b5563" tick={{ fontSize: 11 }} />
            <YAxis domain={[0, 1]} stroke="#4b5563" tick={{ fontSize: 11 }} />
            <Tooltip content={<CustomTooltip />} />
            <ReferenceLine y={0.3} stroke="#10b981" strokeDasharray="5 5" label={{ value: 'Low', fill: '#10b981', fontSize: 10 }} />
            <ReferenceLine y={0.7} stroke="#ef4444" strokeDasharray="5 5" label={{ value: 'High', fill: '#ef4444', fontSize: 10 }} />
            <Area
              type="monotone"
              dataKey="risk_score"
              stroke="#3b82f6"
              strokeWidth={2}
              fill="url(#riskGradient)"
              dot={(props) => {
                const { cx, cy, payload } = props;
                const color = payload.risk_level === 'high' ? '#ef4444' :
                              payload.risk_level === 'medium' ? '#f59e0b' : '#10b981';
                return <circle cx={cx} cy={cy} r={4} fill={color} stroke={color} strokeWidth={1} />;
              }}
            />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}

import React from 'react';

export default function RecentEvents({ title, events, type }) {
  if (!events || events.length === 0) {
    return (
      <div className="bg-white/[0.03] backdrop-blur-sm rounded-2xl border border-white/10 p-6">
        <h3 className="text-lg font-semibold text-white mb-4">{title}</h3>
        <p className="text-gray-500 text-sm">No events recorded yet.</p>
      </div>
    );
  }

  return (
    <div className="glass-card p-6">
      <h3 className="text-lg font-semibold text-white mb-4">{title}</h3>
      <div className="space-y-2 max-h-80 overflow-y-auto">
        {events.map((event, i) => (
          <div
            key={i}
            className="flex items-center justify-between p-3 rounded-lg bg-white/[0.02] border border-white/5 hover:border-emerald-500/20 transition-all"
          >
            <div className="flex items-center gap-3">
              {type === 'login' ? (
                <>
                  <div className={`w-2.5 h-2.5 rounded-full ${event.risk_level === 'high' ? 'bg-red-500' :
                      event.risk_level === 'medium' ? 'bg-yellow-500' : 'bg-emerald-500'
                    }`} />
                  <div>
                    <p className="text-sm text-white font-mono">
                      {event.wallet?.slice(0, 8)}...{event.wallet?.slice(-4)}
                    </p>
                    <p className="text-xs text-gray-500">
                      {event.city && event.country ? `${event.city}, ${event.country}` : 'Unknown location'}
                    </p>
                  </div>
                </>
              ) : (
                <>
                  <div className={`w-2.5 h-2.5 rounded-full ${event.risk_detected ? 'bg-red-500' : 'bg-emerald-500'
                    }`} />
                  <div>
                    <p className="text-sm text-white">
                      {event.risk_detected ? '⚠️ Threat Detected' : '✅ Clean'}
                    </p>
                    <p className="text-xs text-gray-500">
                      {event.categories?.join(', ') || 'No issues'}
                      {event.user_override && ' (overridden)'}
                    </p>
                  </div>
                </>
              )}
            </div>

            <div className="text-right">
              {type === 'login' && (
                <span className={`text-sm font-mono font-medium ${event.risk_level === 'high' ? 'text-red-400' :
                    event.risk_level === 'medium' ? 'text-yellow-400' : 'text-emerald-400'
                  }`}>
                  {event.risk_score?.toFixed(3)}
                </span>
              )}
              <p className="text-xs text-gray-600 font-mono">
                {event.event_hash?.slice(0, 10)}...
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

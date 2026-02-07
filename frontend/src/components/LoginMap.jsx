import React from 'react';
import { MapContainer, TileLayer, CircleMarker, Popup } from 'react-leaflet';

export default function LoginMap({ points }) {
  const riskColor = (level) => {
    switch (level) {
      case 'high': return '#ef4444';
      case 'medium': return '#f59e0b';
      default: return '#10b981';
    }
  };

  return (
    <div className="bg-white/[0.03] backdrop-blur-sm rounded-2xl border border-white/10 p-6">
      <h3 className="text-lg font-semibold text-white mb-4">🌍 Login Origins</h3>
      {points.length === 0 ? (
        <div className="h-64 flex items-center justify-center text-gray-500 rounded-xl bg-white/[0.02]">
          No geo-located logins yet. Run a simulation to see the map.
        </div>
      ) : (
        <div className="h-[280px] rounded-xl overflow-hidden">
          <MapContainer
            center={[30, 0]}
            zoom={2}
            style={{ height: '100%', width: '100%' }}
            scrollWheelZoom={false}
          >
            <TileLayer
              attribution='&copy; <a href="https://carto.com/">CARTO</a>'
              url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
            />
            {points.map((point, i) => (
              <CircleMarker
                key={i}
                center={[point.lat, point.lng]}
                radius={8 + (point.risk_score || 0) * 12}
                fillColor={riskColor(point.risk_level)}
                color={riskColor(point.risk_level)}
                weight={1}
                opacity={0.8}
                fillOpacity={0.4}
              >
                <Popup>
                  <div className="text-sm">
                    <p className="font-bold">{point.city}, {point.country}</p>
                    <p>Risk: {point.risk_score?.toFixed(3)} ({point.risk_level})</p>
                    <p className="text-xs text-gray-500">{point.timestamp}</p>
                  </div>
                </Popup>
              </CircleMarker>
            ))}
          </MapContainer>
        </div>
      )}
    </div>
  );
}

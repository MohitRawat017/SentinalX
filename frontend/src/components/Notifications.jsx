import React from 'react';
import useStore from '../store';
import { HiXMark, HiCheckCircle, HiExclamationTriangle, HiInformationCircle } from 'react-icons/hi2';

export default function Notifications() {
  const { notifications, removeNotification } = useStore();

  const icons = {
    success: <HiCheckCircle className="w-5 h-5 text-emerald-400" />,
    warning: <HiExclamationTriangle className="w-5 h-5 text-yellow-400" />,
    error: <HiExclamationTriangle className="w-5 h-5 text-red-400" />,
    info: <HiInformationCircle className="w-5 h-5 text-blue-400" />,
  };

  const borders = {
    success: 'border-emerald-500/30',
    warning: 'border-yellow-500/30',
    error: 'border-red-500/30',
    info: 'border-blue-500/30',
  };

  if (notifications.length === 0) return null;

  return (
    <div className="fixed top-20 right-4 z-50 flex flex-col gap-2 max-w-sm">
      {notifications.map((n) => (
        <div
          key={n.id}
          className={`glass-card p-3 flex items-start gap-3 border ${borders[n.type] || borders.info} animate-in slide-in-from-right`}
        >
          {icons[n.type] || icons.info}
          <div className="flex-1">
            {n.title && <p className="text-sm font-semibold text-white">{n.title}</p>}
            <p className="text-sm text-gray-300">{n.message}</p>
          </div>
          <button onClick={() => removeNotification(n.id)} className="text-gray-500 hover:text-white">
            <HiXMark className="w-4 h-4" />
          </button>
        </div>
      ))}
    </div>
  );
}

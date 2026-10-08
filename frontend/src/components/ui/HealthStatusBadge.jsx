import React, { useEffect, useState } from 'react';
import { fetchHealthStatus } from '../../services/api';
import { Activity, CheckCircle, AlertTriangle } from 'lucide-react';

export default function HealthStatusBadge() {
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function checkHealth() {
      const data = await fetchHealthStatus();
      setHealth(data);
      setLoading(false);
    }
    checkHealth();
    const interval = setInterval(checkHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-800/60 border border-slate-700/50 text-xs font-mono text-slate-400">
        <Activity className="w-3.5 h-3.5 animate-pulse text-cyan-400" />
        Checking API status...
      </div>
    );
  }

  const isHealthy = health?.status === 'healthy';

  return (
    <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full border text-xs font-mono transition-all ${
      isHealthy
        ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-400'
        : 'bg-rose-950/40 border-rose-500/30 text-rose-400'
    }`}>
      {isHealthy ? (
        <>
          <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
          <span>Backend Online ({health?.version || 'v1.0.0'})</span>
        </>
      ) : (
        <>
          <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
          <span>Backend Offline</span>
        </>
      )}
    </div>
  );
}

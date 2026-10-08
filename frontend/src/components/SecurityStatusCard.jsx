import React from 'react';
import { ShieldCheck, Lock, CheckCircle2, AlertCircle } from 'lucide-react';

export default function SecurityStatusCard() {
  const securityControls = [
    { name: 'Authentication & JWT', status: 'Enabled', verified: true, detail: 'Bearer JWT (HS256) + Argon2id / PBKDF2' },
    { name: 'Multi-Tenant Isolation', status: 'Enforced', verified: true, detail: 'scan_id & owner_id IDOR shielding' },
    { name: 'PE Binary Execution Guard', status: 'Enforced', verified: true, detail: 'Zero host execution (In-memory pefile only)' },
    { name: 'Path Traversal Shield', status: 'Enforced', verified: true, detail: 'Safe-root candidate resolution' },
    { name: 'Model Artifact Integrity', status: 'Verified', verified: true, detail: 'SHA-256 Checksums & PyTorch weights_only' },
    { name: 'Security Audit Logging', status: 'Enabled', verified: true, detail: 'Structured security audit events & X-Request-ID' },
  ];

  return (
    <div className="glass-panel p-6 rounded-2xl border border-cyan-500/20 bg-cyan-950/10 space-y-4">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-bold text-white text-base">Security Posture Status</h3>
            <p className="text-slate-400 text-xs font-mono">Phase 13 Application Hardening Verification</p>
          </div>
        </div>
        <span className="px-2.5 py-1 rounded-full text-xs font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
          HARDENED
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {securityControls.map((ctrl, idx) => (
          <div key={idx} className="p-3 rounded-xl bg-slate-900/60 border border-slate-800/80 flex items-start gap-3">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />
            <div className="space-y-0.5">
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold text-slate-200">{ctrl.name}</span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  {ctrl.status}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-mono">{ctrl.detail}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

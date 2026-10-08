import React, { useState } from 'react';
import { Shield, LayoutDashboard, UploadCloud, History, FileText, Settings, Menu, X, Bell } from 'lucide-react';
import DashboardOverview from './components/dashboard/DashboardOverview';
import HealthStatusBadge from './components/ui/HealthStatusBadge';
import SecurityStatusCard from './components/SecurityStatusCard';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'upload', label: 'Upload Sample', icon: UploadCloud },
    { id: 'history', label: 'Scan History', icon: History },
    { id: 'report', label: 'Analysis Report', icon: FileText },
    { id: 'settings', label: 'Settings & Security', icon: Settings },
  ];

  return (
    <div className="min-h-screen flex bg-[#090d16] text-slate-100">
      {/* Sidebar */}
      <aside className={`fixed inset-y-0 left-0 z-50 w-64 bg-[#0d1320] border-r border-slate-800 transform ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'} md:translate-x-0 transition-transform duration-200 ease-in-out flex flex-col justify-between`}>
        <div>
          {/* Logo Header */}
          <div className="h-16 flex items-center justify-between px-6 border-b border-slate-800">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                <Shield className="w-6 h-6 stroke-[2.25]" />
              </div>
              <div>
                <span className="font-bold tracking-tight text-white text-lg">PolyShield</span>
                <span className="text-cyan-400 text-xs font-mono font-semibold ml-1">AI</span>
              </div>
            </div>
            <button className="md:hidden text-slate-400 hover:text-white" onClick={() => setSidebarOpen(false)}>
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Navigation Items */}
          <nav className="p-4 space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => {
                    setActiveTab(item.id);
                    setSidebarOpen(false);
                  }}
                  className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl font-medium text-sm transition-all cursor-pointer ${
                    isActive
                      ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 font-semibold'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                  }`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                  {item.label}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Sidebar Footer */}
        <div className="p-4 border-t border-slate-800">
          <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 text-xs text-slate-400 font-mono space-y-1">
            <div className="text-slate-300 font-semibold">PolyShield Platform</div>
            <div>Phase 13 Security</div>
            <div className="text-cyan-400">v1.0.0 Hardened</div>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 md:pl-64 flex flex-col min-h-screen">
        {/* Top Header */}
        <header className="h-16 border-b border-slate-800 bg-[#090d16]/80 backdrop-blur-md sticky top-0 z-40 px-6 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button className="md:hidden text-slate-400 hover:text-white" onClick={() => setSidebarOpen(true)}>
              <Menu className="w-6 h-6" />
            </button>
            <div className="text-sm font-medium text-slate-300 hidden sm:block">
              {navItems.find(i => i.id === activeTab)?.label}
            </div>
          </div>

          <div className="flex items-center gap-4">
            <HealthStatusBadge />
            <button className="p-2 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800/60 border border-transparent hover:border-slate-700 transition-all cursor-pointer">
              <Bell className="w-4 h-4" />
            </button>
            <div className="w-8 h-8 rounded-full bg-cyan-500/20 border border-cyan-500/40 text-cyan-400 flex items-center justify-center font-bold text-xs font-mono">
              SEC
            </div>
          </div>
        </header>

        {/* View Routing Body */}
        <main className="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">
          {activeTab === 'dashboard' && (
            <>
              <DashboardOverview />
              <SecurityStatusCard />
            </>
          )}
          {activeTab === 'upload' && (
            <div className="glass-panel p-8 rounded-2xl text-center space-y-4">
              <UploadCloud className="w-12 h-12 text-cyan-400 mx-auto animate-bounce" />
              <h2 className="text-xl font-bold text-white">PE Executable File Scanner</h2>
              <p className="text-slate-400 text-sm max-w-md mx-auto">
                Hardened PE binary upload scanner. Enforces extension check, MZ magic validation, 50MB payload limits, and isolated storage.
              </p>
            </div>
          )}
          {activeTab === 'history' && (
            <div className="glass-panel p-8 rounded-2xl text-center space-y-4">
              <History className="w-12 h-12 text-cyan-400 mx-auto" />
              <h2 className="text-xl font-bold text-white">Scan History</h2>
              <p className="text-slate-400 text-sm max-w-md mx-auto">
                Scan records and state machine tracking active. View scan IDs via <code>/api/v1/scans</code> endpoint.
              </p>
            </div>
          )}
          {activeTab === 'report' && (
            <div className="glass-panel p-8 rounded-2xl text-center space-y-4">
              <FileText className="w-12 h-12 text-cyan-400 mx-auto" />
              <h2 className="text-xl font-bold text-white">Analysis Report Generator</h2>
              <p className="text-slate-400 text-sm max-w-md mx-auto">
                Sample report format available at <code>/api/v1/scans/sample_id/report</code> endpoint.
              </p>
            </div>
          )}
          {activeTab === 'settings' && (
            <div className="space-y-6">
              <SecurityStatusCard />
              <div className="glass-panel p-8 rounded-2xl space-y-4">
                <h2 className="text-xl font-bold text-white">Platform Settings & Security Policies</h2>
                <div className="space-y-2 text-sm text-slate-300 font-mono">
                  <div>FastAPI Backend Port: 8000</div>
                  <div>Authentication: Bearer JWT (HS256)</div>
                  <div>Authorization: RBAC (ANALYST / ADMIN)</div>
                  <div>Path Traversal Shield: Active (Safe-root relative_to)</div>
                  <div>Model Integrity Checksums: SHA-256 Verified</div>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

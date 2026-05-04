import React, { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Activity, Layers, BarChart2, List } from 'lucide-react';

import CommandSidebar from '../components/layout/CommandSidebar';
import MetricsHUD from '../components/panels/MetricsHUD';
import IncidentFeed from '../components/panels/IncidentFeed';
import GaugePanel from '../components/panels/GaugePanel';
import ThreatTimeline from '../components/panels/ThreatTimeline';
import AnalyticsPanel from '../components/panels/AnalyticsPanel';
import AlertLogPanel from '../components/panels/AlertLogPanel';
import CommandPalette from '../components/ui/CommandPalette';
import ThreatOverlay from '../components/ui/ThreatOverlay';

import { useWebSocket } from '../hooks/useWebSocket';
import { useAlertStore } from '../store/alertStore';
import type { FlowEvent } from '../types';

type Tab = 'live' | 'timeline' | 'analytics' | 'log';

const TABS: { id: Tab; label: string; icon: React.ReactNode }[] = [
  { id: 'live',      label: 'Live Feed',        icon: <Activity size={13} /> },
  { id: 'timeline',  label: 'Threat Timeline',  icon: <Layers size={13} /> },
  { id: 'analytics', label: 'Analytics',        icon: <BarChart2 size={13} /> },
  { id: 'log',       label: 'Alert Log',        icon: <List size={13} /> },
];

interface Props {
  token: string;
  email: string;
  onLogout: () => void;
}

export default function DashboardPage({ token, email, onLogout }: Props) {
  const [activeTab, setActiveTab]     = useState<Tab>('live');
  const [cmdOpen, setCmdOpen]         = useState(false);
  const [criticalEv, setCriticalEv]   = useState<FlowEvent | null>(null);
  const { feed, simActive }           = useAlertStore();
  const prevAlertCount                = useRef(0);

  // Connect WebSocket
  useWebSocket(token);

  const lastCriticalUnix = useRef(0);

  // Detect new CRITICAL events for the overlay — only fire when the unix timestamp
  // changes so the same event does not re-trigger the sound on every feed update.
  useEffect(() => {
    const latest = feed[0];
    if (latest && latest.severity === 'CRITICAL' && latest.fired && latest.unix !== lastCriticalUnix.current) {
      lastCriticalUnix.current = latest.unix;
      setCriticalEv(latest);
    }
  }, [feed]);

  // Global keyboard shortcuts
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') { e.preventDefault(); setCmdOpen(true); return; }
      if (e.key === 'Escape') { setCmdOpen(false); setCriticalEv(null); return; }
      if (!cmdOpen) {
        if (e.key === 'l' || e.key === 'L') setActiveTab('live');
        if (e.key === 't' || e.key === 'T') setActiveTab('timeline');
        if (e.key === 'a' || e.key === 'A') setActiveTab('analytics');
        if (e.key === 'g' || e.key === 'G') setActiveTab('log');
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [cmdOpen]);

  const handleNavigate = useCallback((tab: string) => {
    setActiveTab(tab as Tab);
    setCmdOpen(false);
  }, []);

  return (
    <div style={{ display: 'flex', height: '100vh', width: '100vw', overflow: 'hidden' }}>
      {/* Sidebar */}
      <CommandSidebar
        token={token}
        email={email}
        onLogout={onLogout}
        onCommandPalette={() => setCmdOpen(true)}
      />

      {/* Main workspace */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', minWidth: 0 }}>

        {/* Metrics HUD */}
        <MetricsHUD />

        {/* Simulation mode banner */}
        <AnimatePresence>
          {simActive && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.25 }}
              style={{
                display: 'flex', alignItems: 'center', gap: 10,
                padding: '6px 16px', overflow: 'hidden', flexShrink: 0,
                background: 'rgba(191,95,255,0.05)',
                borderBottom: '1px solid rgba(191,95,255,0.2)',
                fontSize: 12, fontWeight: 500, color: 'var(--sev-sim)',
              }}
              className="animate-sim-border"
            >
              <span className="dot dot-purple animate-breathe" />
              <b>SIMULATION ACTIVE</b>
              <span style={{ color: 'var(--text-dim)', fontSize: 11 }}>— Injected flows are labelled SIM</span>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Tab bar + content */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          {/* Tab bar */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-panel)', padding: '0 4px', flexShrink: 0 }}>
            <div className="tab-bar" style={{ border: 'none', flex: 1 }}>
              {TABS.map(tab => (
                <button
                  key={tab.id}
                  className={`tab-item ${activeTab === tab.id ? 'active' : ''}`}
                  onClick={() => setActiveTab(tab.id)}
                >
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                    {tab.icon} {tab.label}
                  </span>
                </button>
              ))}
            </div>
            {/* Keyboard hints */}
            <div style={{ display: 'flex', gap: 8, paddingRight: 12, fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
              <span>L·T·A·G tabs</span>
              <span>⌘K palette</span>
            </div>
          </div>

          {/* Tab content */}
          <div style={{ flex: 1, overflow: 'hidden', position: 'relative' }}>
            <AnimatePresence mode="wait">
              <motion.div
                key={activeTab}
                initial={{ opacity: 0, x: 6 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -6 }}
                transition={{ duration: 0.18 }}
                style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}
              >
                {activeTab === 'live' && (
                  <div style={{ flex: 1, display: 'grid', gridTemplateColumns: '1fr 280px', gap: 0, overflow: 'hidden' }}>
                    <div style={{ borderRight: '1px solid var(--border-panel)', overflow: 'hidden' }}>
                      <IncidentFeed />
                    </div>
                    <div style={{ overflow: 'hidden' }}>
                      <GaugePanel />
                    </div>
                  </div>
                )}

                {activeTab === 'timeline' && (
                  <div style={{ flex: 1, overflow: 'hidden' }}>
                    <ThreatTimeline />
                  </div>
                )}

                {activeTab === 'analytics' && (
                  <div style={{ flex: 1, overflow: 'auto' }}>
                    <AnalyticsPanel />
                  </div>
                )}

                {activeTab === 'log' && (
                  <div style={{ flex: 1, overflow: 'hidden' }}>
                    <AlertLogPanel token={token} />
                  </div>
                )}
              </motion.div>
            </AnimatePresence>
          </div>
        </div>

        {/* Status bar */}
        <div style={{
          borderTop: '1px solid var(--border-dim)', padding: '4px 14px',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', flexShrink: 0,
          background: 'var(--bg-surface)',
        }}>
          <span>AIPS · AI Intrusion Prevention System · RF+XGBoost</span>
          <span style={{ color: 'var(--text-muted)' }}>{new Date().toLocaleDateString()}</span>
        </div>
      </div>

      {/* Overlays */}
      <CommandPalette
        open={cmdOpen}
        onClose={() => setCmdOpen(false)}
        onNavigate={handleNavigate}
        token={token}
      />
      <ThreatOverlay
        event={criticalEv}
        onDismiss={() => setCriticalEv(null)}
      />
    </div>
  );
}

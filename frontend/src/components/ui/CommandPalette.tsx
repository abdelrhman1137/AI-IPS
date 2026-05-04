import React, { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, Terminal, Activity, Layers, BarChart2, List, Play, Square, RotateCcw, Zap, Crosshair } from 'lucide-react';
import { useAlertStore } from '../../store/alertStore';
import { apiPost } from '../../hooks/useAuth';

interface Command {
  id: string;
  label: string;
  sub?: string;
  icon: React.ReactNode;
  action: () => void;
  group: string;
}

interface Props {
  open: boolean;
  onClose: () => void;
  onNavigate: (tab: string) => void;
  token: string;
}

export default function CommandPalette({ open, onClose, onNavigate, token }: Props) {
  const [query, setQuery]     = useState('');
  const [selected, setSelected] = useState(0);
  const inputRef              = useRef<HTMLInputElement>(null);
  const { running, reset }    = useAlertStore();

    const commands: Command[] = [
    { id: 'start',    label: 'Start Monitoring',     icon: <Play size={14} />,     group: 'Engine',   action: async () => { await apiPost('/engine/start', token); useAlertStore.setState({ running: true }); } },
    { id: 'stop',     label: 'Stop Monitoring',      icon: <Square size={14} />,   group: 'Engine',   action: async () => { await apiPost('/engine/stop', token); useAlertStore.setState({ running: false }); } },
    { id: 'clear',    label: 'Clear Session',        icon: <RotateCcw size={14} />, group: 'Engine',  action: async () => { await apiPost('/engine/clear', token); reset(); } },
    { id: 'sim',      label: 'Launch Attack Simulation', icon: <Crosshair size={14} />, group: 'Engine', action: async () => { await apiPost('/sim/start', token); } },
    { id: 'nav-live', label: 'Go to Live Feed',      icon: <Activity size={14} />, group: 'Navigate', action: () => onNavigate('live') },
    { id: 'nav-tl',   label: 'Go to Threat Timeline', icon: <Layers size={14} />,  group: 'Navigate', action: () => onNavigate('timeline') },
    { id: 'nav-an',   label: 'Go to Analytics',      icon: <BarChart2 size={14} />,group: 'Navigate', action: () => onNavigate('analytics') },
    { id: 'nav-log',  label: 'Go to Alert Log',      icon: <List size={14} />,     group: 'Navigate', action: () => onNavigate('log') },
    { id: 'export',   label: 'Export Alert Log CSV', icon: <Zap size={14} />,      group: 'Data',     action: () => { window.open('/api/alerts/export', '_blank'); } },
  ];

  const filtered = query.trim()
    ? commands.filter(c => c.label.toLowerCase().includes(query.toLowerCase()))
    : commands;

  // Group them
  const groups = [...new Set(filtered.map(c => c.group))];

  useEffect(() => {
    if (open) {
      setQuery('');
      setSelected(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [open]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setSelected(s => Math.min(s + 1, filtered.length - 1)); }
    if (e.key === 'ArrowUp')   { e.preventDefault(); setSelected(s => Math.max(s - 1, 0)); }
    if (e.key === 'Enter')     { filtered[selected]?.action(); onClose(); }
    if (e.key === 'Escape')    { onClose(); }
  }, [filtered, selected, onClose]);

  if (!open) return null;

  let globalIdx = 0;

  return (
    <div className="cmd-overlay" onClick={onClose}>
      <motion.div
        className="cmd-palette animate-palette-in"
        onClick={e => e.stopPropagation()}
        onKeyDown={handleKeyDown}
      >
        {/* Input */}
        <div className="cmd-input-row">
          <Search size={16} color="var(--text-dim)" style={{ flexShrink: 0 }} />
          <input
            ref={inputRef}
            className="cmd-input"
            placeholder="Type a command or navigate…"
            value={query}
            onChange={e => { setQuery(e.target.value); setSelected(0); }}
          />
          <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', flexShrink: 0 }}>ESC</span>
        </div>

        {/* Results */}
        <div style={{ overflowY: 'auto', maxHeight: 360 }}>
          {filtered.length === 0 ? (
            <div style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
              No matching commands
            </div>
          ) : (
            groups.map(group => (
              <div key={group}>
                <div className="cmd-section">{group}</div>
                {filtered.filter(c => c.group === group).map(cmd => {
                  const idx = globalIdx++;
                  return (
                    <div
                      key={cmd.id}
                      className={`cmd-result ${selected === idx ? 'selected' : ''}`}
                      onClick={() => { cmd.action(); onClose(); }}
                      onMouseEnter={() => setSelected(idx)}
                    >
                      <span className="cmd-result-icon">{cmd.icon}</span>
                      <span className="cmd-result-label">{cmd.label}</span>
                      {cmd.sub && <span className="cmd-result-sub">{cmd.sub}</span>}
                    </div>
                  );
                })}
              </div>
            ))
          )}
        </div>

        {/* Footer hint */}
        <div style={{
          borderTop: '1px solid var(--border-panel)',
          padding: '7px 16px',
          display: 'flex', gap: 16,
          fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
        }}>
          <span>↑↓ navigate</span>
          <span>↵ select</span>
          <span>esc close</span>
        </div>
      </motion.div>
    </div>
  );
}

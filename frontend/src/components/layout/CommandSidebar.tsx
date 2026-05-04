import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield, Play, Square, RotateCcw,
  ChevronDown, ChevronRight, LogOut,
} from 'lucide-react';
import { useAlertStore } from '../../store/alertStore';
import { apiPost, apiGet } from '../../hooks/useAuth';

interface Props {
  token: string;
  email: string;
  onLogout: () => void;
  onCommandPalette: () => void;
}

interface Settings {
  conf_threshold: number;
  guard:          number;
  auto_block:     boolean;
  webhook_url:    string;
}

export default function CommandSidebar({ token, email, onLogout, onCommandPalette }: Props) {
  const { running, simActive, snifferOk, snifferError } = useAlertStore();

  const [settings, setSettings]         = useState<Settings>({
    conf_threshold: 0.80, guard: 1, auto_block: false, webhook_url: '',
  });
  const [mitigationOpen, setMitigationOpen] = useState(false);
  const [starting, setStarting]         = useState(false);
  const [startError, setStartError]     = useState('');

  // Load settings from backend on mount
  useEffect(() => {
    apiGet('/settings', token).then(d => {
      if (d.conf_threshold !== undefined) setSettings(d as Settings);
    }).catch(() => {});
  }, [token]);

  const saveSettings = useCallback(async (patch: Partial<Settings>) => {
    const updated = { ...settings, ...patch };
    setSettings(updated);
    await apiPost('/settings', token, updated).catch(() => {});
  }, [settings, token]);

  const handleStart = async () => {
    setStarting(true);
    setStartError('');
    try {
      const res = await apiPost('/engine/start', token);
      if (res && res.success === true) {
        // Backend confirmed engine started — WebSocket metric heartbeats will
        // update snifferOk / snifferError shortly after.
        useAlertStore.setState({ running: true });
      } else {
        // Either {success: false} from the API or {} from a connection error
        const detail = res?.detail ?? '';
        setStartError(
          detail || 'Cannot reach backend — make sure start_backend.bat is running as Administrator.'
        );
      }
    } catch (e) {
      setStartError('Could not reach backend — make sure start_backend.bat is running as Administrator.');
    } finally {
      setStarting(false);
    }
  };

  const handleStop = async () => {
    await apiPost('/engine/stop', token);
    useAlertStore.setState({ running: false });
    setStartError('');
  };

  const handleClear = async () => {
    await apiPost('/engine/clear', token);
    useAlertStore.getState().reset();
    useAlertStore.setState({ running: false });
    setStartError('');
  };

  const confPct = Math.round(settings.conf_threshold * 100);

  const snifferStatus = snifferError
    ? { label: 'SNIFFER ERROR', color: 'var(--sev-critical)', dot: 'dot-red' }
    : running && snifferOk
    ? { label: 'ACTIVE', color: 'var(--accent-green)', dot: 'dot-green' }
    : running
    ? { label: 'STARTING…', color: 'var(--accent-blue)', dot: 'dot-blue' }
    : { label: 'STANDBY', color: 'var(--text-dim)', dot: 'dot-grey' };

  return (
    <aside style={{
      width: 240,
      minWidth: 240,
      height: '100vh',
      background: 'var(--bg-surface)',
      borderRight: '1px solid var(--border-panel)',
      display: 'flex',
      flexDirection: 'column',
      overflow: 'hidden',
    }}>

      {/* ── Logo ──────────────────────────────────────────────────────────────── */}
      <div style={{ padding: '18px 16px 12px', borderBottom: '1px solid var(--border-dim)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
          <div style={{
            width: 32, height: 32, borderRadius: 6,
            background: 'rgba(0,212,255,0.07)',
            border: '1px solid rgba(0,212,255,0.15)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
          }}>
            <Shield size={16} color="var(--accent-blue)" />
          </div>
          <div style={{
            fontFamily: 'var(--font-display)', fontSize: 20, fontWeight: 700,
            color: 'var(--text-heading)', letterSpacing: '0.1em',
          }}>
            AIPS
          </div>
        </div>

        {/* Status chip */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 7,
          background: 'var(--bg-panel)',
          border: `1px solid ${running ? 'rgba(0,255,136,0.15)' : 'var(--border-dim)'}`,
          borderRadius: 20, padding: '5px 12px',
          transition: 'border-color 0.3s',
        }}>
          <span className={`dot ${snifferStatus.dot} ${running ? 'animate-breathe' : ''}`} />
          <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase', color: snifferStatus.color }}>
            {snifferStatus.label}
          </span>
        </div>

        {/* Sim mode indicator */}
        {simActive && (
          <div style={{ marginTop: 6, display: 'flex', alignItems: 'center', gap: 6, fontSize: 10, color: 'var(--sev-sim)', fontWeight: 600 }}>
            <span className="dot dot-purple animate-breathe" />
            SIMULATION ACTIVE
          </div>
        )}
      </div>

      {/* ── Scrollable body ────────────────────────────────────────────────────── */}
      <div style={{ flex: 1, overflowY: 'auto', overflowX: 'hidden' }}>

        {/* ─ Engine Controls ─ */}
        <div style={{ padding: '14px', borderBottom: '1px solid var(--border-dim)' }}>
          <div className="section-label">Engine</div>

          {/* Start / Stop */}
          <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}>
            <button
              className={`btn btn-start flex-1 ${running ? 'active' : ''}`}
              disabled={running || starting}
              onClick={handleStart}
              style={{ fontSize: 12 }}
            >
              <Play size={13} />
              {starting ? 'Starting…' : 'Start'}
            </button>
            <button
              className="btn btn-stop flex-1"
              disabled={!running}
              onClick={handleStop}
              style={{ fontSize: 12 }}
            >
              <Square size={13} /> Stop
            </button>
          </div>

          <button className="btn btn-ghost" onClick={handleClear}
                  style={{ fontSize: 12, width: '100%' }}>
            <RotateCcw size={12} /> Clear Session
          </button>

          {startError && (
            <div style={{ marginTop: 8, fontSize: 10, padding: '5px 8px', borderRadius: 4, background: 'rgba(255,45,85,0.06)', border: '1px solid rgba(255,45,85,0.2)', color: 'var(--sev-critical)', fontFamily: 'var(--font-mono)' }}>
              {startError}
            </div>
          )}
          {snifferError && (
            <div style={{ marginTop: 8, fontSize: 10, padding: '5px 8px', borderRadius: 4, background: 'rgba(255,45,85,0.06)', border: '1px solid rgba(255,45,85,0.2)', color: 'var(--sev-critical)', fontFamily: 'var(--font-mono)' }}>
              Sniffer: {snifferError}
            </div>
          )}
        </div>

        {/* ─ Detection Tuning ─ */}
        <div style={{ padding: '14px', borderBottom: '1px solid var(--border-dim)' }}>
          <div className="section-label">Detection</div>

          {/* Confidence Threshold */}
          <div style={{ marginBottom: 14 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
              <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-dim)' }}>
                Confidence Threshold
              </span>
              <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--accent-blue)', fontWeight: 600 }}>
                {confPct}%
              </span>
            </div>
            <input type="range" min={40} max={98} value={confPct}
                   className="nw-slider"
                   onChange={e => saveSettings({ conf_threshold: Number(e.target.value) / 100 })} />
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9, color: 'var(--text-muted)', marginTop: 3 }}>
              <span>40% Sensitive</span><span>98% Strict</span>
            </div>
          </div>

          {/* Alert Guard */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
              <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-dim)' }}>
                Alert Guard
              </span>
              <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--accent-blue)', fontWeight: 600 }}>
                {settings.guard}×
              </span>
            </div>
            <input type="range" min={1} max={5} value={settings.guard}
                   className="nw-slider"
                   onChange={e => saveSettings({ guard: Number(e.target.value) })} />
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 3 }}>
              Consecutive hits required to fire
            </div>
          </div>
        </div>

        {/* ─ Mitigation (collapsible) ─ */}
        <div style={{ borderBottom: '1px solid var(--border-dim)' }}>
          <button onClick={() => setMitigationOpen(o => !o)} style={{
            width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '12px 14px 10px', background: 'none', border: 'none', cursor: 'pointer',
          }}>
            <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.15em', textTransform: 'uppercase', color: 'var(--text-dim)' }}>
              Mitigation
            </span>
            {mitigationOpen
              ? <ChevronDown size={12} color="var(--text-dim)" />
              : <ChevronRight size={12} color="var(--text-dim)" />}
          </button>
          {mitigationOpen && (
            <div style={{ padding: '0 14px 14px' }}>
              <div style={{ marginBottom: 10 }}>
                <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-dim)', marginBottom: 5 }}>
                  Webhook (Slack / Discord)
                </div>
                <input
                  type="password"
                  className="input"
                  placeholder="https://hooks.slack.com/…"
                  value={settings.webhook_url}
                  onChange={e => saveSettings({ webhook_url: e.target.value })}
                />
              </div>
              <label className="nw-checkbox">
                <input type="checkbox" checked={settings.auto_block}
                       onChange={e => saveSettings({ auto_block: e.target.checked })} />
                Auto-Block Critical IPs
              </label>
              {settings.auto_block && (
                <div style={{ marginTop: 6, fontSize: 10, padding: '5px 8px', borderRadius: 4, background: 'rgba(0,255,136,0.06)', border: '1px solid rgba(0,255,136,0.15)', color: 'var(--accent-green)' }}>
                  ✓ Active
                </div>
              )}
            </div>
          )}
        </div>

      </div>

      {/* ── Footer ─────────────────────────────────────────────────────────────── */}
      <div style={{ borderTop: '1px solid var(--border-dim)', padding: '10px 14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-bright)', fontWeight: 500, marginBottom: 2 }}>{email}</div>
            <button onClick={onCommandPalette}
                    style={{ fontSize: 10, color: 'var(--text-dim)', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
              ⌘K Command Palette
            </button>
          </div>
          <button onClick={onLogout} className="btn btn-ghost" style={{ padding: '5px 8px' }}>
            <LogOut size={13} />
          </button>
        </div>
      </div>
    </aside>
  );
}

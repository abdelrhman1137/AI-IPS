import React, { useState, useMemo } from 'react';
import { useAlertStore } from '../../store/alertStore';
import { SEV_COLOR } from '../../types';
import type { Severity, AlertRecord } from '../../types';

const ALL_SEV: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'CLEAN'];

function SevToggle({ s, active, onClick }: { s: Severity; active: boolean; onClick: () => void }) {
  const cls: Record<Severity, string> = { CRITICAL: 'badge-critical', HIGH: 'badge-high', MEDIUM: 'badge-medium', CLEAN: 'badge-clean' };
  return (
    <button onClick={onClick}
            className={`badge ${cls[s]}`}
            style={{ cursor: 'pointer', opacity: active ? 1 : 0.35, transition: 'opacity 0.15s', background: 'none' }}>
      {s}
    </button>
  );
}

function Row({ a, token }: { a: AlertRecord; token: string }) {
  const col = SEV_COLOR[a.severity] ?? '#8FA8C8';
  const sevCls: Record<string, string> = { CRITICAL: 'badge-critical', HIGH: 'badge-high', MEDIUM: 'badge-medium', CLEAN: 'badge-clean' };

  return (
    <tr>
      <td style={{ color: 'var(--text-dim)' }}>{a.timestamp}</td>
      <td><span className={`badge ${sevCls[a.severity] ?? ''}`}>{a.severity}</span></td>
      <td style={{ color: col, fontWeight: 600 }}>{a.label}</td>
      <td>{(a.confidence * 100).toFixed(1)}%</td>
      <td>{a.port}</td>
      <td>{a.duration_us.toLocaleString()} µs</td>
      <td><span className={`badge ${a.src === 'SIM' ? 'badge-sim' : 'badge-clean'}`}>{a.src}</span></td>
      <td style={{ color: 'var(--text-dim)' }}>{a.src_ip || '—'}</td>
      <td>{a.blocked ? <span style={{ color: 'var(--sev-critical)', fontWeight: 600 }}>BLOCKED</span> : '—'}</td>
      <td>
        {a.pcap_path ? (
          <a href={`/api/pcap/${encodeURIComponent(a.pcap_path.split(/[/\\]/).pop()!)}`}
             download style={{ color: 'var(--accent-blue)', fontSize: 10, textDecoration: 'none', fontFamily: 'var(--font-mono)' }}>
            ↓ PCAP
          </a>
        ) : '—'}
      </td>
    </tr>
  );
}

export default function AlertLogPanel({ token }: { token: string }) {
  const { alerts, sevFilter, setSevFilter } = useAlertStore();
  const [search, setSearch] = useState('');

  const filtered = useMemo(() =>
    alerts.filter(a =>
      sevFilter.includes(a.severity as Severity) &&
      (search === '' || a.label.toLowerCase().includes(search.toLowerCase()) || a.src_ip.includes(search))
    ),
    [alerts, sevFilter, search],
  );

  const toggleSev = (s: Severity) => {
    setSevFilter(
      sevFilter.includes(s) ? sevFilter.filter(x => x !== s) : [...sevFilter, s]
    );
  };

  const exportCsv = () => {
    const anchor = document.createElement('a');
    anchor.href = `/api/alerts/export`;
    anchor.download = `ids_alerts_${Date.now()}.csv`;
    anchor.click();
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      {/* Toolbar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap',
        padding: '10px 14px', borderBottom: '1px solid var(--border-dim)', flexShrink: 0,
      }}>
        {/* Severity filter */}
        <div style={{ display: 'flex', gap: 5 }}>
          {ALL_SEV.map(s => (
            <SevToggle key={s} s={s} active={sevFilter.includes(s)} onClick={() => toggleSev(s)} />
          ))}
        </div>

        {/* Search */}
        <input className="input" placeholder="Search label or IP…"
               value={search} onChange={e => setSearch(e.target.value)}
               style={{ maxWidth: 200, padding: '5px 10px', fontSize: 12 }} />

        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, alignItems: 'center' }}>
          <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
            {filtered.length} records
          </span>
          <button className="btn btn-ghost" onClick={exportCsv} style={{ fontSize: 11, padding: '5px 12px' }}>
            ↓ Export CSV
          </button>
        </div>
      </div>

      {/* Table */}
      <div style={{ flex: 1, overflowY: 'auto', overflowX: 'auto' }}>
        {filtered.length === 0 ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-muted)', fontSize: 13 }}>
            No alerts match current filters.
          </div>
        ) : (
          <table className="nw-table" style={{ minWidth: 900 }}>
            <thead>
              <tr>
                {['Time','Severity','Label','Conf','Port','Duration','Src','IP','Blocked','PCAP'].map(h => (
                  <th key={h}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((a, i) => (
                <Row key={i} a={a} token={token} />
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

import React from 'react';
import { useAlertStore } from '../../store/alertStore';
import { SEV_COLOR, ATK_COLOR } from '../../types';
import type { FlowEvent } from '../../types';

const SEV_CSS: Record<string, string> = {
  CRITICAL: 'feed-critical animate-threat-pulse',
  HIGH:     'feed-high',
  MEDIUM:   'feed-medium',
  CLEAN:    'feed-clean',
};

function SeverityBadge({ sev }: { sev: string }) {
  const cls: Record<string, string> = {
    CRITICAL: 'badge badge-critical', HIGH: 'badge badge-high',
    MEDIUM: 'badge badge-medium',     CLEAN: 'badge badge-clean',
  };
  return <span className={cls[sev] ?? 'badge'}>{sev}</span>;
}

function FeedRow({ ev }: { ev: FlowEvent }) {
  const col  = SEV_COLOR[ev.severity] ?? '#8FA8C8';
  const css  = SEV_CSS[ev.severity]   ?? 'feed-clean';

  // Log the raw event so DevTools confirms which keys arrive from the backend
  // eslint-disable-next-line no-console
  if (import.meta.env.DEV) console.log('[FeedRow]', ev);

  // Build compact connection string.
  // Guard: src_port and dst_port can be 0 for self-test flows — use them if present.
  const srcPort = ev.src_port != null ? ev.src_port : ev.port;
  const dstPort = ev.dst_port != null ? ev.dst_port : ev.port;
  const srcStr  = ev.src_ip ? `${ev.src_ip}:${srcPort}` : '—';
  const dstStr  = ev.dst_ip ? `${ev.dst_ip}:${dstPort}` : '—';

  return (
    <div
      className={`feed-row ${css}`}
      style={{ overflow: 'hidden', animation: 'fadeIn 0.2s ease-out' }}
    >
      <SeverityBadge sev={ev.severity} />

      <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', minWidth: 64 }}>
        {ev.timestamp}
      </span>

      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600, color: col, minWidth: 110 }}>
        {ev.label}
      </span>

      {/* Confidence mini-bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 5, minWidth: 80 }}>
        <div style={{ height: 3, borderRadius: 2, background: 'var(--border-panel)', flex: 1, maxWidth: 60 }}>
          <div style={{ height: '100%', width: `${Math.round(ev.confidence * 100)}%`, borderRadius: 2, background: col, transition: 'width 0.3s' }} />
        </div>
        <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', minWidth: 36 }}>
          {(ev.confidence * 100).toFixed(1)}%
        </span>
      </div>

      {/* Source → Destination connection */}
      <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        <span style={{ color: ev.src_ip ? 'var(--text-bright)' : 'var(--text-muted)' }}>{srcStr}</span>
        <span style={{ color: 'var(--text-muted)', margin: '0 4px' }}>→</span>
        <span style={{ color: ev.dst_ip ? 'var(--accent-blue)' : 'var(--text-muted)' }}>{dstStr}</span>
      </span>

      {ev.is_sim   && <span className="badge badge-sim"      style={{ fontSize: 9 }}>SIM</span>}
      {ev.blocked  && <span className="badge badge-critical" style={{ fontSize: 9 }}>BLOCKED</span>}
    </div>
  );
}

export default function IncidentFeed() {
  const { feed, running } = useAlertStore();

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '10px 14px', borderBottom: '1px solid var(--border-dim)', flexShrink: 0,
      }}>
        <div className="section-label" style={{ margin: 0, border: 'none', padding: 0 }}>
          INCIDENT STREAM
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
          {running && <span className="dot dot-green animate-breathe" />}
          {feed.length} events
        </div>
      </div>

      {/* Column headers */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10,
        padding: '5px 12px', borderBottom: '1px solid var(--border-dim)', flexShrink: 0,
      }}>
        {[
          { label: 'SEV',        width: 60 },
          { label: 'TIME',       width: 64 },
          { label: 'CLASS',      width: 110 },
          { label: 'CONFIDENCE', width: 80 },
          { label: 'SRC → DST (IP:PORT)', width: undefined },
        ].map(h => (
          <div key={h.label} style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--text-muted)', minWidth: h.width, flex: h.width ? undefined : 1 }}>
            {h.label}
          </div>
        ))}
      </div>


      {/* Feed */}
      <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 1, padding: '4px 0' }}>
        {feed.length === 0 ? (
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 12, color: 'var(--text-muted)', fontSize: 13 }}>
            <div style={{ fontSize: 32, opacity: 0.3 }}>◎</div>
            <div>
              {running
                ? 'Monitoring active — awaiting network flows'
                : 'Click Start to begin monitoring, or Run Self-Test'}
            </div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
            {feed.map((ev, i) => <FeedRow key={`${ev.unix}-${i}`} ev={ev} />)}
          </div>
        )}
      </div>
    </div>
  );
}

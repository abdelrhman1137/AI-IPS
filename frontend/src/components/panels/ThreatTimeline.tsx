import React, { useMemo, useState } from 'react';
import { useAlertStore } from '../../store/alertStore';
import { ATK_COLOR, SEV_COLOR } from '../../types';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  AreaChart, Area, CartesianGrid,
} from 'recharts';

const RANGES: Record<string, number | null> = {
  '1 min': 60, '5 min': 300, '15 min': 900, '30 min': 1800, 'All': null,
};

const CHART_STYLE = {
  background: 'transparent',
  fontSize: 10,
  fontFamily: 'var(--font-mono)',
  color: 'var(--text-dim)',
};

const TooltipStyle = {
  background: 'var(--bg-raised)',
  border: '1px solid var(--border-panel)',
  borderRadius: 6,
  padding: '8px 12px',
  fontSize: 11,
  fontFamily: 'var(--font-mono)',
  color: 'var(--text-bright)',
};

export default function ThreatTimeline() {
  const { tsLog, alertCount } = useAlertStore();
  const [range, setRange] = useState('5 min');

  const now    = Date.now() / 1000;
  const secs   = RANGES[range];
  const filtered = useMemo(() =>
    secs ? tsLog.filter(e => now - e.unix <= secs) : tsLog,
    [tsLog, range, now],
  );

  // Build 5-second bucket bar chart data
  const barData = useMemo(() => {
    if (!filtered.length) return [];
    const min_ts = Math.min(...filtered.map(e => e.unix));
    const bkts: Record<number, Record<string, number>> = {};
    for (const { unix, label } of filtered) {
      const bk = Math.floor((unix - min_ts) / 5) * 5;
      if (!bkts[bk]) bkts[bk] = {};
      bkts[bk][label] = (bkts[bk][label] ?? 0) + 1;
    }
    return Object.entries(bkts)
      .sort(([a], [b]) => Number(a) - Number(b))
      .map(([bk, counts]) => ({ time: `+${bk}s`, ...counts }));
  }, [filtered]);

  // Build cumulative line data
  const cumData = useMemo(() => {
    if (!filtered.length) return [];
    const sorted = [...filtered].sort((a, b) => a.unix - b.unix);
    const t0     = sorted[0].unix;
    return sorted.map((e, i) => ({
      t:   `+${Math.round(e.unix - t0)}s`,
      cum: i + 1,
      col: ATK_COLOR[e.label] ?? 'var(--accent-blue)',
    }));
  }, [filtered]);

  const attackClasses = [...new Set(tsLog.map(e => e.label))];

  return (
    <div style={{ height: '100%', overflow: 'hidden', display: 'flex', flexDirection: 'column', gap: 0 }}>
      {/* Time range selector */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '10px 14px', borderBottom: '1px solid var(--border-dim)', flexShrink: 0 }}>
        <span style={{ fontSize: 10, color: 'var(--text-dim)', marginRight: 8, letterSpacing: '0.1em', textTransform: 'uppercase', fontWeight: 600 }}>Window</span>
        {Object.keys(RANGES).map(r => (
          <button key={r} onClick={() => setRange(r)}
                  style={{
                    background: r === range ? 'rgba(0,212,255,0.08)' : 'transparent',
                    border: `1px solid ${r === range ? 'var(--accent-blue)' : 'var(--border-panel)'}`,
                    borderRadius: 4, padding: '3px 10px',
                    fontSize: 11, fontFamily: 'var(--font-body)', fontWeight: 500,
                    color: r === range ? 'var(--accent-blue)' : 'var(--text-dim)',
                    cursor: 'pointer', transition: 'all 0.15s',
                  }}>
            {r}
          </button>
        ))}
        <span style={{ marginLeft: 'auto', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--accent-blue)' }}>
          {filtered.length} events
        </span>
      </div>

      <div style={{ flex: 1, overflow: 'auto', padding: 14, display: 'flex', flexDirection: 'column', gap: 16 }}>
        {/* Alert Rate Bar Chart */}
        <ChartBlock label="Alert Rate — 5-Second Buckets">
          {barData.length > 0 ? (
            <ResponsiveContainer width="100%" height={140}>
              <BarChart data={barData} style={CHART_STYLE} barCategoryGap="20%">
                <CartesianGrid stroke="var(--border-dim)" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="time" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 10 }} tickLine={false} axisLine={false} allowDecimals={false} width={24} />
                <Tooltip contentStyle={TooltipStyle} cursor={{ fill: 'rgba(0,212,255,0.04)' }} />
                {attackClasses.map(cls => (
                  <Bar key={cls} dataKey={cls} stackId="a"
                       fill={ATK_COLOR[cls] ?? '#4A5980'} radius={[2, 2, 0, 0]} />
                ))}
              </BarChart>
            </ResponsiveContainer>
          ) : <EmptyChart />}
        </ChartBlock>

        {/* Cumulative Area Chart */}
        <ChartBlock label="Cumulative Threat Count">
          {cumData.length > 0 ? (
            <ResponsiveContainer width="100%" height={140}>
              <AreaChart data={cumData} style={CHART_STYLE}>
                <defs>
                  <linearGradient id="cumGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="var(--accent-blue)" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="var(--accent-blue)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="var(--border-dim)" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="t" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 10 }} tickLine={false} axisLine={false} allowDecimals={false} width={24} />
                <Tooltip contentStyle={TooltipStyle} />
                <Area type="monotone" dataKey="cum" stroke="var(--accent-blue)" strokeWidth={2}
                      fill="url(#cumGrad)" dot={false} activeDot={{ r: 4, fill: 'var(--accent-blue)' }} name="Alerts" />
              </AreaChart>
            </ResponsiveContainer>
          ) : <EmptyChart />}
        </ChartBlock>

        {/* Recent detections mini table */}
        <ChartBlock label="Recent Detections">
          <RecentTable />
        </ChartBlock>
      </div>
    </div>
  );
}

function ChartBlock({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="section-label">{label}</div>
      {children}
    </div>
  );
}

function EmptyChart() {
  return (
    <div style={{ height: 120, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
      No data in selected time range
    </div>
  );
}

function RecentTable() {
  const { alerts } = useAlertStore();
  const rows = alerts.slice(0, 15);
  if (!rows.length) return <div style={{ color: 'var(--text-muted)', fontSize: 12, textAlign: 'center', padding: 12 }}>No detections yet</div>;
  return (
    <div style={{ overflowX: 'auto' }}>
      <table className="nw-table">
        <thead>
          <tr>
            {['Time','Severity','Label','Conf','Port','Src','IP','Blocked'].map(h => (
              <th key={h}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((a, i) => (
            <tr key={i}>
              <td>{a.timestamp}</td>
              <td><SevBadge s={a.severity} /></td>
              <td style={{ color: SEV_COLOR[a.severity] }}>{a.label}</td>
              <td>{(a.confidence * 100).toFixed(1)}%</td>
              <td>{a.port}</td>
              <td><span className={`badge ${a.src === 'SIM' ? 'badge-sim' : 'badge-clean'}`}>{a.src}</span></td>
              <td style={{ color: 'var(--text-dim)' }}>{a.src_ip || '—'}</td>
              <td>{a.blocked ? <span style={{ color: 'var(--sev-critical)' }}>✓</span> : '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SevBadge({ s }: { s: string }) {
  const cls: Record<string, string> = { CRITICAL: 'badge-critical', HIGH: 'badge-high', MEDIUM: 'badge-medium', CLEAN: 'badge-clean' };
  return <span className={`badge ${cls[s] ?? ''}`}>{s}</span>;
}

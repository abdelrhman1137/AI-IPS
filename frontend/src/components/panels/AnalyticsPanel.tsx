import React, { useMemo } from 'react';
import { useAlertStore } from '../../store/alertStore';
import { ATK_COLOR } from '../../types';
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  AreaChart, Area,
} from 'recharts';

const TooltipStyle = {
  background: 'var(--bg-raised)',
  border: '1px solid var(--border-panel)',
  borderRadius: 6,
  padding: '8px 12px',
  fontSize: 11,
  fontFamily: 'var(--font-mono)',
  color: 'var(--text-bright)',
};

function StatCard({ label, value, color, sub }: { label: string; value: string; color: string; sub?: string }) {
  return (
    <div className="stat-card panel-hud panel-hud-br">
      <div className="stat-card-label">{label}</div>
      <div className="stat-card-val" style={{ color }}>{value}</div>
      {sub && <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>{sub}</div>}
    </div>
  );
}

function EmptyState({ msg }: { msg: string }) {
  return (
    <div style={{ height: 160, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
      {msg}
    </div>
  );
}

export default function AnalyticsPanel() {
  const { totalFlows, alertCount, avgConf, confHistory, throughput, threatLog, tsLog } = useAlertStore();
  const threatRate = totalFlows > 0 ? (alertCount / totalFlows * 100).toFixed(1) : '—';

  // Donut: traffic class distribution
  const donutData = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const l of threatLog) counts[l] = (counts[l] ?? 0) + 1;
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [threatLog]);

  // Histogram: confidence distribution (20 bins 0-1)
  const histData = useMemo(() => {
    const bins: { x: string; count: number }[] = Array.from({ length: 20 }, (_, i) => ({
      x: (i / 20).toFixed(2),
      count: 0,
    }));
    for (const entry of confHistory) {
      const c   = entry[1] as number;
      const idx = Math.min(19, Math.floor(c * 20));
      bins[idx].count++;
    }
    return bins;
  }, [confHistory]);

  // Throughput sparkline
  const tpData = useMemo(() => {
    return throughput.slice(-100).map((entry, i) => {
      const bps = entry[1] as number;
      return { i, bps };
    });
  }, [throughput]);

  // Attack class breakdown (horizontal bar)
  const classData = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const entry of tsLog) {
      const label = entry.label;
      counts[label] = (counts[label] ?? 0) + 1;
    }
    return Object.entries(counts)
      .sort((a, b) => a[1] - b[1])
      .map(([name, count]) => ({ name, count }));
  }, [tsLog]);

  return (
    <div style={{ height: '100%', overflow: 'auto', padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Stat cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10 }}>
        <StatCard label="Flows Analyzed"  value={totalFlows.toLocaleString()} color="var(--accent-blue)" />
        <StatCard label="Threats Detected" value={alertCount.toString()}      color="var(--sev-critical)" sub={`${threatRate}% rate`} />
        <StatCard label="Avg. Confidence" value={`${(avgConf * 100).toFixed(1)}%`} color="var(--accent-green)" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
        {/* Traffic class donut */}
        <ChartBox label="Traffic Class Distribution">
          {donutData.length > 1 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={donutData} cx="50%" cy="50%" innerRadius={55} outerRadius={80}
                     dataKey="value" paddingAngle={2}>
                  {donutData.map((entry, i) => (
                    <Cell key={i} fill={ATK_COLOR[entry.name] ?? '#4A5980'} stroke="transparent" />
                  ))}
                </Pie>
                <Tooltip contentStyle={TooltipStyle} />
              </PieChart>
            </ResponsiveContainer>
          ) : <EmptyState msg="Awaiting traffic data" />}
        </ChartBox>

        {/* Confidence histogram */}
        <ChartBox label="Model Confidence Distribution">
          {confHistory.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={histData} barCategoryGap="4%">
                <CartesianGrid stroke="var(--border-dim)" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="x" tick={{ fill: 'var(--text-muted)', fontSize: 9 }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 9 }} tickLine={false} axisLine={false} width={24} />
                <Tooltip contentStyle={TooltipStyle} />
                <Bar dataKey="count" fill="var(--accent-blue)" radius={[2, 2, 0, 0]} name="Flows" />
              </BarChart>
            </ResponsiveContainer>
          ) : <EmptyState msg="Awaiting predictions" />}
        </ChartBox>

        {/* Throughput sparkline */}
        <ChartBox label="Throughput Over Time (Bytes/s)">
          {tpData.length > 2 ? (
            <ResponsiveContainer width="100%" height={140}>
              <AreaChart data={tpData}>
                <defs>
                  <linearGradient id="tpGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="var(--accent-cyan)" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="var(--accent-cyan)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="var(--border-dim)" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="i" hide />
                <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 9 }} tickLine={false} axisLine={false} width={48} />
                <Tooltip contentStyle={TooltipStyle} />
                <Area type="monotone" dataKey="bps" stroke="var(--accent-cyan)" strokeWidth={2}
                      fill="url(#tpGrad)" dot={false} name="Bytes/s" />
              </AreaChart>
            </ResponsiveContainer>
          ) : <EmptyState msg="Awaiting traffic" />}
        </ChartBox>

        {/* Attack class horizontal bar */}
        <ChartBox label="Alerts by Attack Class">
          {classData.length > 0 ? (
            <ResponsiveContainer width="100%" height={Math.max(120, classData.length * 32 + 20)}>
              <BarChart data={classData} layout="vertical" barCategoryGap="25%">
                <CartesianGrid stroke="var(--border-dim)" strokeDasharray="3 3" horizontal={false} />
                <XAxis type="number" tick={{ fill: 'var(--text-muted)', fontSize: 9 }} tickLine={false} axisLine={false} />
                <YAxis dataKey="name" type="category" width={110}
                       tick={{ fill: 'var(--text-body)', fontSize: 10, fontFamily: 'var(--font-mono)' }}
                       tickLine={false} axisLine={false} />
                <Tooltip contentStyle={TooltipStyle} />
                <Bar dataKey="count" radius={[0, 3, 3, 0]} name="Alerts"
                     label={{ position: 'right', fill: 'var(--text-dim)', fontSize: 10, fontFamily: 'var(--font-mono)' }}>
                  {classData.map((entry, i) => (
                    <Cell key={i} fill={ATK_COLOR[entry.name] ?? 'var(--accent-blue)'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : <EmptyState msg="Awaiting alerts" />}
        </ChartBox>
      </div>
    </div>
  );
}

function ChartBox({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="panel" style={{ padding: '14px' }}>
      <div className="section-label">{label}</div>
      {children}
    </div>
  );
}

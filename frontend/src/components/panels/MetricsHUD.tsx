import React, { useEffect, useRef } from 'react';
import { useAlertStore } from '../../store/alertStore';
import { SEV_COLOR, ATK_COLOR } from '../../types';
import { motion, AnimatePresence } from 'framer-motion';
import type { FlowEvent } from '../../types';

function fmt_bps(bps: number): string {
  if (bps >= 1_048_576) return `${(bps / 1_048_576).toFixed(2)} MB/s`;
  if (bps >= 1024)      return `${(bps / 1024).toFixed(1)} KB/s`;
  return `${Math.round(bps)} B/s`;
}

function fmt_uptime(s: number): string {
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = Math.floor(s % 60);
  return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(sec).padStart(2,'0')}`;
}

export default function MetricsHUD() {
  const { rawPackets, totalFlows, alertCount, threatRate, throughputBps, uptimeSecs, running } =
    useAlertStore();

  const prevAlerts = useRef(alertCount);
  const flashRef   = useRef(false);

  useEffect(() => {
    if (alertCount > prevAlerts.current) flashRef.current = true;
    prevAlerts.current = alertCount;
  }, [alertCount]);

  const metrics = [
    { label: 'RAW PACKETS',    value: rawPackets.toLocaleString(),   color: 'var(--accent-blue)',   sub: 'Captured',   icon: '▲' },
    { label: 'FLOWS ANALYZED', value: totalFlows.toLocaleString(),   color: 'var(--text-heading)',  sub: 'Processed',  icon: '⬡' },
    { label: 'THREATS',        value: alertCount.toString(),         color: alertCount > 0 ? 'var(--sev-critical)' : 'var(--accent-green)', sub: 'Detected', icon: '⚠', pulse: alertCount > 0 },
    { label: 'THREAT RATE',    value: totalFlows > 0 ? `${threatRate.toFixed(1)}%` : '—', color: 'var(--accent-amber)', sub: 'Of flows', icon: '◎' },
    { label: 'THROUGHPUT',     value: fmt_bps(throughputBps),        color: 'var(--accent-cyan)',   sub: 'Current',    icon: '≈' },
    { label: 'UPTIME',         value: fmt_uptime(uptimeSecs),        color: running ? 'var(--accent-green)' : 'var(--text-dim)', sub: running ? 'Active' : 'Idle', icon: '◷' },
  ];

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(6, 1fr)',
      gap: 1,
      borderBottom: '1px solid var(--border-panel)',
      background: 'var(--border-panel)',
    }}>
      {metrics.map((m, i) => (
        <MetricCard key={i} {...m} />
      ))}
    </div>
  );
}

function MetricCard({ label, value, color, sub, icon, pulse }: {
  label: string; value: string; color: string; sub: string; icon: string; pulse?: boolean;
}) {
  const prevVal = useRef(value);
  const isNew   = prevVal.current !== value;
  prevVal.current = value;

  return (
    <div style={{
      background: 'var(--bg-surface)',
      padding: '12px 14px',
      position: 'relative',
      overflow: 'hidden',
      transition: 'background 0.2s',
    }}
    className={pulse ? 'animate-threat-pulse' : ''}
    >
      {/* Subtle side accent */}
      <div style={{
        position: 'absolute', left: 0, top: 0, bottom: 0, width: 2,
        background: pulse ? 'var(--sev-critical)' : 'transparent',
        transition: 'background 0.3s',
      }} />

      <div style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 5 }}>
        {label}
      </div>
      <motion.div
        key={value}
        initial={{ opacity: 0, y: 3 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.2 }}
        style={{
          fontFamily: 'var(--font-display)',
          fontSize: 22,
          fontWeight: 700,
          color,
          lineHeight: 1,
          marginBottom: 3,
          ...(pulse ? { textShadow: '0 0 20px rgba(255,45,85,0.5)' } : {}),
        }}
      >
        {value}
      </motion.div>
      <div style={{ fontSize: 9, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 3 }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9 }}>{icon}</span>
        {sub}
      </div>
    </div>
  );
}

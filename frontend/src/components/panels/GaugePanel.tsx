import React, { useEffect, useRef } from 'react';
import { useAlertStore } from '../../store/alertStore';
import { SEV_COLOR, ATK_COLOR } from '../../types';

/** D3-style SVG radial gauge for model confidence */
export default function GaugePanel() {
  const { lastLabel, lastConf, lastProbs, running } = useAlertStore();

  const sev = lastLabel === 'Normal Traffic' ? 'CLEAN'
    : lastConf >= 0.95 && ['DoS','DDoS','Brute Force','Botnet'].includes(lastLabel) ? 'CRITICAL'
    : lastConf >= 0.85 ? 'HIGH' : 'MEDIUM';

  const color = SEV_COLOR[sev] ?? 'var(--text-dim)';
  const pct   = lastConf * 100;

  // SVG arc math
  const R  = 70;
  const CX = 90, CY = 90;
  const startAngle = -220;
  const endAngle   = 40;
  const span       = endAngle - startAngle;
  const valAngle   = startAngle + (span * lastConf);

  const toXY = (angleDeg: number, r: number) => {
    const a = (angleDeg - 90) * (Math.PI / 180);
    return { x: CX + r * Math.cos(a), y: CY + r * Math.sin(a) };
  };

  const arcPath = (from: number, to: number, r: number) => {
    const s  = toXY(from, r);
    const e  = toXY(to, r);
    const la = Math.abs(to - from) > 180 ? 1 : 0;
    return `M ${s.x} ${s.y} A ${r} ${r} 0 ${la} 1 ${e.x} ${e.y}`;
  };

  const top5 = Object.entries(lastProbs)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      {/* Header */}
      <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--border-dim)', flexShrink: 0 }}>
        <div className="section-label" style={{ margin: 0, border: 'none', padding: 0 }}>
          THREAT GAUGE
        </div>
      </div>

      {/* Gauge SVG */}
      <div style={{ padding: '8px 12px', display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }}>
        <svg width={180} height={140} viewBox="0 0 180 140">
          {/* Background track */}
          <path d={arcPath(startAngle, endAngle, R)}
                fill="none" stroke="var(--border-panel)" strokeWidth={8} strokeLinecap="round" />

          {/* Severity zones (subtle) */}
          <path d={arcPath(startAngle, startAngle + span * 0.65, R)}
                fill="none" stroke="rgba(0,255,136,0.12)" strokeWidth={8} strokeLinecap="round" />
          <path d={arcPath(startAngle + span * 0.65, startAngle + span * 0.85, R)}
                fill="none" stroke="rgba(255,184,0,0.12)" strokeWidth={8} strokeLinecap="round" />
          <path d={arcPath(startAngle + span * 0.85, endAngle, R)}
                fill="none" stroke="rgba(255,45,85,0.12)" strokeWidth={8} strokeLinecap="round" />

          {/* Value arc */}
          {lastConf > 0 && (
            <path d={arcPath(startAngle, valAngle, R)}
                  fill="none" stroke={color} strokeWidth={8} strokeLinecap="round"
                  style={{ filter: `drop-shadow(0 0 6px ${color}88)`, transition: 'all 0.5s ease' }} />
          )}

          {/* Needle dot */}
          {lastConf > 0 && (
            <circle cx={toXY(valAngle, R).x} cy={toXY(valAngle, R).y} r={5}
                    fill={color} style={{ filter: `drop-shadow(0 0 8px ${color})`, transition: 'all 0.5s ease' }} />
          )}

          {/* Center: confidence % */}
          <text x={CX} y={CY - 2} textAnchor="middle" dominantBaseline="middle"
                fontFamily="var(--font-display)" fontSize={28} fontWeight={700} fill={color}
                style={{ transition: 'fill 0.4s' }}>
            {lastConf > 0 ? `${Math.round(pct)}%` : '—'}
          </text>
          <text x={CX} y={CY + 18} textAnchor="middle" dominantBaseline="middle"
                fontFamily="var(--font-body)" fontSize={9} fill="var(--text-dim)"
                letterSpacing="0.1em" style={{ textTransform: 'uppercase' }}>
            Confidence
          </text>

          {/* Min/Max labels */}
          <text x={toXY(startAngle, R + 14).x} y={toXY(startAngle, R + 14).y}
                textAnchor="middle" fontSize={8} fill="var(--text-muted)" fontFamily="var(--font-mono)">0%</text>
          <text x={toXY(endAngle, R + 14).x} y={toXY(endAngle, R + 14).y}
                textAnchor="middle" fontSize={8} fill="var(--text-muted)" fontFamily="var(--font-mono)">100%</text>
        </svg>

        {/* Verdict */}
        <div style={{
          textAlign: 'center', padding: '8px 16px',
          border: `1px solid ${color}33`,
          borderRadius: 6, background: `${color}08`,
          width: '100%', transition: 'all 0.4s',
        }}>
          <div style={{ fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 3 }}>
            Active Verdict
          </div>
          <div style={{
            fontFamily: 'var(--font-display)', fontSize: 16, fontWeight: 700, color,
            textShadow: lastConf > 0.85 ? `0 0 16px ${color}88` : 'none',
            transition: 'all 0.4s',
          }}>
            {lastLabel || '—'}
          </div>
        </div>
      </div>

      {/* Class probability bars */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '8px 14px' }}>
        <div className="section-label">Class Probabilities</div>
        {top5.length === 0 ? (
          <div style={{ fontSize: 11, color: 'var(--text-muted)', textAlign: 'center', paddingTop: 12 }}>
            Awaiting prediction…
          </div>
        ) : (
          top5.map(([cls, prob]) => (
            <div key={cls} style={{ marginBottom: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                <span style={{ fontSize: 10.5, fontFamily: 'var(--font-mono)', color: 'var(--text-body)' }}>
                  {cls.slice(0, 16)}
                </span>
                <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
                  {(prob * 100).toFixed(1)}%
                </span>
              </div>
              <div style={{ height: 3, background: 'var(--border-panel)', borderRadius: 2 }}>
                <div style={{
                  height: '100%',
                  width: `${prob * 100}%`,
                  background: ATK_COLOR[cls] ?? 'var(--accent-blue)',
                  borderRadius: 2,
                  transition: 'width 0.4s ease',
                  boxShadow: prob > 0.7 ? `0 0 8px ${ATK_COLOR[cls] ?? 'var(--accent-blue)'}88` : 'none',
                }} />
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

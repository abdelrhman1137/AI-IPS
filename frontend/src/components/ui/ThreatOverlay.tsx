import { useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import type { FlowEvent } from '../../types';

interface Props {
  event: FlowEvent | null;
  onDismiss: () => void;
}

/** Full-screen vignette overlay for CRITICAL threats */
export default function ThreatOverlay({ event, onDismiss }: Props) {
  const timerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => {
    if (!event) return;
    // Play audio alert
    try {
      const AudioCtx = window.AudioContext || (window as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
      if (AudioCtx) {
        const ctx  = new AudioCtx();
        const osc  = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.frequency.setValueAtTime(880, ctx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(440, ctx.currentTime + 0.3);
        gain.gain.setValueAtTime(0.3, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.6);
        osc.start(ctx.currentTime);
        osc.stop(ctx.currentTime + 0.6);
      }
    } catch (_) {}

    clearTimeout(timerRef.current);
    timerRef.current = setTimeout(onDismiss, 4000);
    return () => clearTimeout(timerRef.current);
  }, [event, onDismiss]);

  return (
    <AnimatePresence>
      {event && (
        <motion.div
          className="threat-overlay"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.3 }}
          onClick={onDismiss}
        >
          {/* Red vignette */}
          <motion.div
            className="threat-overlay-bg"
            initial={{ opacity: 0 }}
            animate={{ opacity: [0, 1, 0.7] }}
            transition={{ duration: 0.5, times: [0, 0.1, 1] }}
          />
          {/* Corner border */}
          <div className="threat-overlay-border" />

          {/* Content */}
          <div className="threat-card">
            {/* Pulsing icon */}
            <motion.div
              style={{ fontSize: 48, marginBottom: 12, userSelect: 'none' }}
              animate={{ scale: [1, 1.1, 1], opacity: [1, 0.8, 1] }}
              transition={{ duration: 0.8, repeat: 3, ease: 'easeInOut' }}
            >
              <span style={{ filter: 'drop-shadow(0 0 20px #FF2D55)' }}>⚠</span>
            </motion.div>

            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--sev-critical)', letterSpacing: '0.2em', textTransform: 'uppercase', marginBottom: 8 }}>
              CRITICAL THREAT DETECTED
            </div>

            <div style={{ fontFamily: 'var(--font-display)', fontSize: 48, fontWeight: 700, color: 'var(--sev-critical)', textShadow: '0 0 40px rgba(255,45,85,0.7)', lineHeight: 1.1, marginBottom: 12 }}>
              {event.label.toUpperCase()}
            </div>

            <div style={{ display: 'flex', gap: 20, justifyContent: 'center', fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-body)', marginBottom: 16 }}>
              <span>CONF: <b style={{ color: 'var(--sev-critical)' }}>{(event.confidence * 100).toFixed(1)}%</b></span>
              <span>SRC: <b style={{ color: 'var(--text-heading)' }}>{event.src_ip || 'UNKNOWN'}</b></span>
              <span>PORT: <b>{event.port}</b></span>
            </div>

            <div style={{ display: 'flex', gap: 10, justifyContent: 'center' }}>
              {event.blocked && (
                <span style={{ padding: '4px 16px', borderRadius: 4, background: 'rgba(255,45,85,0.1)', border: '1px solid rgba(255,45,85,0.3)', color: 'var(--sev-critical)', fontSize: 11, fontWeight: 700, letterSpacing: '0.08em' }}>
                  IP BLOCKED
                </span>
              )}
              {event.is_sim && (
                <span className="badge badge-sim">SIMULATION</span>
              )}
            </div>

            <div style={{ marginTop: 20, fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              Click anywhere to dismiss
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

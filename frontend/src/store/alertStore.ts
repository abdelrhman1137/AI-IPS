import { create } from 'zustand';
import type { AlertRecord, FlowEvent, Severity } from '../types';

const MAX_FEED    = 80;
const MAX_ALERTS  = 1000;
const MAX_TS_LOG  = 2000;
const MAX_CONF    = 1000;

interface TsEntry { unix: number; label: string; is_sim: boolean; }
type ConfEntry = [string, number];
type ThruEntry = [number, number];

interface AlertStore {
  // Connection
  wsConnected: boolean;

  // Live state
  running:      boolean;
  simActive:    boolean;
  snifferOk:    boolean;
  snifferError: string;

  // Metrics
  rawPackets:    number;
  totalFlows:    number;
  alertCount:    number;
  threatRate:    number;
  avgConf:       number;
  uptimeSecs:    number;
  throughputBps: number;
  blockedIps:    string[];

  // Feed
  feed:       FlowEvent[];
  lastFlow:   FlowEvent | null;

  // History
  alerts:     AlertRecord[];
  tsLog:      TsEntry[];
  confHistory: ConfEntry[];
  throughput:  ThruEntry[];
  threatLog:   string[];

  // Settings
  sevFilter: Severity[];

  // Derived last prediction
  lastLabel: string;
  lastConf:  number;
  lastProbs: Record<string, number>;

  // Alert animation
  alertFlash: number; // increment to trigger animation

  // Actions
  setWsConnected:  (v: boolean) => void;
  setRunning:      (v: boolean) => void;
  setSimActive:    (v: boolean) => void;
  pushFlow:        (ev: FlowEvent) => void;
  pushAlert:       (a: AlertRecord) => void;
  setMetrics:      (m: Partial<AlertStore>) => void;
  setSevFilter:    (f: Severity[]) => void;
  loadInitial:     (data: any) => void;
  setAnalytics:    (data: any) => void;
  reset:           () => void;
}

export const useAlertStore = create<AlertStore>((set, get) => ({
  wsConnected:   false,
  running:       false,
  simActive:     false,
  snifferOk:     false,
  snifferError:  '',
  rawPackets:    0,
  totalFlows:    0,
  alertCount:    0,
  threatRate:    0,
  avgConf:       0,
  uptimeSecs:    0,
  throughputBps: 0,
  blockedIps:    [],
  feed:          [],
  lastFlow:      null,
  alerts:        [],
  tsLog:         [],
  confHistory:   [] as ConfEntry[],
  throughput:    [] as ThruEntry[],
  threatLog:     [],
  sevFilter:     ['CRITICAL', 'HIGH', 'MEDIUM'],
  lastLabel:     '—',
  lastConf:      0,
  lastProbs:     {},
  alertFlash:    0,

  setWsConnected: (v) => set({ wsConnected: v }),
  setRunning:     (v) => set({ running: v }),
  setSimActive:   (v) => set({ simActive: v }),
  setSevFilter:   (f) => set({ sevFilter: f }),

  pushFlow: (ev) => {
    const s = get();
    const newFeed = [ev, ...s.feed].slice(0, MAX_FEED);
    const newThreat = [...s.threatLog, ev.label].slice(-MAX_TS_LOG);
    const newConf   = [...s.confHistory, [ev.label, ev.confidence] as ConfEntry].slice(-MAX_CONF);
    const update: Partial<AlertStore> = {
      feed:        newFeed,
      lastFlow:    ev,
      lastLabel:   ev.label,
      lastConf:    ev.confidence,
      lastProbs:   ev.all_probs,
      threatLog:   newThreat,
      confHistory: newConf,
    };
    if (ev.fired) {
      const ts: TsEntry = { unix: ev.unix, label: ev.label, is_sim: ev.is_sim };
      update.tsLog = [...s.tsLog, ts].slice(-MAX_TS_LOG);
      update.alertFlash = s.alertFlash + 1;
      
      const alert: AlertRecord = {
        timestamp: ev.timestamp,
        unix: ev.unix,
        label: ev.label,
        severity: ev.severity,
        confidence: ev.confidence,
        port: ev.port,
        duration_us: ev.duration_us || 0,
        src: ev.is_sim ? 'SIM' : 'LIVE',
        src_ip: ev.src_ip,
        blocked: ev.blocked,
        pcap_path: ev.pcap_path,
        all_probs: ev.all_probs
      };
      update.alerts = [alert, ...s.alerts].slice(0, MAX_ALERTS);
    }
    set(update);
  },

  pushAlert: (a) => set(s => ({
    alerts: [a, ...s.alerts].slice(0, MAX_ALERTS),
  })),

  setMetrics: (m) => {
    const update: Partial<AlertStore> = { ...(m as any) };
    // Append to the throughput time-series whenever a bps value arrives
    if (typeof (m as any).throughputBps === 'number') {
      const bps = (m as any).throughputBps as number;
      const prev = useAlertStore.getState().throughput;
      update.throughput = [...prev, [Date.now() / 1000, bps] as ThruEntry].slice(-600);
    }
    set(update);
  },

  loadInitial: (data) => {
    set({
      running:       data.running       ?? false,
      simActive:     data.sim_active    ?? false,
      totalFlows:    data.total_flows   ?? 0,
      alertCount:    data.alert_count   ?? 0,
      threatRate:    data.threat_rate   ?? 0,
      avgConf:       data.avg_conf      ?? 0,
      uptimeSecs:    data.uptime_secs   ?? 0,
      throughputBps: data.throughput_bps ?? 0,
      alerts:        data.recent_alerts ?? [],
    });
  },

  setAnalytics: (data) => {
    set({
      tsLog:       (data.ts_log || []).map((t: any) => ({ unix: t[0], label: t[1], is_sim: t[2] })),
      confHistory: data.conf_history || [],
      throughput:  data.throughput   || [],
      threatLog:   data.threat_log   || [],
    });
  },

  reset: () => set({
    rawPackets: 0, totalFlows: 0, alertCount: 0,
    threatRate: 0, avgConf: 0, uptimeSecs: 0, throughputBps: 0,
    feed: [], alerts: [], tsLog: [], confHistory: [],
    throughput: [], threatLog: [], lastLabel: '—', lastConf: 0,
    lastProbs: {}, alertFlash: 0, simActive: false,
    blockedIps: [], snifferError: '',
  }),
}));

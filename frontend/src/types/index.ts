// ── Shared TypeScript types for AI-IDS NIGHTWATCH ────────────────────────────

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'CLEAN';
export type AlertSource = 'LIVE' | 'SIM';

export interface FlowEvent {
  type:       'flow';
  timestamp:  string;
  unix:       number;
  label:      string;
  severity:   Severity;
  confidence: number;
  port:       number;      // dst_port alias (kept for backward compat)
  src_ip:     string;
  dst_ip:     string;
  src_port:   number;
  dst_port:   number;
  is_sim:     boolean;
  blocked:    boolean;
  pcap_path:  string;
  all_probs:  Record<string, number>;
  fired:      boolean;
}

export interface MetricEvent {
  type:            'metric';
  raw_packets:     number;
  total_flows:     number;
  alert_count:     number;
  throughput_bps:  number;
  uptime_secs:     number;
  sniffer_running: boolean;
  sniffer_error:   string;
}

export interface AlertRecord {
  timestamp:   string;
  unix:        number;
  label:       string;
  severity:    Severity;
  confidence:  number;
  port:        number;
  duration_us: number;
  src:         AlertSource;
  src_ip:      string;
  blocked:     boolean;
  pcap_path:   string;
  all_probs:   Record<string, number>;
}

export interface SessionState {
  running:        boolean;
  sim_active:     boolean;
  sniffer_ok:     boolean;
  sniffer_error:  string;
  raw_packets:    number;
  total_flows:    number;
  alert_count:    number;
  threat_rate:    number;
  avg_conf:       number;
  uptime_secs:    number;
  throughput_bps: number;
  blocked_ips:    string[];
}

export interface EngineSettings {
  conf_threshold: number;
  guard:          number;
  auto_block:     boolean;
  webhook_url:    string;
  interface:      string;
}

export type WsMessage =
  | FlowEvent
  | MetricEvent
  | { type: 'init'; running: boolean; sim_active: boolean; recent_alerts: AlertRecord[]; total_flows: number; alert_count: number; threat_rate: number; avg_conf: number; uptime_secs: number; throughput_bps: number }
  | { type: 'sim_start' }
  | { type: 'sim_done' }
  | { type: 'pong' }
  | { type: 'error'; message: string };

// ── Color helpers ─────────────────────────────────────────────────────────────
export const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#FF2D55',
  HIGH:     '#FF6B35',
  MEDIUM:   '#FFB800',
  CLEAN:    '#00FF88',
};

export const ATK_COLOR: Record<string, string> = {
  'DoS':            '#FF2D55',
  'DDoS':           '#FF6B35',
  'Brute Force':    '#FFB800',
  'Port Scanning':  '#00D4FF',
  'Web Attacks':    '#00FF88',
  'Botnet':         '#BF5FFF',
  'Other Exploit':  '#F7DF1E',
  'Normal Traffic': '#2E4070',
};

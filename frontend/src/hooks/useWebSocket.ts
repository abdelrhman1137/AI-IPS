import { useEffect, useRef, useCallback } from 'react';
import { useAlertStore } from '../store/alertStore';
import type { WsMessage, FlowEvent } from '../types';

const WS_URL = `ws://${window.location.hostname}:8000/ws/feed`;
const PING_INTERVAL = 15_000;
const RECONNECT_DELAY = 2_000;

/** Force logout and reload — used when the server rejects our token (4001). */
function forceLogout() {
  localStorage.removeItem('nw_token');
  localStorage.removeItem('nw_email');
  window.location.reload();
}

export function useWebSocket(token: string | null) {
  const wsRef     = useRef<WebSocket | null>(null);
  const pingRef   = useRef<ReturnType<typeof setInterval> | undefined>(undefined);
  const retryRef  = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const aliveRef  = useRef(true);

  const { setWsConnected, loadInitial, pushFlow, setMetrics, setSimActive } =
    useAlertStore();

  const handleMessage = useCallback((ev: MessageEvent) => {
    try {
      const msg: WsMessage = JSON.parse(ev.data);

      switch (msg.type) {
        case 'init':
          loadInitial(msg);
          break;

        case 'flow':
          pushFlow(msg as FlowEvent);
          break;

        case 'metric':
          setMetrics({
            rawPackets:    msg.raw_packets,
            totalFlows:    msg.total_flows,
            alertCount:    msg.alert_count,
            throughputBps: msg.throughput_bps,
            uptimeSecs:    msg.uptime_secs,
            snifferOk:     msg.sniffer_running,
            snifferError:  msg.sniffer_error,
          });
          break;

        case 'sim_start':
          setSimActive(true);
          break;

        case 'sim_done':
          setSimActive(false);
          break;

        default:
          break;
      }
    } catch (_) {}
  }, [loadInitial, pushFlow, setMetrics, setSimActive]);

  const connect = useCallback(() => {
    if (!aliveRef.current) return;
    if (!token) return;

    const ws = new WebSocket(`${WS_URL}?token=${token}`);
    wsRef.current = ws;

    ws.onopen = () => {
      setWsConnected(true);
      pingRef.current = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) ws.send('ping');
      }, PING_INTERVAL);
    };

    ws.onmessage = handleMessage;

    ws.onclose = (ev) => {
      setWsConnected(false);
      clearInterval(pingRef.current);
      // Code 4001 = auth rejected (token invalid/expired) — do NOT retry, force logout
      if (ev.code === 4001) {
        forceLogout();
        return;
      }
      if (aliveRef.current) {
        retryRef.current = setTimeout(connect, RECONNECT_DELAY);
      }
    };

    ws.onerror = () => {
      ws.close();
    };
  }, [token, handleMessage, setWsConnected]);

  useEffect(() => {
    aliveRef.current = true;
    connect();
    return () => {
      aliveRef.current = false;
      clearInterval(pingRef.current);
      clearTimeout(retryRef.current);
      wsRef.current?.close();
    };
  }, [connect]);
}

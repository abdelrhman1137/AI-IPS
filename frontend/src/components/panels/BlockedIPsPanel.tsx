import React, { useState, useEffect, useCallback } from 'react';
import { Shield, RefreshCw } from 'lucide-react';
import { apiGet, apiPost } from '../../hooks/useAuth';
import type { SessionState } from '../../types';

export default function BlockedIPsPanel({ token }: { token: string }) {
  const [blockedIps, setBlockedIps] = useState<SessionState['blocked_ips']>([]);
  const [loading, setLoading] = useState(true);
  const [unblocking, setUnblocking] = useState<string | null>(null);

  const fetchBlocked = useCallback(async () => {
    try {
      const res = await apiGet('/session', token);
      if (res && !res._error && res.blocked_ips) {
        setBlockedIps(res.blocked_ips);
      } else if (res && !res._error) {
        setBlockedIps([]);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchBlocked();
    // Poll every 5s just in case
    const intv = setInterval(fetchBlocked, 5000);
    return () => clearInterval(intv);
  }, [token]);

  const handleUnblock = async (ip: string) => {
    setUnblocking(ip);
    try {
      const res = await apiPost('/engine/unblock', token, { ip });
      if (res?.success) {
        setBlockedIps(prev => prev.filter(b => b.ip !== ip));
      }
    } catch (e) {
      console.error(e);
    } finally {
      setUnblocking(null);
    }
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-muted)' }}>
        Loading blocked IPs...
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      {/* Toolbar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10,
        padding: '10px 14px', borderBottom: '1px solid var(--border-dim)', flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--sev-critical)', fontSize: 12, fontWeight: 600 }}>
          <Shield size={14} /> Active Windows Firewall Blocks
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
            {blockedIps.length} blocked
          </span>
          <button
            className="btn btn-ghost"
            style={{ padding: '4px 8px', fontSize: 10 }}
            onClick={() => { setLoading(true); fetchBlocked(); }}
            title="Refresh"
          >
            <RefreshCw size={11} />
          </button>
        </div>
      </div>

      {/* Table */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {blockedIps.length === 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 8 }}>
            <Shield size={28} color="var(--border-panel)" />
            <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>No IPs are currently blocked.</span>
            <span style={{ color: 'var(--text-muted)', fontSize: 11, textAlign: 'center', maxWidth: 260 }}>
              Enable <strong style={{ color: 'var(--text-dim)' }}>Auto-Block Critical IPs</strong> in Mitigation settings,
              then run a simulation or let live traffic trigger HIGH/CRITICAL alerts.
            </span>
          </div>
        ) : (
          <table className="nw-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Block Timestamp</th>
                <th>Reason</th>
                <th style={{ textAlign: 'right' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {blockedIps.map((b, i) => (
                <tr key={i}>
                  <td style={{ color: 'var(--text-bright)', fontWeight: 600 }}>{b.ip}</td>
                  <td style={{ color: 'var(--text-dim)' }}>{b.timestamp}</td>
                  <td style={{ color: 'var(--sev-critical)' }}>{b.reason}</td>
                  <td style={{ textAlign: 'right' }}>
                    <button 
                      className="btn btn-ghost" 
                      style={{ fontSize: 10, padding: '4px 10px', color: 'var(--accent-blue)', borderColor: 'var(--accent-blue)' }}
                      onClick={() => handleUnblock(b.ip)}
                      disabled={unblocking === b.ip}
                    >
                      {unblocking === b.ip ? 'Unblocking...' : 'Unblock'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

import { useState, useCallback } from 'react';

const API = '/api';

function authHeaders(token: string) {
  return { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` };
}

/** Safely parse JSON — returns {} if the body is empty or not valid JSON. */
async function safeJson(r: Response): Promise<Record<string, any>> {
  try {
    const text = await r.text();
    if (!text || text.trim() === '') return {};
    return JSON.parse(text);
  } catch {
    return {};
  }
}

/** Friendly message when the backend is completely unreachable. */
function reachabilityError(e: unknown): string {
  if (e instanceof TypeError && String(e).includes('fetch')) {
    return 'Cannot reach the server — make sure the backend is running on port 8000.';
  }
  return e instanceof Error ? e.message : 'Unknown error';
}

export function useAuth() {
  const [token, setToken]     = useState<string | null>(localStorage.getItem('nw_token'));
  const [email, setEmail]     = useState<string>(localStorage.getItem('nw_email') ?? '');
  const [error, setError]     = useState('');
  const [loading, setLoading] = useState(false);

  const login = useCallback(async (loginEmail: string, password: string) => {
    setLoading(true); setError('');
    try {
      const r    = await fetch(`${API}/auth/login`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ email: loginEmail, password }),
      });
      const data = await safeJson(r);
      if (!r.ok) throw new Error(data['detail'] ?? `Login failed (${r.status})`);
      localStorage.setItem('nw_token', data['access_token']);
      localStorage.setItem('nw_email', data['email']);
      setToken(data['access_token']);
      setEmail(data['email']);
    } catch (e) {
      setError(reachabilityError(e));
    } finally {
      setLoading(false);
    }
  }, []);

  const register = useCallback(async (regEmail: string, password: string) => {
    setLoading(true); setError('');
    try {
      const r    = await fetch(`${API}/auth/register`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ email: regEmail, password }),
      });
      const data = await safeJson(r);
      if (!r.ok) throw new Error(data['detail'] ?? `Registration failed (${r.status})`);
      return { success: true as const, message: data['message'] ?? 'Registered successfully' };
    } catch (e) {
      setError(reachabilityError(e));
      return { success: false as const };
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('nw_token');
    localStorage.removeItem('nw_email');
    setToken(null);
    setEmail('');
  }, []);

  return { token, email, error, loading, login, register, logout };
}

// ── Generic API helpers ────────────────────────────────────────────────────────
export async function apiPost(path: string, token: string, body?: object) {
  try {
    const r = await fetch(`${API}${path}`, {
      method:  'POST',
      headers: authHeaders(token),
      body:    body ? JSON.stringify(body) : undefined,
    });
    const data = await safeJson(r);
    // Attach HTTP status so callers know if this was an error
    if (!r.ok) return { ...data, _error: true, _status: r.status };
    return data;
  } catch (e) {
    return { _error: true, detail: reachabilityError(e) };
  }
}

export async function apiGet(path: string, token: string) {
  try {
    const r = await fetch(`${API}${path}`, { headers: authHeaders(token) });
    const data = await safeJson(r);
    if (!r.ok) return { ...data, _error: true, _status: r.status };
    return data;
  } catch (e) {
    return { _error: true, detail: reachabilityError(e) };
  }
}

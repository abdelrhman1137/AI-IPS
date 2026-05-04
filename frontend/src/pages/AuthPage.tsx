import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Lock, UserPlus, Eye, EyeOff, Activity } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';

interface Props {
  onAuthenticated: (token: string, email: string) => void;
}

// ── Validation helpers ────────────────────────────────────────────────────────
function sanitizeInput(value: string): string {
  // Strip leading/trailing whitespace and remove control characters
  return value.trim().replace(/[\x00-\x1F\x7F]/g, '');
}

function validateEmail(email: string): string {
  const e = sanitizeInput(email);
  if (!e) return 'Email is required.';
  if (e.length > 254) return 'Email is too long.';
  const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
  if (!emailRe.test(e)) return 'Please enter a valid email address.';
  return '';
}

function validatePassword(pw: string): string {
  if (!pw) return 'Password is required.';
  if (pw.length < 8) return 'Password must be at least 8 characters.';
  if (pw.length > 128) return 'Password is too long (max 128 characters).';
  return '';
}

export default function AuthPage({ onAuthenticated }: Props) {
  const [tab, setTab]               = useState<'login' | 'register'>('login');
  const [email, setEmail]           = useState('');
  const [password, setPassword]     = useState('');
  const [confirmPw, setConfirmPw]   = useState('');
  const [showPw, setShowPw]         = useState(false);
  const [showCfm, setShowCfm]       = useState(false);
  const [success, setSuccess]       = useState('');
  const [localErr, setLocalErr]     = useState('');
  const { login, register, error, loading } = useAuth();

  // If already authenticated via localStorage
  React.useEffect(() => {
    const savedToken = localStorage.getItem('nw_token');
    const savedEmail = localStorage.getItem('nw_email');
    if (savedToken && savedEmail) onAuthenticated(savedToken, savedEmail);
  }, []);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalErr('');
    const emailErr = validateEmail(email);
    if (emailErr) { setLocalErr(emailErr); return; }
    const pwErr = validatePassword(password);
    if (pwErr) { setLocalErr(pwErr); return; }

    await login(sanitizeInput(email), password);
    const newToken = localStorage.getItem('nw_token');
    const newEmail = localStorage.getItem('nw_email');
    if (newToken && newEmail) onAuthenticated(newToken, newEmail);
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalErr('');
    const emailErr = validateEmail(email);
    if (emailErr) { setLocalErr(emailErr); return; }
    const pwErr = validatePassword(password);
    if (pwErr) { setLocalErr(pwErr); return; }
    if (password !== confirmPw) { setLocalErr('Passwords do not match.'); return; }

    const res = await register(sanitizeInput(email), password);
    if (res?.success) {
      setSuccess('Account created. Sign in to access the console.');
      setTab('login');
      setPassword('');
      setConfirmPw('');
    }
  };

  const switchTab = (t: 'login' | 'register') => {
    setTab(t);
    setLocalErr('');
    setSuccess('');
    setPassword('');
    setConfirmPw('');
  };

  const displayError = localErr || error;

  return (
    <div className="w-full h-full flex items-center justify-center relative overflow-hidden"
         style={{ background: 'var(--bg-void)' }}>

      {/* Animated background grid */}
      <div className="absolute inset-0 pointer-events-none"
           style={{
             backgroundImage: `linear-gradient(var(--border-dim) 1px, transparent 1px),
                               linear-gradient(90deg, var(--border-dim) 1px, transparent 1px)`,
             backgroundSize: '48px 48px',
             maskImage: 'radial-gradient(ellipse 80% 80% at 50% 50%, black 40%, transparent 100%)',
           }} />

      {/* Center glow */}
      <div className="absolute w-[600px] h-[600px] rounded-full pointer-events-none"
           style={{ background: 'radial-gradient(circle, rgba(0,212,255,0.04) 0%, transparent 70%)' }} />

      <motion.div
        initial={{ opacity: 0, y: 20, scale: 0.98 }}
        animate={{ opacity: 1, y: 0,  scale: 1 }}
        transition={{ duration: 0.5, ease: [0.22,1,0.36,1] }}
        className="relative w-[420px]"
      >
        {/* Logo */}
        <div className="text-center mb-10">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-xl mb-4"
               style={{ background: 'rgba(0,212,255,0.08)', border: '1px solid rgba(0,212,255,0.2)', boxShadow: '0 0 40px rgba(0,212,255,0.1)' }}>
            <Shield size={28} color="var(--accent-blue)" />
          </div>
          <div className="font-display text-4xl font-bold text-heading glow-blue"
               style={{ fontFamily: 'var(--font-display)', letterSpacing: '0.08em' }}>
            AIPS
          </div>
          <div className="text-xs font-mono" style={{ color: 'var(--text-dim)', letterSpacing: '0.2em', marginTop: 4 }}>
            AI INTRUSION PREVENTION SYSTEM
          </div>
        </div>

        {/* Card */}
        <div className="panel-glass" style={{ borderColor: 'rgba(0,212,255,0.12)' }}>
          {/* Tabs */}
          <div className="flex border-b" style={{ borderColor: 'var(--border-panel)' }}>
            {(['login', 'register'] as const).map(t => (
              <button key={t}
                onClick={() => switchTab(t)}
                className="flex-1 flex items-center justify-center gap-2 py-3 text-xs font-semibold tracking-widest uppercase transition-colors"
                style={{
                  color: tab === t ? 'var(--accent-blue)' : 'var(--text-dim)',
                  borderBottom: tab === t ? '2px solid var(--accent-blue)' : '2px solid transparent',
                  marginBottom: '-1px',
                  background: 'none',
                  cursor: 'pointer',
                  fontFamily: 'var(--font-body)',
                  letterSpacing: '0.1em',
                }}
              >
                {t === 'login' ? <Lock size={13} /> : <UserPlus size={13} />}
                {t === 'login' ? 'Sign In' : 'Register'}
              </button>
            ))}
          </div>

          {/* Form */}
          <div className="p-8">
            <AnimatePresence mode="wait">
              <motion.form
                key={tab}
                initial={{ opacity: 0, x: tab === 'login' ? -12 : 12 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.2 }}
                onSubmit={tab === 'login' ? handleLogin : handleRegister}
                noValidate
              >
                <div className="space-y-4">
                  {/* Email */}
                  <div>
                    <label className="block mb-1.5" style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--text-dim)' }}>
                      Email Address
                    </label>
                    <input
                      type="email"
                      required
                      maxLength={254}
                      autoComplete="email"
                      value={email}
                      onChange={e => setEmail(e.target.value)}
                      placeholder="operator@example.com"
                      className="input"
                    />
                  </div>

                  {/* Password */}
                  <div>
                    <label className="block mb-1.5" style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--text-dim)' }}>
                      Password
                    </label>
                    <div className="relative">
                      <input
                        type={showPw ? 'text' : 'password'}
                        required
                        minLength={8}
                        maxLength={128}
                        autoComplete={tab === 'login' ? 'current-password' : 'new-password'}
                        value={password}
                        onChange={e => setPassword(e.target.value)}
                        placeholder="Min. 8 characters"
                        className="input pr-10"
                      />
                      <button type="button" onClick={() => setShowPw(p => !p)}
                              className="absolute right-3 top-1/2 -translate-y-1/2"
                              style={{ color: 'var(--text-dim)', background: 'none', border: 'none', cursor: 'pointer' }}>
                        {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
                      </button>
                    </div>
                  </div>

                  {/* Confirm Password (register only) */}
                  {tab === 'register' && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                    >
                      <label className="block mb-1.5" style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--text-dim)' }}>
                        Confirm Password
                      </label>
                      <div className="relative">
                        <input
                          type={showCfm ? 'text' : 'password'}
                          required
                          maxLength={128}
                          autoComplete="new-password"
                          value={confirmPw}
                          onChange={e => setConfirmPw(e.target.value)}
                          placeholder="Re-enter password"
                          className="input pr-10"
                          style={{
                            borderColor: confirmPw && confirmPw !== password
                              ? 'rgba(255,45,85,0.5)'
                              : confirmPw && confirmPw === password
                              ? 'rgba(0,255,136,0.4)'
                              : undefined
                          }}
                        />
                        <button type="button" onClick={() => setShowCfm(p => !p)}
                                className="absolute right-3 top-1/2 -translate-y-1/2"
                                style={{ color: 'var(--text-dim)', background: 'none', border: 'none', cursor: 'pointer' }}>
                          {showCfm ? <EyeOff size={15} /> : <Eye size={15} />}
                        </button>
                      </div>
                      {confirmPw && confirmPw !== password && (
                        <div style={{ fontSize: 10, color: 'var(--sev-critical)', marginTop: 4 }}>
                          Passwords do not match
                        </div>
                      )}
                      {confirmPw && confirmPw === password && (
                        <div style={{ fontSize: 10, color: 'var(--accent-green)', marginTop: 4 }}>
                          ✓ Passwords match
                        </div>
                      )}
                    </motion.div>
                  )}

                  {/* Error / success messages */}
                  {displayError && (
                    <div className="text-xs px-3 py-2 rounded" style={{ background: 'rgba(255,45,85,0.08)', border: '1px solid rgba(255,45,85,0.2)', color: 'var(--sev-critical)' }}>
                      {displayError}
                    </div>
                  )}
                  {success && (
                    <div className="text-xs px-3 py-2 rounded" style={{ background: 'rgba(0,255,136,0.06)', border: '1px solid rgba(0,255,136,0.2)', color: 'var(--accent-green)' }}>
                      {success}
                    </div>
                  )}

                  <button type="submit" disabled={loading}
                          className="btn btn-start w-full mt-2 justify-center"
                          style={{ width: '100%', fontSize: 13 }}>
                    <Activity size={14} />
                    {loading ? 'Please wait…' : tab === 'login' ? 'Access Console' : 'Create Account'}
                  </button>
                </div>
              </motion.form>
            </AnimatePresence>
          </div>
        </div>
      </motion.div>
    </div>
  );
}

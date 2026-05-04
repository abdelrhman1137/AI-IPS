import React, { useState } from 'react';
import AuthPage from './pages/AuthPage';
import DashboardPage from './pages/DashboardPage';

/** Decode JWT payload and return true if the token is expired or malformed. */
function isTokenExpired(token: string | null): boolean {
  if (!token) return true;
  try {
    const payload = token.split('.')[1];
    const decoded = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
    // exp is in seconds, Date.now() is in ms
    return decoded.exp * 1000 < Date.now();
  } catch {
    return true; // malformed token → treat as expired
  }
}

function getValidToken(): string | null {
  const stored = localStorage.getItem('nw_token');
  if (isTokenExpired(stored)) {
    // Wipe stale credentials so login screen appears immediately
    localStorage.removeItem('nw_token');
    localStorage.removeItem('nw_email');
    return null;
  }
  return stored;
}

export default function App() {
  const [token, setToken] = useState<string | null>(getValidToken);
  const [email, setEmail] = useState(localStorage.getItem('nw_email') ?? '');

  const handleAuthenticated = (t: string, e: string) => {
    setToken(t);
    setEmail(e);
  };

  const handleLogout = () => {
    localStorage.removeItem('nw_token');
    localStorage.removeItem('nw_email');
    setToken(null);
    setEmail('');
  };

  if (!token) {
    return <AuthPage onAuthenticated={handleAuthenticated} />;
  }

  return (
    <DashboardPage
      token={token}
      email={email}
      onLogout={handleLogout}
    />
  );
}

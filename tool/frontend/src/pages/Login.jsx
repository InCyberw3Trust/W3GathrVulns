import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'

export default function Login() {
  const { login } = useAuth()
  const navigate   = useNavigate()

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error,    setError]    = useState('')
  const [loading,  setLoading]  = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(username, password)
      navigate('/dashboard', { replace: true })
    } catch (err) {
      setError(err.response?.status === 401 ? 'Invalid username or password.' : 'Login failed — is the API running?')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'var(--bg-base)',
    }}>
      {/* Background glow */}
      <div style={{
        position: 'fixed', top: '20%', left: '50%', transform: 'translateX(-50%)',
        width: 500, height: 500, borderRadius: '50%',
        background: 'radial-gradient(circle, var(--accent-dim) 0%, transparent 70%)',
        pointerEvents: 'none',
      }}/>

      <div style={{ width: '100%', maxWidth: 400, padding: '0 1.5rem' }}>
        {/* Brand */}
        <div style={{ textAlign: 'center', marginBottom: '2.5rem' }}>
          <div style={{
            width: 200, height: 200, borderRadius: 16, margin: '0 auto 1rem',
            background: 'linear-gradient(310deg,#060b28,#0b1437)',
            overflow: 'hidden',
            boxShadow: '0 4px 20px rgba(33,82,255,0.35)',
          }}>
            <img
              src="/logo.png"
              alt="W3GathrVulns"
              style={{ width: '100%', height: '100%', display: 'block', objectFit: 'cover', marginTop: 10 }}
            />
          </div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
            W3Gathr<span style={{ color: '#63b3ed' }}>Vulns</span>
          </h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.83rem', marginTop: 4 }}>
            Security findings management
          </p>
        </div>

        {/* Card */}
        <div className="card" style={{ padding: '2rem' }}>
          <h2 style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '1.5rem' }}>
            Sign in
          </h2>

          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div>
              <label style={{
                display: 'block', fontSize: '0.75rem', fontWeight: 600,
                color: 'var(--text-muted)', marginBottom: 6,
                textTransform: 'uppercase', letterSpacing: '0.06em',
              }}>
                Username
              </label>
              <input
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                autoFocus
                autoComplete="username"
                required
                placeholder="admin"
                style={inputStyle}
              />
            </div>

            <div>
              <label style={{
                display: 'block', fontSize: '0.75rem', fontWeight: 600,
                color: 'var(--text-muted)', marginBottom: 6,
                textTransform: 'uppercase', letterSpacing: '0.06em',
              }}>
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                autoComplete="current-password"
                required
                placeholder="••••••••"
                style={inputStyle}
              />
            </div>

            {error && (
              <div style={{
                background: 'rgba(252,129,129,0.1)', border: '1px solid rgba(252,129,129,0.3)',
                borderRadius: 8, padding: '0.65rem 0.9rem',
                fontSize: '0.83rem', color: '#fc8181',
              }}>
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="btn btn-primary"
              style={{ marginTop: 4, width: '100%', padding: '0.7rem', fontSize: '0.9rem', justifyContent: 'center', opacity: loading ? 0.7 : 1 }}
            >
              {loading ? 'Signing in…' : 'Sign in'}
            </button>
          </form>
        </div>

        <p style={{ textAlign: 'center', marginTop: '1.5rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          v0.1.0-beta · Self-hosted
        </p>
      </div>
    </div>
  )
}

const inputStyle = {
  width: '100%',
  background: 'var(--bg-elevated)',
  border: '1px solid var(--border)',
  borderRadius: 8,
  color: 'var(--text-primary)',
  fontSize: '0.88rem',
  padding: '0.6rem 0.85rem',
  outline: 'none',
  transition: 'border-color 0.15s',
  fontFamily: 'var(--font-ui)',
}

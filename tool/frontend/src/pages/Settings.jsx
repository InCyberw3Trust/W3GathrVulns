import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { fetchTokens, regenerateToken, changePassword, fetchAppConfig } from '../api/client.js'

// ── Section wrapper ───────────────────────────────────────────────────────────
function Section({ title, children }) {
  return (
    <div className="card" style={{ marginBottom: '1.5rem' }}>
      <p style={{
        fontSize: '0.68rem', fontWeight: 700, color: 'var(--text-muted)',
        textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: '1.2rem',
      }}>
        {title}
      </p>
      {children}
    </div>
  )
}

// ── Demo mode lock notice ─────────────────────────────────────────────────────
function DemoLock() {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 10,
      background: 'rgba(251,191,36,0.08)', border: '1px solid rgba(251,191,36,0.3)',
      borderRadius: 8, padding: '0.7rem 1rem', fontSize: '0.82rem',
      color: '#fbbf24',
    }}>
      <svg viewBox="0 0 24 24" fill="currentColor" width="16" height="16" style={{ flexShrink: 0 }}>
        <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>
      </svg>
      Not available in demo mode
    </div>
  )
}

// ── Token row ─────────────────────────────────────────────────────────────────
function TokenRow({ label, preview, tokenType, onNewToken, locked }) {
  const queryClient = useQueryClient()
  const [revealed,  setRevealed]  = useState(null)   // full token after regen
  const [confirming, setConfirming] = useState(false)

  const { mutate, isPending } = useMutation({
    mutationFn: () => regenerateToken(tokenType),
    onSuccess: (data) => {
      setRevealed(data.token)
      setConfirming(false)
      queryClient.invalidateQueries(['tokens'])
      if (onNewToken) onNewToken(data.token)
      toast.success(`${label} regenerated — copy it now, it won't be shown again`)
    },
    onError: () => toast.error('Failed to regenerate token'),
  })

  function handleCopy(text) {
    navigator.clipboard.writeText(text)
      .then(() => toast.success('Copied to clipboard'))
      .catch(() => toast.error('Copy failed'))
  }

  if (locked) {
    return (
      <div style={{ marginBottom: '1.2rem' }}>
        <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)' }}>{label}</span>
        <div style={{ marginTop: 8, display: 'flex', alignItems: 'center', gap: 8, background: 'var(--bg-elevated)', borderRadius: 8, padding: '0.5rem 0.85rem', border: '1px solid var(--border)' }}>
          <code style={{ flex: 1, fontSize: '0.82rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>{preview}</code>
        </div>
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: '1.2rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)' }}>{label}</span>
        {!confirming && !revealed && (
          <button
            className="btn btn-ghost"
            style={{ fontSize: '0.75rem', padding: '3px 10px' }}
            onClick={() => setConfirming(true)}
          >
            Regenerate
          </button>
        )}
      </div>

      {/* Current masked preview */}
      {!revealed && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 8,
          background: 'var(--bg-elevated)', borderRadius: 8,
          padding: '0.5rem 0.85rem', border: '1px solid var(--border)',
        }}>
          <code style={{ flex: 1, fontSize: '0.82rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
            {preview}
          </code>
        </div>
      )}

      {/* New token revealed after regen */}
      {revealed && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 8,
          background: 'rgba(104,211,145,0.08)', borderRadius: 8,
          padding: '0.5rem 0.85rem',
          border: '1px solid rgba(104,211,145,0.3)',
        }}>
          <code style={{ flex: 1, fontSize: '0.8rem', fontFamily: 'var(--font-mono)', color: '#68d391', wordBreak: 'break-all' }}>
            {revealed}
          </code>
          <button
            onClick={() => handleCopy(revealed)}
            title="Copy"
            style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: '#68d391', padding: '2px 6px', flexShrink: 0 }}
          >
            <svg viewBox="0 0 24 24" fill="currentColor" width="16" height="16">
              <path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/>
            </svg>
          </button>
        </div>
      )}
      {revealed && (
        <p style={{ fontSize: '0.72rem', color: '#f6ad55' }}>
          Save this token now — it will not be shown again after you leave this page.
        </p>
      )}

      {/* Confirm regeneration */}
      {confirming && (
        <div style={{
          background: 'rgba(252,129,129,0.08)', border: '1px solid rgba(252,129,129,0.25)',
          borderRadius: 8, padding: '0.75rem 1rem', display: 'flex', flexDirection: 'column', gap: 8,
        }}>
          <p style={{ fontSize: '0.82rem', color: '#fc8181' }}>
            Regenerating will invalidate the current token. All CI/CD pipelines using it will need to be updated.
          </p>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              className="btn"
              style={{ fontSize: '0.78rem', padding: '4px 14px', background: '#fc8181', color: '#0b1437', fontWeight: 700, border: 'none', borderRadius: 6 }}
              onClick={() => mutate()}
              disabled={isPending}
            >
              {isPending ? 'Regenerating…' : 'Yes, regenerate'}
            </button>
            <button className="btn btn-ghost" style={{ fontSize: '0.78rem', padding: '4px 14px' }} onClick={() => setConfirming(false)}>
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Change password form ──────────────────────────────────────────────────────
function ChangePasswordForm() {
  const [current,  setCurrent]  = useState('')
  const [next,     setNext]     = useState('')
  const [confirm,  setConfirm]  = useState('')
  const [err,      setErr]      = useState('')

  const { mutate, isPending } = useMutation({
    mutationFn: () => changePassword({ current_password: current, new_password: next }),
    onSuccess: () => {
      toast.success('Password updated')
      setCurrent(''); setNext(''); setConfirm(''); setErr('')
    },
    onError: (e) => {
      const msg = e.response?.data?.detail || 'Failed to change password'
      setErr(msg)
    },
  })

  function handleSubmit(e) {
    e.preventDefault()
    setErr('')
    if (next !== confirm) { setErr('New passwords do not match'); return }
    if (next.length < 8)  { setErr('New password must be at least 8 characters'); return }
    mutate()
  }

  const inputStyle = {
    width: '100%', background: 'var(--bg-elevated)',
    border: '1px solid var(--border)', borderRadius: 8,
    color: 'var(--text-primary)', fontSize: '0.88rem',
    padding: '0.55rem 0.85rem', outline: 'none',
    fontFamily: 'var(--font-ui)',
  }

  return (
    <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem', maxWidth: 400 }}>
      {[
        { label: 'Current password', value: current, set: setCurrent },
        { label: 'New password',     value: next,    set: setNext,    hint: 'Minimum 8 characters' },
        { label: 'Confirm new password', value: confirm, set: setConfirm },
      ].map(({ label, value, set, hint }) => (
        <div key={label}>
          <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            {label}
          </label>
          <input type="password" value={value} onChange={e => set(e.target.value)} required style={inputStyle} autoComplete="new-password" />
          {hint && <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: 4 }}>{hint}</p>}
        </div>
      ))}

      {err && (
        <div style={{ background: 'rgba(252,129,129,0.1)', border: '1px solid rgba(252,129,129,0.3)', borderRadius: 8, padding: '0.6rem 0.9rem', fontSize: '0.82rem', color: '#fc8181' }}>
          {err}
        </div>
      )}

      <button type="submit" className="btn btn-primary" style={{ alignSelf: 'flex-start', padding: '0.55rem 1.4rem', opacity: isPending ? 0.7 : 1 }} disabled={isPending}>
        {isPending ? 'Saving…' : 'Update password'}
      </button>
    </form>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function Settings() {
  const { data, isPending }       = useQuery({ queryKey: ['tokens'],     queryFn: fetchTokens })
  const { data: appConfig }       = useQuery({ queryKey: ['app-config'], queryFn: fetchAppConfig, staleTime: Infinity })
  const demoMode = appConfig?.demo_mode ?? false

  return (
    <div className="animate-in" style={{ maxWidth: 720 }}>
      <h1 style={{ fontSize: '1.55rem', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-primary)', marginBottom: '0.4rem' }}>
        Settings
      </h1>
      <p style={{ color: 'var(--text-muted)', fontSize: '0.82rem', marginBottom: demoMode ? '1rem' : '2rem' }}>
        Manage API tokens and admin account credentials.
      </p>

      {demoMode && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10, marginBottom: '1.5rem',
          background: 'rgba(251,191,36,0.08)', border: '1px solid rgba(251,191,36,0.3)',
          borderRadius: 8, padding: '0.75rem 1rem', fontSize: '0.85rem', color: '#fbbf24',
        }}>
          <svg viewBox="0 0 24 24" fill="currentColor" width="18" height="18" style={{ flexShrink: 0 }}>
            <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>
          </svg>
          <span><strong>Demo mode</strong> — token regeneration and password changes are disabled on this instance.</span>
        </div>
      )}

      {/* API Tokens */}
      <Section title="API Tokens">
        <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '1.2rem', lineHeight: 1.6 }}>
          Use <strong style={{ color: 'var(--text-secondary)' }}>Write token</strong> in CI/CD pipelines for ingest (requires <code style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>Authorization: Bearer &lt;token&gt;</code>).<br/>
          Use <strong style={{ color: 'var(--text-secondary)' }}>Read token</strong> for read-only access (dashboards, exports).
        </p>

        {isPending ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {[1,2].map(i => <div key={i} style={{ height: 36, background: 'var(--bg-elevated)', borderRadius: 8 }}/>)}
          </div>
        ) : (
          <>
            <TokenRow label="Write token (full access)" preview={data?.write_token_preview} tokenType="write" locked={demoMode} />
            <TokenRow label="Read token (GET only)"     preview={data?.read_token_preview}  tokenType="read"  locked={demoMode} />
          </>
        )}
      </Section>

      {/* Change password */}
      <Section title="Admin Password">
        {demoMode ? <DemoLock /> : <ChangePasswordForm />}
      </Section>
    </div>
  )
}

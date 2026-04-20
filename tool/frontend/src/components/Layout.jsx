import React, { useState, useEffect } from 'react'
import { Outlet, NavLink, useLocation, useNavigate } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import { useAuth } from '../context/AuthContext.jsx'

const NAV = [
  {
    to: '/dashboard', label: 'Dashboard',
    gradient: 'linear-gradient(310deg,#2152ff,#21d4fd)',
    icon: <svg viewBox="0 0 24 24" fill="currentColor" width="15" height="15"><path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z"/></svg>,
  },
  {
    to: '/findings', label: 'Findings',
    gradient: 'linear-gradient(310deg,#f5365c,#f56036)',
    icon: <svg viewBox="0 0 24 24" fill="currentColor" width="15" height="15"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>,
  },
  {
    to: '/projects', label: 'Projects',
    gradient: 'linear-gradient(310deg,#17ad37,#98ec2d)',
    icon: <svg viewBox="0 0 24 24" fill="currentColor" width="15" height="15"><path d="M20 6h-8l-2-2H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2z"/></svg>,
  },
  {
    to: '/rules', label: 'Rules',
    gradient: 'linear-gradient(310deg,#7928ca,#ff0080)',
    icon: <svg viewBox="0 0 24 24" fill="currentColor" width="15" height="15"><path d="M13 2.05v2.02c3.95.49 7 3.85 7 7.93 0 3.21-1.81 6-4.72 7.28L13 17v5h5l-1.22-1.22C19.91 19.07 22 15.76 22 12c0-5.18-3.95-9.45-9-9.95zM11 2.05C5.95 2.55 2 6.82 2 12c0 3.76 2.09 7.07 5.22 8.78L6 22h5V2.05z"/></svg>,
  },
  {
    to: '/debug', label: 'Debug',
    gradient: 'linear-gradient(310deg,#627594,#a8b8d8)',
    icon: <svg viewBox="0 0 24 24" fill="currentColor" width="15" height="15"><path d="M20 8h-2.81c-.45-.78-1.07-1.45-1.82-1.96l1.4-1.4-1.41-1.42-1.92 1.92C13 4.75 12.51 4.6 12 4.6s-1 .15-1.45.43L8.64 3.11 7.22 4.52l1.4 1.4C7.88 6.55 7.26 7.22 6.81 8H4v2h2.09c-.05.33-.09.66-.09 1v1H4v2h2v1c0 .34.04.67.09 1H4v2h2.81c1.04 1.79 2.97 3 5.19 3s4.15-1.21 5.19-3H20v-2h-2.09c.05-.33.09-.66.09-1v-1h2v-2h-2v-1c0-.34-.04-.67-.09-1H20V8zm-6 8h-4v-2h4v2zm0-4h-4v-2h4v2z"/></svg>,
  },
  {
    to: '/settings', label: 'Settings',
    gradient: 'linear-gradient(310deg,#4a5568,#718096)',
    icon: <svg viewBox="0 0 24 24" fill="currentColor" width="15" height="15"><path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58c.18-.14.23-.41.12-.61l-1.92-3.32c-.12-.22-.37-.29-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54c-.04-.24-.24-.41-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58c-.18.14-.23.41-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z"/></svg>,
  },
  {
    to: '/docs', label: 'API Docs',
    gradient: 'linear-gradient(310deg,#f77f00,#ffd60a)',
    icon: <svg viewBox="0 0 24 24" fill="currentColor" width="15" height="15"><path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>,
  },
]

// ── Theme persistence ─────────────────────────────────────────────────────────
function getInitialTheme() {
  return localStorage.getItem('w3g_theme') || 'dark'
}
function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme)
  localStorage.setItem('w3g_theme', theme)
}

export default function Layout() {
  const [collapsed,  setCollapsed]  = useState(false)
  const [theme,      setTheme]      = useState(getInitialTheme)
  const { logout }                  = useAuth()
  const location                    = useLocation()
  const navigate                    = useNavigate()
  const W = collapsed ? 78 : 240

  // Apply theme on mount and on change
  useEffect(() => { applyTheme(theme) }, [theme])

  const toggleTheme = () => setTheme(t => t === 'dark' ? 'light' : 'dark')

  const isDark = theme === 'dark'

  function handleLogout() {
    logout()
    navigate('/login', { replace: true })
  }

  return (
    <div style={{ display:'flex', minHeight:'100vh', background:'var(--bg-base)' }}>

      {/* Sidebar */}
      <aside style={{
        width: W, flexShrink: 0,
        background: 'var(--bg-sidebar)',
        backdropFilter: 'blur(40px)', WebkitBackdropFilter: 'blur(40px)',
        borderRight: '1px solid var(--border)',
        boxShadow: 'var(--shadow-sidebar)',
        display: 'flex', flexDirection: 'column',
        position: 'fixed', top:0, left:0, bottom:0, zIndex:200,
        transition: 'width 0.22s cubic-bezier(.4,0,.2,1)',
        overflow: 'hidden',
      }}>

        {/* Brand */}
        <div style={{
          padding: collapsed ? '1.5rem 0' : '1.5rem 1.4rem',
          borderBottom: '1px solid var(--border)',
          display:'flex', alignItems:'center', gap:10,
          justifyContent: collapsed ? 'center' : 'flex-start',
          minHeight: 68,
        }}>
          <div style={{
            width:90, height:90, borderRadius:10, flexShrink:0,
            background:'linear-gradient(310deg,#060b28,#0b1437)',
            overflow:'hidden',
          }}>
            <img
              src="/logo.png"
              alt="W3GathrVulns"
              style={{ width:'100%', height:'100%', display:'block', objectFit:'cover', marginTop: 10 }}
            />
          </div>
          {!collapsed && (
            <div style={{ overflow:'hidden' }}>
              <div style={{ fontWeight:700, fontSize:'0.95rem', whiteSpace:'nowrap', color:'var(--text-primary)', letterSpacing:'-0.01em' }}>
                W3Gathr<span style={{ color:'#63b3ed' }}>Vulns</span>
              </div>
              <div style={{ fontSize:'0.65rem', color:'var(--text-muted)', fontFamily:'var(--font-mono)', letterSpacing:'0.06em' }}>
                v0.1.0-beta
              </div>
            </div>
          )}
        </div>

        {/* Nav */}
        <nav style={{ flex:1, padding:'1rem 0', overflowY:'auto', overflowX:'hidden' }}>
          {!collapsed && (
            <div style={{
              padding:'0 1.4rem 0.6rem',
              fontSize:'0.63rem', fontWeight:700,
              color:'var(--text-muted)', letterSpacing:'0.12em', textTransform:'uppercase',
            }}>
              Main menu
            </div>
          )}
          {NAV.map(({ to, label, icon, gradient }) => (
            <NavLink key={to} to={to} style={{ textDecoration:'none', display:'block' }}>
              {({ isActive }) => (
                <div style={{
                  display:'flex', alignItems:'center', gap:12,
                  padding: collapsed ? '0.6rem 0' : '0.6rem 1.4rem',
                  justifyContent: collapsed ? 'center' : 'flex-start',
                  cursor:'pointer', transition:'all 0.15s',
                  position:'relative', margin:'2px 0',
                  background: isActive && !collapsed ? 'var(--bg-elevated)' : 'transparent',
                  borderRadius: !collapsed ? '0 10px 10px 0' : 0,
                  marginRight: !collapsed ? '0.6rem' : 0,
                }}>
                  {isActive && !collapsed && (
                    <div style={{
                      position:'absolute', left:0, top:4, bottom:4,
                      width:3, borderRadius:'0 3px 3px 0',
                      background:'linear-gradient(180deg,#4299e1,#63b3ed)',
                    }}/>
                  )}
                  <div style={{
                    width:34, height:34, borderRadius:9, flexShrink:0,
                    background: isActive ? gradient : 'var(--bg-elevated)',
                    display:'flex', alignItems:'center', justifyContent:'center',
                    color: isActive ? '#fff' : 'var(--text-muted)',
                    transition:'all 0.18s',
                    boxShadow: isActive ? '0 2px 12px rgba(0,0,0,0.2)' : 'none',
                  }}>
                    {icon}
                  </div>
                  {!collapsed && (
                    <span style={{
                      fontSize:'0.87rem',
                      fontWeight: isActive ? 600 : 400,
                      color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
                      transition:'color 0.15s', whiteSpace:'nowrap',
                    }}>
                      {label}
                    </span>
                  )}
                </div>
              )}
            </NavLink>
          ))}
        </nav>

        {/* Footer — theme toggle, logout, collapse */}
        <div style={{ borderTop:'1px solid var(--border)' }}>

          {/* API status */}
          {!collapsed && (
            <div style={{ padding:'0.6rem 1.4rem', display:'flex', alignItems:'center', gap:8 }}>
              <div style={{
                width:7, height:7, borderRadius:'50%', background:'#68d391', flexShrink:0,
                boxShadow:'0 0 6px rgba(104,211,145,0.6)',
              }}/>
              <span style={{ fontSize:'0.7rem', color:'var(--text-muted)', fontFamily:'var(--font-mono)' }}>
                API LIVE
              </span>
            </div>
          )}

          {/* Theme toggle */}
          <button
            onClick={toggleTheme}
            title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
            style={{
              width:'100%', padding: collapsed ? '0.6rem' : '0.55rem 1.4rem',
              background:'transparent', border:'none', cursor:'pointer',
              display:'flex', alignItems:'center', gap:10,
              justifyContent: collapsed ? 'center' : 'flex-start',
              color: 'var(--text-muted)', transition:'color 0.15s, background 0.15s',
            }}
            onMouseEnter={e => { e.currentTarget.style.background = 'var(--bg-elevated)'; e.currentTarget.style.color = 'var(--text-primary)' }}
            onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = 'var(--text-muted)' }}
          >
            {isDark
              ? <svg viewBox="0 0 24 24" fill="currentColor" width="16" height="16"><path d="M12 7c-2.76 0-5 2.24-5 5s2.24 5 5 5 5-2.24 5-5-2.24-5-5-5zM2 13h2c.55 0 1-.45 1-1s-.45-1-1-1H2c-.55 0-1 .45-1 1s.45 1 1 1zm18 0h2c.55 0 1-.45 1-1s-.45-1-1-1h-2c-.55 0-1 .45-1 1s.45 1 1 1zM11 2v2c0 .55.45 1 1 1s1-.45 1-1V2c0-.55-.45-1-1-1s-1 .45-1 1zm0 18v2c0 .55.45 1 1 1s1-.45 1-1v-2c0-.55-.45-1-1-1s-1 .45-1 1zM5.99 4.58c-.39-.39-1.03-.39-1.41 0-.39.39-.39 1.03 0 1.41l1.06 1.06c.39.39 1.03.39 1.41 0 .38-.39.38-1.03 0-1.41L5.99 4.58zm12.37 12.37c-.39-.39-1.03-.39-1.41 0-.39.39-.39 1.03 0 1.41l1.06 1.06c.39.39 1.03.39 1.41 0 .39-.38.39-1.02 0-1.41l-1.06-1.06zm1.06-12.37l-1.06 1.06c-.39.39-.39 1.03 0 1.41.39.39 1.03.39 1.41 0l1.06-1.06c.39-.39.39-1.03 0-1.41s-1.03-.39-1.41 0zM7.05 18.36l-1.06 1.06c-.39.39-.39 1.03 0 1.41.39.39 1.03.39 1.41 0l1.06-1.06c.39-.39.39-1.03 0-1.41-.38-.39-1.02-.39-1.41 0z"/></svg>
              : <svg viewBox="0 0 24 24" fill="currentColor" width="16" height="16"><path d="M12 3c-4.97 0-9 4.03-9 9s4.03 9 9 9 9-4.03 9-9c0-.46-.04-.92-.1-1.36-.98 1.37-2.58 2.26-4.4 2.26-2.98 0-5.4-2.42-5.4-5.4 0-1.81.89-3.42 2.26-4.4-.44-.06-.9-.1-1.36-.1z"/></svg>
            }
            {!collapsed && (
              <span style={{ fontSize:'0.82rem' }}>
                {isDark ? 'Light mode' : 'Dark mode'}
              </span>
            )}
          </button>

          {/* Logout */}
          <button
            onClick={handleLogout}
            title="Sign out"
            style={{
              width:'100%', padding: collapsed ? '0.6rem' : '0.55rem 1.4rem',
              background:'transparent', border:'none', cursor:'pointer',
              display:'flex', alignItems:'center', gap:10,
              justifyContent: collapsed ? 'center' : 'flex-start',
              color: 'var(--text-muted)', transition:'color 0.15s, background 0.15s',
            }}
            onMouseEnter={e => { e.currentTarget.style.background = 'rgba(252,129,129,0.08)'; e.currentTarget.style.color = '#fc8181' }}
            onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = 'var(--text-muted)' }}
          >
            <svg viewBox="0 0 24 24" fill="currentColor" width="16" height="16">
              <path d="M17 7l-1.41 1.41L18.17 11H8v2h10.17l-2.58 2.58L17 17l5-5zM4 5h8V3H4c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h8v-2H4V5z"/>
            </svg>
            {!collapsed && <span style={{ fontSize:'0.82rem' }}>Sign out</span>}
          </button>

          {/* Collapse toggle */}
          <button onClick={() => setCollapsed(c => !c)}
            style={{
              width:'100%', padding:'0.65rem',
              background:'transparent', color:'var(--text-muted)',
              display:'flex', justifyContent:'center', alignItems:'center',
              transition:'color 0.15s, background 0.15s',
              cursor:'pointer', border:'none',
            }}
            onMouseEnter={e => { e.currentTarget.style.color='var(--text-primary)'; e.currentTarget.style.background='var(--bg-elevated)'; }}
            onMouseLeave={e => { e.currentTarget.style.color='var(--text-muted)'; e.currentTarget.style.background='transparent'; }}
          >
            {collapsed
              ? <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} width={16} height={16}><polyline points="9 18 15 12 9 6"/></svg>
              : <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} width={16} height={16}><polyline points="15 18 9 12 15 6"/></svg>
            }
          </button>
        </div>
      </aside>

      {/* Main */}
      <main style={{
        flex:1, marginLeft:W,
        transition:'margin-left 0.22s cubic-bezier(.4,0,.2,1)',
        minHeight:'100vh', display:'flex', flexDirection:'column',
        background: 'var(--bg-base)',
      }}>
        {/* Topbar */}
        <header style={{
          height:58, borderBottom:'1px solid var(--border)',
          display:'flex', alignItems:'center', justifyContent:'space-between',
          padding:'0 2rem',
          background: isDark ? 'rgba(11,20,55,0.85)' : 'rgba(255,255,255,0.9)',
          backdropFilter:'blur(20px)', WebkitBackdropFilter:'blur(20px)',
          position:'sticky', top:0, zIndex:100,
        }}>
          <div style={{ display:'flex', alignItems:'center', gap:8 }}>
            <span style={{ color:'var(--text-muted)', fontSize:'0.75rem' }}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} width={13} height={13}><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>
            </span>
            <span style={{ color:'var(--text-muted)', fontSize:'0.78rem' }}>/</span>
            <span style={{ fontSize:'0.83rem', fontWeight:500, color:'var(--text-secondary)' }}>
              {getPageLabel(location.pathname)}
            </span>
          </div>
          <div style={{ display:'flex', alignItems:'center', gap:8 }}>
            <div style={{
              width:7, height:7, borderRadius:'50%', background:'#68d391',
              boxShadow:'0 0 8px rgba(104,211,145,0.5)',
            }}/>
            <span style={{ fontSize:'0.7rem', color:'var(--text-muted)', fontFamily:'var(--font-mono)', letterSpacing:'0.06em' }}>
              LIVE
            </span>
          </div>
        </header>

        {/* Content */}
        <div style={{ flex:1, padding:'1.75rem 2rem', maxWidth:1400, width:'100%', margin:'0 auto' }}>
          <Outlet />
        </div>
      </main>

      <Toaster position="top-right" toastOptions={{
        style:{
          background: isDark ? 'rgba(17,28,68,0.97)' : 'rgba(255,255,255,0.97)',
          backdropFilter:'blur(20px)',
          color: isDark ? '#fff' : '#1a202c',
          border:'1px solid var(--border)',
          borderRadius:12, fontSize:'0.84rem',
          boxShadow:'0 8px 25px rgba(0,0,0,0.15)',
        },
        success:{ iconTheme:{ primary:'#68d391', secondary: isDark ? '#0b1437' : '#fff' } },
        error:  { iconTheme:{ primary:'#fc8181', secondary: isDark ? '#0b1437' : '#fff' } },
      }}/>
    </div>
  )
}

function getPageLabel(path) {
  if (path.startsWith('/dashboard'))  return 'Dashboard'
  if (path.startsWith('/findings/'))  return 'Finding detail'
  if (path.startsWith('/findings'))   return 'Findings'
  if (path.startsWith('/projects/'))  return 'Project detail'
  if (path.startsWith('/projects'))   return 'Projects'
  if (path.startsWith('/rules'))      return 'Rules'
  if (path.startsWith('/docs'))       return 'API Docs'
  if (path.startsWith('/debug'))      return 'Debug'
  if (path.startsWith('/settings'))   return 'Settings'
  return 'W3GathrVulns'
}

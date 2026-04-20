import React, { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, Legend,
} from 'recharts'
import { fetchDashboard, fetchProjects } from '../api/client.js'
import { format, parseISO } from 'date-fns'

// ── Custom dot for area chart ─────────────────────────────────────────────────
const GlowDot = (props) => {
  const { cx, cy, payload } = props
  if (!payload?.count) return null
  return (
    <g>
      <circle cx={cx} cy={cy} r={5} fill="#4299e1" opacity={0.25}/>
      <circle cx={cx} cy={cy} r={3} fill="#4299e1" stroke="#fff" strokeWidth={1.5}/>
    </g>
  )
}

// ── Palette ───────────────────────────────────────────────────────────────────
const SEV_COLORS = {
  CRITICAL: '#fc8181', HIGH: '#f6ad55', MEDIUM: '#f6e05e',
  LOW: '#68d391', INFO: '#63b3ed', UNKNOWN: '#a0aec0',
}
const STATUS_COLORS = {
  OPEN:           '#fc8181',
  IN_PROGRESS:    '#f6ad55',
  CLOSED:         '#68d391',
  ACCEPTED_RISK:  '#b794f4',
  FALSE_POSITIVE: '#718096',
}
const SOURCE_COLORS = ['#63b3ed','#fc8181','#f6ad55','#f6e05e','#68d391','#b794f4','#f687b3']

const SEVERITIES = ['CRITICAL','HIGH','MEDIUM','LOW','INFO']
const STATUSES   = ['OPEN','IN_PROGRESS','CLOSED','ACCEPTED_RISK','FALSE_POSITIVE']
const SOURCES    = ['trivy','gitlab_sast','gitlab_iac','gitlab_secrets','owasp_zap','nuclei']

// ── Theme hook ────────────────────────────────────────────────────────────────
function useTheme() {
  const [isDark, setIsDark] = useState(
    () => document.documentElement.dataset.theme !== 'light'
  )
  useEffect(() => {
    const obs = new MutationObserver(
      () => setIsDark(document.documentElement.dataset.theme !== 'light')
    )
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
    return () => obs.disconnect()
  }, [])
  return isDark
}

// ── Tooltip ───────────────────────────────────────────────────────────────────
const ChartTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: 'var(--bg-surface)',
      backdropFilter: 'blur(20px)',
      border: '1px solid var(--border-light)',
      borderRadius: 10,
      padding: '9px 13px',
      boxShadow: '0 8px 25px rgba(0,0,0,0.25)',
    }}>
      {label && <p style={{ fontSize:'0.7rem', color:'var(--text-muted)', marginBottom:5 }}>{label}</p>}
      {payload.map((p, i) => (
        <p key={i} style={{ fontSize:'0.82rem', color: p.color || 'var(--text-primary)' }}>
          {p.name}: <strong>{typeof p.value === 'number' ? p.value.toLocaleString() : p.value}</strong>
        </p>
      ))}
    </div>
  )
}

// ── Chip ──────────────────────────────────────────────────────────────────────
function Chip({ label, color = 'var(--accent)', active, onClick }) {
  return (
    <button onClick={onClick} style={{
      display:'inline-flex', alignItems:'center', gap:4,
      padding:'3px 10px', borderRadius:20, cursor:'pointer',
      fontSize:'0.72rem', fontWeight:600, whiteSpace:'nowrap',
      border: `1px solid ${active ? color : 'var(--border)'}`,
      background: active ? `${color}22` : 'transparent',
      color: active ? color : 'var(--text-muted)',
      transition:'all 0.15s',
    }}>
      {active && <span style={{ fontSize:'0.6rem' }}>✓</span>}
      {label}
    </button>
  )
}

// ── Section title ─────────────────────────────────────────────────────────────
function SectionTitle({ children }) {
  return (
    <p style={{
      fontSize:'0.68rem', fontWeight:700, color:'var(--text-muted)',
      textTransform:'uppercase', letterSpacing:'0.12em', marginBottom:'0.9rem',
    }}>
      {children}
    </p>
  )
}

// ── Row label ─────────────────────────────────────────────────────────────────
function RowLabel({ children }) {
  return (
    <span style={{
      fontSize:'0.63rem', color:'var(--text-muted)', fontWeight:700,
      textTransform:'uppercase', letterSpacing:'0.06em', alignSelf:'center',
      marginRight:2, whiteSpace:'nowrap',
    }}>
      {children}
    </span>
  )
}

// ── KPI card ──────────────────────────────────────────────────────────────────
function KpiCard({ label, value, color, gradient, sub, pulse, onClick }) {
  return (
    <div className="card" onClick={onClick} style={{
      position:'relative', overflow:'hidden', padding:'1.1rem 1.2rem',
      cursor: onClick ? 'pointer' : 'default',
      transition: onClick ? 'transform 0.12s, box-shadow 0.12s' : undefined,
    }}
    onMouseEnter={e => { if (onClick) e.currentTarget.style.transform = 'translateY(-2px)' }}
    onMouseLeave={e => { if (onClick) e.currentTarget.style.transform = 'translateY(0)' }}
    >
      {pulse && (
        <div style={{
          position:'absolute', top:10, right:10, width:7, height:7,
          borderRadius:'50%', background:color, animation:'pulse-glow 1.5s infinite',
        }}/>
      )}
      <div style={{
        position:'absolute', top:-18, right:-18, width:70, height:70,
        borderRadius:'50%', background:gradient, filter:'blur(26px)', opacity:0.2,
      }}/>
      <div style={{ fontSize:'0.63rem', fontWeight:700, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.1em', marginBottom:8 }}>
        {label}
      </div>
      <div style={{ fontSize:'1.75rem', fontWeight:700, color, fontFamily:'var(--font-mono)', lineHeight:1, letterSpacing:'-0.02em' }}>
        {typeof value === 'string' ? value : (value?.toLocaleString() ?? 0)}
      </div>
      {sub !== undefined && (
        <div style={{ fontSize:'0.68rem', color:'var(--text-muted)', marginTop:5, fontFamily:'var(--font-mono)' }}>
          {sub}
        </div>
      )}
    </div>
  )
}

// ── Project dropdown ──────────────────────────────────────────────────────────
function ProjectSelect({ projects, value, onChange, isDark }) {
  const chevronColor = isDark ? 'rgba(255,255,255,0.35)' : 'rgba(26,32,44,0.5)'
  const svgChevron = `<svg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'><path fill='${chevronColor}' d='M6 8L1 3h10z'/></svg>`
  return (
    <div style={{ display:'flex', alignItems:'center', gap:8 }}>
      <RowLabel>Project</RowLabel>
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        style={{
          background: 'var(--bg-elevated)',
          border: '1px solid var(--border)',
          borderRadius:8, color:'var(--text-secondary)',
          fontSize:'0.78rem', padding:'4px 28px 4px 10px',
          cursor:'pointer', outline:'none',
          appearance:'none', WebkitAppearance:'none',
          backgroundImage: `url("data:image/svg+xml,${encodeURIComponent(svgChevron)}")`,
          backgroundRepeat:'no-repeat',
          backgroundPosition:'right 8px center',
          maxWidth:200,
        }}
      >
        <option value="">All projects</option>
        {projects?.map(p => (
          <option key={p.id} value={p.id}>{p.name}</option>
        ))}
      </select>
    </div>
  )
}

// ── Main ──────────────────────────────────────────────────────────────────────
const FINDINGS_SESSION_KEY = 'w3gathrvulns_findings_state'

export default function Dashboard() {
  const isDark = useTheme()
  const navigate = useNavigate()
  const [selectedProject, setSelectedProject] = useState('')
  const [chipSev,         setChipSev]         = useState(new Set())
  const [chipStatus,      setChipStatus]       = useState(new Set())
  const [chipSource,      setChipSource]       = useState(new Set())

  const toggleChip = (setter, val) => setter(prev => {
    const s = new Set(prev); s.has(val) ? s.delete(val) : s.add(val); return s
  })

  const filterParams = {
    ...(selectedProject              && { project_id: selectedProject }),
    ...(chipSev.size    > 0          && { severity:   [...chipSev] }),
    ...(chipStatus.size > 0          && { status:     [...chipStatus] }),
    ...(chipSource.size > 0          && { source:     [...chipSource] }),
  }
  const hasFilters = selectedProject || chipSev.size || chipStatus.size || chipSource.size

  const { data, isPending, error, refetch, isFetching } = useQuery({
    queryKey: ['dashboard', filterParams],
    queryFn: () => fetchDashboard(filterParams),
    refetchInterval: 60_000,
    placeholderData: prev => prev,
  })

  const { data: projects } = useQuery({ queryKey: ['projects'], queryFn: fetchProjects })

  const navigateToFindings = (patch) => {
    try {
      sessionStorage.setItem(FINDINGS_SESSION_KEY, JSON.stringify({
        page: 1, sortBy: 'first_seen', sortDir: 'desc',
        search: '', filters: [], projectId: selectedProject || '',
        chipSev: [], chipStatus: [], chipSource: [],
        filtersOpen: true,
        ...patch,
      }))
    } catch {}
    navigate('/findings')
  }

  if (error) return <ErrorState />

  const s = data

  // Computed summary values
  const toBeDealt      = s ? (s.open_findings + s.in_progress_count) : 0
  const managed        = s ? (s.closed_count + s.false_positives + s.accepted_risk_count) : 0
  const remediationRate = s && s.total_findings > 0
    ? Math.round((managed / s.total_findings) * 100)
    : 0

  // Theme-aware chart axis colors (SVG attributes — CSS variables don't apply here)
  const tickColor  = isDark ? 'rgba(255,255,255,0.28)' : 'rgba(26,32,44,0.45)'
  const tick2Color = isDark ? 'rgba(255,255,255,0.45)' : 'rgba(26,32,44,0.62)'

  return (
    <div className="animate-in" style={{ display:'flex', flexDirection:'column', gap:'1.5rem' }}>

      {/* ── Header + filters ────────────────────────────────────────────────── */}
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap:16, flexWrap:'wrap' }}>
        <div style={{ display:'flex', alignItems:'flex-start', gap:10 }}>
          <div>
            <h1 style={{ fontSize:'1.55rem', fontWeight:700, letterSpacing:'-0.02em', color:'var(--text-primary)' }}>
              Security Overview
            </h1>
            {s && (
              <p style={{ color:'var(--text-muted)', fontSize:'0.82rem', marginTop:3 }}>
                {s.total_scans} scans · {s.total_projects} projects
                {hasFilters && <span style={{ color:'var(--accent)', marginLeft:8 }}>— filtered</span>}
              </p>
            )}
          </div>
          <button
            onClick={() => refetch()}
            title="Refresh"
            style={{
              marginTop:4, background:'transparent', border:'1px solid var(--border)',
              borderRadius:8, color:'var(--text-muted)', cursor:'pointer',
              padding:'4px 8px', fontSize:'0.95rem', lineHeight:1,
              transition:'all 0.15s',
              animation: isFetching ? 'spin 0.8s linear infinite' : 'none',
            }}
          >⟳</button>
        </div>

        {/* Filter panel */}
        <div style={{ display:'flex', flexDirection:'column', gap:6, alignItems:'flex-end' }}>
          {/* Project dropdown */}
          <ProjectSelect projects={projects} value={selectedProject} onChange={setSelectedProject} isDark={isDark} />
          {/* Severity chips */}
          <div style={{ display:'flex', gap:4, flexWrap:'wrap', justifyContent:'flex-end' }}>
            <RowLabel>Sev</RowLabel>
            {SEVERITIES.map(v => (
              <Chip key={v} label={v} color={SEV_COLORS[v]}
                active={chipSev.has(v)} onClick={() => toggleChip(setChipSev, v)} />
            ))}
          </div>
          {/* Status chips */}
          <div style={{ display:'flex', gap:4, flexWrap:'wrap', justifyContent:'flex-end' }}>
            <RowLabel>Status</RowLabel>
            {STATUSES.map(v => (
              <Chip key={v} label={v.replace(/_/g,' ')} color={STATUS_COLORS[v]}
                active={chipStatus.has(v)} onClick={() => toggleChip(setChipStatus, v)} />
            ))}
          </div>
          {/* Source chips */}
          <div style={{ display:'flex', gap:4, flexWrap:'wrap', justifyContent:'flex-end' }}>
            <RowLabel>Source</RowLabel>
            {SOURCES.map((v, i) => (
              <Chip key={v} label={v} color={SOURCE_COLORS[i % SOURCE_COLORS.length]}
                active={chipSource.has(v)} onClick={() => toggleChip(setChipSource, v)} />
            ))}
          </div>
          {hasFilters && (
            <button className="btn btn-ghost" style={{ fontSize:'0.72rem', padding:'2px 10px', alignSelf:'flex-end' }}
              onClick={() => { setSelectedProject(''); setChipSev(new Set()); setChipStatus(new Set()); setChipSource(new Set()) }}>
              ✕ Clear filters
            </button>
          )}
        </div>
      </div>

      {isPending && !s ? (
        <LoadingState />
      ) : (
        <>
          {/* ── Line 1: Summary KPIs ──────────────────────────────────────── */}
          <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit,minmax(150px,1fr))', gap:'0.9rem' }}>
            <KpiCard
              label="Total Findings"
              value={s.total_findings}
              color="var(--text-secondary)"
              gradient="linear-gradient(310deg,#627594,#a8b8d8)"
            />
            <KpiCard
              label="To Be Dealt With"
              value={toBeDealt}
              color="#4299e1"
              gradient="linear-gradient(310deg,#2152ff,#21d4fd)"
              sub="open + in progress"
              pulse={toBeDealt > 0}
            />
            <KpiCard
              label="Managed"
              value={managed}
              color="#68d391"
              gradient="linear-gradient(310deg,#17ad37,#98ec2d)"
              sub="closed + fp + accepted"
            />
            <KpiCard
              label="New This Week"
              value={s.new_this_week}
              color="#63b3ed"
              gradient="linear-gradient(310deg,#2152ff,#21d4fd)"
            />
            <KpiCard
              label="Remediation Rate"
              value={`${remediationRate}%`}
              color={remediationRate >= 70 ? '#68d391' : remediationRate >= 40 ? '#f6ad55' : '#fc8181'}
              gradient="linear-gradient(310deg,#17ad37,#98ec2d)"
              sub={`${managed.toLocaleString()} resolved`}
            />
          </div>

          {/* ── Line 2: Status detail ─────────────────────────────────────── */}
          <div>
            <SectionTitle>Status Breakdown</SectionTitle>
            <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit,minmax(120px,1fr))', gap:'0.9rem' }}>
              <KpiCard label="Open"           value={s.open_findings}       color={STATUS_COLORS.OPEN}           gradient="linear-gradient(310deg,#f5365c,#f56036)" pulse={s.open_findings > 0}  onClick={() => navigateToFindings({ chipStatus: ['OPEN'] })} />
              <KpiCard label="In Progress"    value={s.in_progress_count}   color={STATUS_COLORS.IN_PROGRESS}    gradient="linear-gradient(310deg,#f77f00,#ffd60a)"                              onClick={() => navigateToFindings({ chipStatus: ['IN_PROGRESS'] })} />
              <KpiCard label="Closed"         value={s.closed_count}        color={STATUS_COLORS.CLOSED}         gradient="linear-gradient(310deg,#17ad37,#98ec2d)"                              onClick={() => navigateToFindings({ chipStatus: ['CLOSED'] })} />
              <KpiCard label="Accepted Risk"  value={s.accepted_risk_count} color={STATUS_COLORS.ACCEPTED_RISK}  gradient="linear-gradient(310deg,#7928ca,#ff0080)"                              onClick={() => navigateToFindings({ chipStatus: ['ACCEPTED_RISK'] })} />
              <KpiCard label="False Positive" value={s.false_positives}     color={STATUS_COLORS.FALSE_POSITIVE} gradient="linear-gradient(310deg,#627594,#a8b8d8)"                              onClick={() => navigateToFindings({ chipStatus: ['FALSE_POSITIVE'] })} />
            </div>
          </div>

          {/* ── Line 3: Open by severity ──────────────────────────────────── */}
          <div>
            <SectionTitle>Open Findings by Severity</SectionTitle>
            <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit,minmax(120px,1fr))', gap:'0.9rem' }}>
              <KpiCard label="Critical" value={s.critical_count} color={SEV_COLORS.CRITICAL} gradient="linear-gradient(310deg,#f5365c,#f56036)" pulse={s.critical_count > 0} onClick={() => navigateToFindings({ chipSev: ['CRITICAL'], chipStatus: ['OPEN'] })} />
              <KpiCard label="High"     value={s.high_count}     color={SEV_COLORS.HIGH}     gradient="linear-gradient(310deg,#f77f00,#ffd60a)"                              onClick={() => navigateToFindings({ chipSev: ['HIGH'],     chipStatus: ['OPEN'] })} />
              <KpiCard label="Medium"   value={s.medium_count}   color={SEV_COLORS.MEDIUM}   gradient="linear-gradient(310deg,#f7971e,#ffd200)"                              onClick={() => navigateToFindings({ chipSev: ['MEDIUM'],   chipStatus: ['OPEN'] })} />
              <KpiCard label="Low"      value={s.low_count}      color={SEV_COLORS.LOW}      gradient="linear-gradient(310deg,#17ad37,#98ec2d)"                              onClick={() => navigateToFindings({ chipSev: ['LOW'],      chipStatus: ['OPEN'] })} />
            </div>
          </div>

          {/* ── Trend (full width) ────────────────────────────────────────── */}
          <div className="card">
            <SectionTitle>New Findings — 30 Days</SectionTitle>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={s.recent_trend} margin={{ top:10, right:10, left:0, bottom:0 }}>
                <defs>
                  <linearGradient id="gradBlue" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%"   stopColor="#4299e1" stopOpacity={0.45}/>
                    <stop offset="60%"  stopColor="#4299e1" stopOpacity={0.12}/>
                    <stop offset="100%" stopColor="#4299e1" stopOpacity={0}/>
                  </linearGradient>
                  <filter id="glow">
                    <feGaussianBlur stdDeviation="3" result="blur"/>
                    <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                  </filter>
                </defs>
                <XAxis dataKey="date"
                  tickFormatter={d => { try { return format(parseISO(d),'dd/MM') } catch { return d } }}
                  tick={{ fill: tickColor, fontSize:10, fontFamily:'var(--font-mono)' }}
                  axisLine={false} tickLine={false} interval="preserveStartEnd"/>
                <YAxis tick={{ fill: tickColor, fontSize:10 }} axisLine={false} tickLine={false} width={28}/>
                <Tooltip content={<ChartTooltip />}/>
                <Area
                  type="monotone" dataKey="count" name="Findings"
                  stroke="#4299e1" strokeWidth={2.5}
                  fill="url(#gradBlue)"
                  dot={<GlowDot />} activeDot={{ r:5, fill:'#4299e1', stroke:'#fff', strokeWidth:2 }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* ── Status donut + Severity donut ─────────────────────────────── */}
          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:'1.1rem' }}>
            <div className="card">
              <SectionTitle>Status Breakdown</SectionTitle>
              {s.by_status.length === 0 ? <NoData /> : (
                <ResponsiveContainer width="100%" height={230}>
                  <PieChart>
                    <defs>
                      {s.by_status.map((e, i) => {
                        const c = STATUS_COLORS[e.status] || '#718096'
                        return (
                          <radialGradient key={i} id={`sg-status-${i}`} cx="50%" cy="30%" r="70%">
                            <stop offset="0%" stopColor={c} stopOpacity={1}/>
                            <stop offset="100%" stopColor={c} stopOpacity={0.65}/>
                          </radialGradient>
                        )
                      })}
                    </defs>
                    <Pie data={s.by_status} dataKey="count" nameKey="status" cx="50%" cy="48%" outerRadius={82} innerRadius={46} paddingAngle={4} strokeWidth={0}>
                      {s.by_status.map((e, i) => (
                        <Cell key={i} fill={`url(#sg-status-${i})`}/>
                      ))}
                    </Pie>
                    <Tooltip content={<ChartTooltip />}/>
                    <Legend iconType="circle" iconSize={8} formatter={v => <span style={{ fontSize:'0.7rem', color:'var(--text-secondary)' }}>{v.replace(/_/g,' ')}</span>}/>
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>

            <div className="card">
              <SectionTitle>Severity Breakdown</SectionTitle>
              {s.by_severity.length === 0 ? <NoData /> : (
                <ResponsiveContainer width="100%" height={230}>
                  <PieChart>
                    <defs>
                      {s.by_severity.map((e, i) => {
                        const c = SEV_COLORS[e.severity] || '#a0aec0'
                        return (
                          <radialGradient key={i} id={`sg-sev-${i}`} cx="50%" cy="30%" r="70%">
                            <stop offset="0%" stopColor={c} stopOpacity={1}/>
                            <stop offset="100%" stopColor={c} stopOpacity={0.65}/>
                          </radialGradient>
                        )
                      })}
                    </defs>
                    <Pie data={s.by_severity} dataKey="count" nameKey="severity" cx="50%" cy="48%" outerRadius={82} innerRadius={46} paddingAngle={4} strokeWidth={0}>
                      {s.by_severity.map((e, i) => (
                        <Cell key={i} fill={`url(#sg-sev-${i})`}/>
                      ))}
                    </Pie>
                    <Tooltip content={<ChartTooltip />}/>
                    <Legend iconType="circle" iconSize={8} formatter={v => <span style={{ fontSize:'0.7rem', color: SEV_COLORS[v] || 'var(--text-secondary)' }}>{v}</span>}/>
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          {/* ── Severity × Project stacked bar (full width) ───────────────── */}
          {s.by_severity_project.length > 0 && (
            <div className="card">
              <SectionTitle>Open Findings by Severity × Project</SectionTitle>
              <ResponsiveContainer width="100%" height={230}>
                <BarChart data={s.by_severity_project} margin={{ left:0, right:10, top:8 }} barCategoryGap="35%">
                  <XAxis dataKey="project"
                    tick={{ fill: tick2Color, fontSize:10, fontFamily:'var(--font-mono)' }}
                    axisLine={false} tickLine={false}
                    tickFormatter={v => v.length > 14 ? v.slice(0,14)+'…' : v}
                  />
                  <YAxis tick={{ fill: tickColor, fontSize:10 }} axisLine={false} tickLine={false} width={28}/>
                  <Tooltip content={<ChartTooltip />} cursor={{ fill:'var(--bg-overlay)', radius:6 }}/>
                  <Legend iconType="circle" iconSize={8} formatter={v => <span style={{ fontSize:'0.7rem', color: SEV_COLORS[v] || 'var(--text-secondary)' }}>{v}</span>}/>
                  <Bar dataKey="CRITICAL" name="CRITICAL" stackId="a" fill={SEV_COLORS.CRITICAL}/>
                  <Bar dataKey="HIGH"     name="HIGH"     stackId="a" fill={SEV_COLORS.HIGH}/>
                  <Bar dataKey="MEDIUM"   name="MEDIUM"   stackId="a" fill={SEV_COLORS.MEDIUM}/>
                  <Bar dataKey="LOW"      name="LOW"      stackId="a" fill={SEV_COLORS.LOW} radius={[5,5,0,0]}/>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* ── Findings by Tool + Top Projects ───────────────────────────── */}
          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:'1.1rem' }}>
            <div className="card">
              <SectionTitle>Findings by Tool</SectionTitle>
              {s.by_source.length === 0 ? <NoData /> : (
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={s.by_source} layout="vertical" margin={{ left:10, top:4 }} barCategoryGap="30%">
                    <XAxis type="number" tick={{ fill: tickColor, fontSize:10 }} axisLine={false} tickLine={false}/>
                    <YAxis dataKey="source" type="category"
                      tick={{ fill: tick2Color, fontSize:10, fontFamily:'var(--font-mono)' }}
                      axisLine={false} tickLine={false} width={90}/>
                    <Tooltip content={<ChartTooltip />} cursor={{ fill:'var(--bg-overlay)', radius:4 }}/>
                    <Bar dataKey="count" name="Findings" radius={[0,7,7,0]}>
                      {s.by_source.map((_, i) => <Cell key={i} fill={SOURCE_COLORS[i % SOURCE_COLORS.length]}/>)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>

            <div className="card">
              <SectionTitle>Top Projects — Open Findings</SectionTitle>
              {s.top_projects.length === 0 ? <NoData /> : (
                <div style={{ display:'flex', flexDirection:'column', gap:11 }}>
                  {s.top_projects.map((p, i) => (
                    <div key={p.id} style={{ display:'flex', alignItems:'center', gap:10 }}>
                      <span style={{ width:18, fontSize:'0.67rem', color:'var(--text-muted)', fontFamily:'var(--font-mono)' }}>#{i+1}</span>
                      <div style={{ flex:1 }}>
                        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:4 }}>
                          <span style={{ fontSize:'0.81rem', fontWeight:500, color:'var(--text-secondary)' }}>{p.name}</span>
                          <span style={{ fontSize:'0.73rem', color:'#fc8181', fontFamily:'var(--font-mono)', fontWeight:700 }}>{p.open_findings}</span>
                        </div>
                        <div style={{ height:3, background:'var(--bg-overlay)', borderRadius:4, overflow:'hidden' }}>
                          <div style={{
                            height:'100%', borderRadius:4,
                            width:`${Math.min(100,(p.open_findings/(s.top_projects[0]?.open_findings||1))*100)}%`,
                            background:'linear-gradient(90deg,#4299e1,#fc8181)',
                            transition:'width 0.5s ease',
                          }}/>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  )
}

function NoData() {
  return <p style={{ color:'var(--text-muted)', fontSize:'0.82rem', textAlign:'center', padding:'2rem 0' }}>No data</p>
}

function LoadingState() {
  return (
    <div style={{ display:'flex', flexDirection:'column', gap:'1.5rem' }}>
      <div style={{ display:'grid', gridTemplateColumns:'repeat(5,1fr)', gap:'0.9rem' }}>
        {[...Array(5)].map((_,i) => <div key={i} style={{ height:88, background:'var(--bg-elevated)', borderRadius:18 }}/>)}
      </div>
      <div style={{ display:'grid', gridTemplateColumns:'repeat(5,1fr)', gap:'0.9rem' }}>
        {[...Array(5)].map((_,i) => <div key={i} style={{ height:80, background:'var(--bg-elevated)', borderRadius:18 }}/>)}
      </div>
      <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:'0.9rem' }}>
        {[...Array(4)].map((_,i) => <div key={i} style={{ height:80, background:'var(--bg-elevated)', borderRadius:18 }}/>)}
      </div>
      <div style={{ height:200, background:'var(--bg-elevated)', borderRadius:18 }}/>
      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:'1.1rem' }}>
        {[...Array(2)].map((_,i) => <div key={i} style={{ height:220, background:'var(--bg-elevated)', borderRadius:18 }}/>)}
      </div>
    </div>
  )
}

function ErrorState() {
  return (
    <div className="card" style={{ textAlign:'center', padding:'4rem', color:'#fc8181' }}>
      <div style={{ fontSize:'2.5rem', marginBottom:12 }}>!</div>
      <p style={{ fontWeight:600 }}>Failed to load dashboard</p>
      <p style={{ fontSize:'0.83rem', color:'var(--text-muted)', marginTop:6 }}>Is the API running?</p>
    </div>
  )
}

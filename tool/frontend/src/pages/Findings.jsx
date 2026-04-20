import React, { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { fetchFindings, fetchProjects, batchUpdateFindings, deleteFinding, exportFile } from '../api/client.js'
import { format } from 'date-fns'
import toast from 'react-hot-toast'

// ── Constants ──────────────────────────────────────────────────────────────────
const FILTER_FIELDS = [
  { value: 'title',       label: 'Title' },
  { value: 'source',      label: 'Source' },
  { value: 'severity',    label: 'Severity' },
  { value: 'status',      label: 'Status' },
  { value: 'file_path',   label: 'File path' },
  { value: 'component',   label: 'Component' },
  { value: 'vuln_id',     label: 'Identifier' },
  { value: 'cve',         label: 'CVE' },
  { value: 'description', label: 'Description' },
  { value: 'project',     label: 'Project name' },
]
const OPERATORS = [
  { value: 'contains',     label: 'contains' },
  { value: 'not_contains', label: 'does not contain' },
  { value: 'equals',       label: 'equals' },
  { value: 'not_equals',   label: 'not equals' },
  { value: 'starts_with',  label: 'starts with' },
  { value: 'ends_with',    label: 'ends with' },
  { value: 'in',           label: 'is one of (comma-sep)' },
]
const SORTABLE_COLS = [
  { key: 'short_id',   label: '#' },
  { key: 'severity',   label: 'Severity' },
  { key: 'title',      label: 'Title' },
  { key: 'source',     label: 'Source' },
  { key: 'status',     label: 'Status' },
  { key: 'first_seen', label: 'First seen' },
  { key: 'last_seen',  label: 'Last seen' },
]
const STATUSES   = ['OPEN','IN_PROGRESS','CLOSED','ACCEPTED_RISK','FALSE_POSITIVE']
const SEVERITIES = ['CRITICAL','HIGH','MEDIUM','LOW','INFO','UNKNOWN']
const SOURCES    = ['trivy','gitlab_sast','gitlab_iac','gitlab_secrets','owasp_zap','nuclei']

const SEV_COLORS = {
  CRITICAL: '#e53e3e',
  HIGH:     '#dd6b20',
  MEDIUM:   '#d69e2e',
  LOW:      '#38a169',
  INFO:     '#3182ce',
  UNKNOWN:  '#718096',
}
const STATUS_COLORS = {
  OPEN:            '#e53e3e',
  IN_PROGRESS:     '#d69e2e',
  CLOSED:          '#38a169',
  ACCEPTED_RISK:   '#805ad5',
  FALSE_POSITIVE:  '#718096',
}
const SOURCE_COLORS = {
  trivy:           '#3182ce',
  gitlab_sast:     '#e53e3e',
  gitlab_iac:      '#dd6b20',
  gitlab_secrets:  '#805ad5',
  owasp_zap:       '#38a169',
  nuclei:          '#d69e2e',
}

const SESSION_KEY = 'w3gathrvulns_findings_state'

let filterIdCounter = 100
let groupIdCounter  = 0
const newFilter = (groupId = 0) => ({ _id: ++filterIdCounter, groupId, field: 'title', op: 'contains', value: '' })
const newGroupId = () => ++groupIdCounter

// ── Session state helpers ─────────────────────────────────────────────────────
function loadSession() {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY)
    if (raw) return JSON.parse(raw)
  } catch {}
  return null
}
function saveSession(state) {
  try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(state)) } catch {}
}

// ── Chip button ───────────────────────────────────────────────────────────────
function Chip({ label, color, active, onClick }) {
  return (
    <button
      onClick={onClick}
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 4,
        padding: '3px 10px', borderRadius: 20,
        fontSize: '0.75rem', fontWeight: 600, cursor: 'pointer',
        border: `1px solid ${active ? color : 'var(--border)'}`,
        background: active ? `${color}22` : 'transparent',
        color: active ? color : 'var(--text-muted)',
        transition: 'all 0.15s',
        whiteSpace: 'nowrap',
      }}
    >
      {active && <span style={{ fontSize: '0.65rem' }}>✓</span>}
      {label}
    </button>
  )
}

// ── Main ──────────────────────────────────────────────────────────────────────
export default function Findings() {
  const qc = useQueryClient()

  // Restore from session
  const saved = loadSession()

  const [page, setPage]       = useState(saved?.page     || 1)
  const [sortBy, setSortBy]   = useState(saved?.sortBy   || 'first_seen')
  const [sortDir, setSortDir] = useState(saved?.sortDir  || 'desc')
  const [search, setSearch]   = useState(saved?.search   || '')
  const [filters, setFilters] = useState(saved?.filters  || [])
  const [projectId, setProjectId] = useState(saved?.projectId || '')

  // Quick-filter chips (Sets of active values)
  const [chipSev,    setChipSev]    = useState(() => new Set(saved?.chipSev    || []))
  const [chipStatus, setChipStatus] = useState(() => new Set(saved?.chipStatus || []))
  const [chipSource, setChipSource] = useState(() => new Set(saved?.chipSource || []))

  const [filtersOpen, setFiltersOpen] = useState(saved?.filtersOpen !== false)

  const [selected, setSelected]       = useState(new Set())
  const [batchStatus, setBatchStatus] = useState('')

  // Persist to session on every state change
  useEffect(() => {
    saveSession({
      page, sortBy, sortDir, search, filters, projectId,
      chipSev:    [...chipSev],
      chipStatus: [...chipStatus],
      chipSource: [...chipSource],
      filtersOpen,
    })
  }, [page, sortBy, sortDir, search, filters, projectId, chipSev, chipStatus, chipSource, filtersOpen])

  // ── Build grouped filters JSON for API ───────────────────────────────────────
  const activeFilters = filters.filter(f => f.value.trim())

  function buildFiltersParam() {
    // Chip selections → groups (each group is a single OR-group)
    const groups = []

    if (chipSev.size > 0) {
      groups.push({ mode: 'or', conditions: [...chipSev].map(v => ({ field: 'severity', op: 'equals', value: v })) })
    }
    if (chipStatus.size > 0) {
      groups.push({ mode: 'or', conditions: [...chipStatus].map(v => ({ field: 'status', op: 'equals', value: v })) })
    }
    if (chipSource.size > 0) {
      groups.push({ mode: 'or', conditions: [...chipSource].map(v => ({ field: 'source', op: 'equals', value: v })) })
    }

    // Advanced filters — group by groupId, OR within group, AND between groups
    const byGroup = {}
    for (const f of activeFilters) {
      const gid = f.groupId ?? 0
      if (!byGroup[gid]) byGroup[gid] = []
      byGroup[gid].push({ field: f.field, op: f.op, value: f.value })
    }
    for (const conditions of Object.values(byGroup)) {
      groups.push({ mode: 'or', conditions })
    }

    if (groups.length === 0) return undefined
    return JSON.stringify({ groups })
  }

  const filtersParam = buildFiltersParam()

  const params = {
    page, page_size: 25,
    sort_by: sortBy, sort_dir: sortDir,
    ...(search      && { search }),
    ...(projectId   && { project_id: projectId }),
    ...(filtersParam && { filters: filtersParam }),
  }

  const { data, isPending, refetch, isFetching } = useQuery({
    queryKey: ['findings', params],
    queryFn: () => fetchFindings(params),
    placeholderData: prev => prev,
  })
  const { data: projects } = useQuery({ queryKey: ['projects'], queryFn: fetchProjects })

  // ── Batch actions ────────────────────────────────────────────────────────────
  const batchMutation = useMutation({
    mutationFn: batchUpdateFindings,
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['findings'] })
      setSelected(new Set()); setBatchStatus('')
      toast.success(`${res.updated} finding(s) updated`)
    },
    onError: () => toast.error('Batch update failed'),
  })

  const [confirmDelete, setConfirmDelete] = useState(false)
  const batchDeleteMutation = useMutation({
    mutationFn: async (ids) => {
      let deleted = 0
      for (const id of ids) { await deleteFinding(id); deleted++ }
      return deleted
    },
    onSuccess: (n) => {
      qc.invalidateQueries({ queryKey: ['findings'] })
      setSelected(new Set()); setConfirmDelete(false)
      toast.success(`${n} finding(s) deleted`)
    },
    onError: () => toast.error('Delete failed'),
  })

  // ── Sort ─────────────────────────────────────────────────────────────────────
  const toggleSort = (col) => {
    if (sortBy === col) setSortDir(d => d === 'desc' ? 'asc' : 'desc')
    else { setSortBy(col); setSortDir('desc') }
    setPage(1)
  }

  // ── Chip toggles ─────────────────────────────────────────────────────────────
  const toggleChip = (setter, val) => {
    setter(prev => {
      const s = new Set(prev)
      s.has(val) ? s.delete(val) : s.add(val)
      return s
    })
    setPage(1)
  }

  // ── Advanced filters ─────────────────────────────────────────────────────────
  // Get distinct groupIds in insertion order
  const groupIds = [...new Set(filters.map(f => f.groupId ?? 0))]

  const addFilterToGroup = (groupId) => {
    setFilters(f => [...f, newFilter(groupId)])
  }
  const addGroup = () => {
    const gid = newGroupId()
    setFilters(f => [...f, newFilter(gid)])
  }
  const removeFilter = (id) => setFilters(f => f.filter(x => x._id !== id))
  const removeGroup  = (groupId) => setFilters(f => f.filter(x => (x.groupId ?? 0) !== groupId))
  const updateFilter = (id, key, val) => {
    setFilters(f => f.map(x => x._id === id ? { ...x, [key]: val } : x))
    setPage(1)
  }

  // ── Selection ────────────────────────────────────────────────────────────────
  const allPageIds  = data?.items?.map(f => f.id) || []
  const allSelected = allPageIds.length > 0 && allPageIds.every(id => selected.has(id))
  const someSelected = selected.size > 0
  const toggleAll   = () => setSelected(allSelected ? new Set() : new Set(allPageIds))
  const toggleOne   = (id) => setSelected(prev => {
    const s = new Set(prev); s.has(id) ? s.delete(id) : s.add(id); return s
  })

  // ── Export ────────────────────────────────────────────────────────────────────
  const getExportParams = () => {
    const p = {}
    if (projectId)    p.project_id = projectId
    if (filtersParam) p.filters    = filtersParam
    if (search)       p.search     = search
    return p
  }

  const hasChips   = chipSev.size > 0 || chipStatus.size > 0 || chipSource.size > 0
  const hasFilters = activeFilters.length > 0 || search || projectId || hasChips

  const clearAll = () => {
    setFilters([]); setSearch(''); setProjectId('')
    setChipSev(new Set()); setChipStatus(new Set()); setChipSource(new Set())
    setPage(1); setSelected(new Set())
  }

  return (
    <div className="animate-in" style={{ display:'flex', flexDirection:'column', gap:'1.25rem' }}>

      {/* Header */}
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-end' }}>
        <div style={{ display:'flex', alignItems:'flex-start', gap:10 }}>
          <div>
            <h1 style={{ fontSize:'1.6rem', fontWeight:800, letterSpacing:'-0.03em' }}>Findings</h1>
            {data && (
              <p style={{ color:'var(--text-secondary)', fontSize:'0.85rem', marginTop:4 }}>
                {data.total.toLocaleString()} results
                {selected.size > 0 && <span style={{ color:'var(--accent)', marginLeft:12 }}>· {selected.size} selected</span>}
              </p>
            )}
          </div>
          <button
            onClick={() => refetch()}
            title="Refresh"
            style={{
              marginTop:6, background:'transparent', border:'1px solid var(--border)',
              borderRadius:8, color:'var(--text-muted)', cursor:'pointer',
              padding:'4px 8px', fontSize:'0.95rem', lineHeight:1,
              transition:'all 0.15s',
              animation: isFetching ? 'spin 0.8s linear infinite' : 'none',
            }}
          >⟳</button>
        </div>
        <div style={{ display:'flex', gap:8, alignItems:'center', flexWrap:'wrap' }}>
          {/* Batch bar */}
          {someSelected && (
            <div style={{ display:'flex', gap:6, alignItems:'center', background:'var(--bg-elevated)',
              border:'1px solid var(--border)', borderRadius:8, padding:'4px 8px' }}>
              <span style={{ fontSize:'0.78rem', color:'var(--text-muted)', fontFamily:'var(--font-mono)', whiteSpace:'nowrap' }}>
                {selected.size} selected
              </span>
              <select value={batchStatus} onChange={e => setBatchStatus(e.target.value)}
                style={{ fontSize:'0.8rem', padding:'3px 6px', background:'var(--bg-overlay)' }}>
                <option value="">→ Set status…</option>
                {STATUSES.map(s => <option key={s} value={s}>{s.replace(/_/g,' ')}</option>)}
              </select>
              <button className="btn btn-primary" style={{ padding:'3px 10px', fontSize:'0.78rem' }}
                disabled={!batchStatus || batchMutation.isPending}
                onClick={() => batchMutation.mutate({ ids: [...selected], status: batchStatus })}>
                Apply
              </button>
              {!confirmDelete ? (
                <button className="btn btn-danger" style={{ padding:'3px 8px', fontSize:'0.78rem' }}
                  onClick={() => setConfirmDelete(true)}>
                  🗑 Delete
                </button>
              ) : (
                <span style={{ display:'flex', gap:4, alignItems:'center' }}>
                  <span style={{ fontSize:'0.75rem', color:'var(--critical)', whiteSpace:'nowrap' }}>Delete {selected.size}?</span>
                  <button className="btn btn-danger" style={{ padding:'3px 8px', fontSize:'0.75rem' }}
                    disabled={batchDeleteMutation.isPending}
                    onClick={() => batchDeleteMutation.mutate([...selected])}>
                    {batchDeleteMutation.isPending ? '…' : 'Yes'}
                  </button>
                  <button className="btn btn-ghost" style={{ padding:'3px 8px', fontSize:'0.75rem' }}
                    onClick={() => setConfirmDelete(false)}>No</button>
                </span>
              )}
              <button className="btn btn-ghost" style={{ padding:'3px 8px', fontSize:'0.78rem' }}
                onClick={() => { setSelected(new Set()); setConfirmDelete(false) }}>✕</button>
            </div>
          )}
          <button className="btn btn-ghost"
            onClick={() => setFiltersOpen(v => !v)}
            title={filtersOpen ? 'Hide filters' : 'Show filters'}
            style={{ fontSize:'0.82rem' }}>
            {filtersOpen ? '▾ Filters' : '▸ Filters'}
          </button>
          <button className="btn btn-ghost"
            onClick={() => exportFile('csv', getExportParams()).catch(e => toast.error(e.message || 'Export failed'))}
            title="Export filtered results as CSV">↓ CSV</button>
          <button className="btn btn-ghost"
            onClick={() => exportFile('pdf', getExportParams()).catch(e => toast.error(e.message || 'Export failed'))}
            title="Export filtered results as PDF">↓ PDF</button>
        </div>
      </div>

      {/* Filter panel */}
      {filtersOpen && <div className="card" style={{ display:'flex', flexDirection:'column', gap:'0.85rem', padding:'1rem 1.25rem' }}>

        {/* Row 1: search + project */}
        <div style={{ display:'flex', gap:8, alignItems:'center' }}>
          <input placeholder="Search title, CVE, identifier, component, file…"
            value={search} onChange={e => { setSearch(e.target.value); setPage(1) }}
            style={{ flex:1, fontSize:'0.9rem' }} />
          <select value={projectId} onChange={e => { setProjectId(e.target.value); setPage(1) }}
            style={{ fontSize:'0.82rem', padding:'6px 10px', minWidth:160 }}>
            <option value="">All projects</option>
            {projects?.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
          {hasFilters && (
            <button className="btn btn-ghost" style={{ fontSize:'0.8rem', padding:'4px 10px', whiteSpace:'nowrap' }}
              onClick={clearAll}>✕ Clear all</button>
          )}
        </div>

        {/* Row 2: quick-filter chips */}
        <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
          {/* Severity chips */}
          <div style={{ display:'flex', alignItems:'center', gap:6, flexWrap:'wrap' }}>
            <span style={{ fontSize:'0.7rem', color:'var(--text-muted)', fontWeight:600, minWidth:52, textTransform:'uppercase', letterSpacing:'0.05em' }}>Severity</span>
            {SEVERITIES.map(v => (
              <Chip key={v} label={v} color={SEV_COLORS[v] || '#718096'}
                active={chipSev.has(v)} onClick={() => toggleChip(setChipSev, v)} />
            ))}
          </div>
          {/* Status chips */}
          <div style={{ display:'flex', alignItems:'center', gap:6, flexWrap:'wrap' }}>
            <span style={{ fontSize:'0.7rem', color:'var(--text-muted)', fontWeight:600, minWidth:52, textTransform:'uppercase', letterSpacing:'0.05em' }}>Status</span>
            {STATUSES.map(v => (
              <Chip key={v} label={v.replace(/_/g,' ')} color={STATUS_COLORS[v] || '#718096'}
                active={chipStatus.has(v)} onClick={() => toggleChip(setChipStatus, v)} />
            ))}
          </div>
          {/* Source chips */}
          <div style={{ display:'flex', alignItems:'center', gap:6, flexWrap:'wrap' }}>
            <span style={{ fontSize:'0.7rem', color:'var(--text-muted)', fontWeight:600, minWidth:52, textTransform:'uppercase', letterSpacing:'0.05em' }}>Source</span>
            {SOURCES.map(v => (
              <Chip key={v} label={v.replace(/_/g,'_')} color={SOURCE_COLORS[v] || '#718096'}
                active={chipSource.has(v)} onClick={() => toggleChip(setChipSource, v)} />
            ))}
          </div>
        </div>

        {/* Row 3: advanced filter groups (AND between groups, OR within group) */}
        {filters.length > 0 && (
          <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
            <div style={{ fontSize:'0.72rem', color:'var(--text-muted)', fontWeight:600, textTransform:'uppercase', letterSpacing:'0.05em' }}>
              Advanced filters — groups are ANDed, conditions within a group are ORed
            </div>
            {groupIds.map((groupId, gIdx) => {
              const groupFilters = filters.filter(f => (f.groupId ?? 0) === groupId)
              return (
                <React.Fragment key={groupId}>
                  {gIdx > 0 && (
                    <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                      <div style={{ flex:1, height:1, background:'var(--border)' }} />
                      <span style={{ fontSize:'0.7rem', fontWeight:700, color:'var(--accent)',
                        background:'var(--bg-elevated)', border:'1px solid var(--border)',
                        padding:'2px 10px', borderRadius:20 }}>AND</span>
                      <div style={{ flex:1, height:1, background:'var(--border)' }} />
                    </div>
                  )}
                  <div style={{ border:'1px solid var(--border)', borderRadius:8,
                    padding:'0.6rem 0.75rem', display:'flex', flexDirection:'column', gap:6,
                    background:'var(--bg-elevated)' }}>
                    {groupFilters.map((f, fIdx) => (
                      <React.Fragment key={f._id}>
                        {fIdx > 0 && (
                          <div style={{ display:'flex', alignItems:'center', gap:6 }}>
                            <span style={{ fontSize:'0.68rem', fontWeight:700, color:'var(--accent)',
                              padding:'1px 8px', borderRadius:20, border:'1px solid var(--accent)',
                              background:'rgba(66,153,225,0.08)' }}>OR</span>
                          </div>
                        )}
                        <div style={{ display:'flex', gap:6, alignItems:'center' }}>
                          <select value={f.field} onChange={e => updateFilter(f._id, 'field', e.target.value)}
                            style={{ fontSize:'0.82rem', padding:'4px 8px', minWidth:130 }}>
                            {FILTER_FIELDS.map(opt => <option key={opt.value} value={opt.value}>{opt.label}</option>)}
                          </select>
                          <select value={f.op} onChange={e => updateFilter(f._id, 'op', e.target.value)}
                            style={{ fontSize:'0.82rem', padding:'4px 8px', minWidth:160 }}>
                            {OPERATORS.map(opt => <option key={opt.value} value={opt.value}>{opt.label}</option>)}
                          </select>
                          <input value={f.value} onChange={e => updateFilter(f._id, 'value', e.target.value)}
                            onBlur={() => setPage(1)}
                            placeholder="value…" style={{ flex:1, fontSize:'0.85rem', padding:'4px 8px' }} />
                          <button onClick={() => removeFilter(f._id)}
                            style={{ background:'transparent', color:'var(--text-muted)', padding:'4px 8px',
                              fontSize:'1rem', border:'none', cursor:'pointer', transition:'color 0.15s' }}
                            onMouseEnter={e => e.target.style.color='var(--critical)'}
                            onMouseLeave={e => e.target.style.color='var(--text-muted)'}>✕</button>
                        </div>
                      </React.Fragment>
                    ))}
                    <div style={{ display:'flex', gap:6, marginTop:2 }}>
                      <button className="btn btn-ghost" style={{ fontSize:'0.75rem', padding:'2px 8px' }}
                        onClick={() => addFilterToGroup(groupId)}>
                        + OR condition
                      </button>
                      {groupIds.length > 1 && (
                        <button className="btn btn-ghost" style={{ fontSize:'0.75rem', padding:'2px 8px', color:'var(--critical)' }}
                          onClick={() => removeGroup(groupId)}>
                          Remove group
                        </button>
                      )}
                    </div>
                  </div>
                </React.Fragment>
              )
            })}
          </div>
        )}

        {/* Add filter / group buttons */}
        <div style={{ display:'flex', gap:8 }}>
          <button className="btn btn-ghost" style={{ fontSize:'0.8rem', padding:'3px 10px' }}
            onClick={() => {
              // Add to first group or create group 0
              const gid = groupIds.length > 0 ? groupIds[0] : 0
              addFilterToGroup(gid)
            }}>
            + Add filter
          </button>
          {filters.length > 0 && (
            <button className="btn btn-ghost" style={{ fontSize:'0.8rem', padding:'3px 10px' }}
              onClick={addGroup}>
              + AND group
            </button>
          )}
        </div>
      </div>}

      {/* Table */}
      <div className="card" style={{ padding:0, overflow:'hidden' }}>
        {isPending ? (
          <div style={{ padding:'2rem', textAlign:'center', color:'var(--text-muted)' }}>Loading…</div>
        ) : !data?.items?.length ? (
          <EmptyState />
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th style={{ width:36 }}>
                    <input type="checkbox" checked={allSelected} onChange={toggleAll}
                      style={{ cursor:'pointer', accentColor:'var(--accent)' }} />
                  </th>
                  {SORTABLE_COLS.map(col => (
                    <th key={col.key} onClick={() => toggleSort(col.key)}
                      style={{ cursor:'pointer', userSelect:'none', whiteSpace:'nowrap' }}>
                      <span style={{ display:'flex', alignItems:'center', gap:4 }}>
                        {col.label}
                        {sortBy === col.key && (
                          <span style={{ fontSize:'0.7rem', color:'var(--accent)' }}>
                            {sortDir === 'desc' ? '▼' : '▲'}
                          </span>
                        )}
                      </span>
                    </th>
                  ))}
                  <th>Identifier</th>
                  <th>Project</th>
                  <th>File</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map(f => {
                  const href = `/findings/${f.short_id || f.id}`
                  return (
                    <tr key={f.id}
                      style={{ background: selected.has(f.id) ? 'rgba(66,153,225,0.12)' : undefined }}>
                      <td onClick={e => e.stopPropagation()}>
                        <input type="checkbox" checked={selected.has(f.id)} onChange={() => toggleOne(f.id)}
                          style={{ cursor:'pointer', accentColor:'var(--accent)' }} />
                      </td>
                      <td style={{ padding:0 }}>
                        <Link to={href} style={{ display:'block', padding:'0.65rem 0.75rem', textDecoration:'none',
                          fontFamily:'var(--font-mono)', fontSize:'0.75rem', color:'var(--text-muted)' }}>
                          #{f.short_id || '—'}
                        </Link>
                      </td>
                      <td style={{ padding:0 }}>
                        <Link to={href} style={{ display:'block', padding:'0.65rem 0.75rem', textDecoration:'none' }}>
                          <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                        </Link>
                      </td>
                      <td style={{ padding:0, maxWidth:320 }}>
                        <Link to={href} style={{ display:'block', padding:'0.65rem 0.75rem', textDecoration:'none',
                          color:'var(--text-primary)', fontWeight:500, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', maxWidth:300 }}>
                          {f.title}
                        </Link>
                      </td>
                      <td style={{ padding:0 }}>
                        <Link to={href} style={{ display:'block', padding:'0.65rem 0.75rem', textDecoration:'none' }}>
                          <span className="source-chip">{f.source}</span>
                        </Link>
                      </td>
                      <td style={{ padding:0 }}>
                        <Link to={href} style={{ display:'block', padding:'0.65rem 0.75rem', textDecoration:'none' }}>
                          <span className={`badge badge-${f.status}`}>{f.status.replace(/_/g,' ')}</span>
                        </Link>
                      </td>
                      <td style={{ padding:0 }}>
                        <Link to={href} style={{ display:'block', padding:'0.65rem 0.75rem', textDecoration:'none',
                          fontSize:'0.78rem', fontFamily:'var(--font-mono)', whiteSpace:'nowrap', color:'var(--text-secondary)' }}>
                          {format(new Date(f.first_seen), 'yyyy-MM-dd')}
                        </Link>
                      </td>
                      <td style={{ padding:0 }}>
                        <Link to={href} style={{ display:'block', padding:'0.65rem 0.75rem', textDecoration:'none',
                          fontSize:'0.78rem', fontFamily:'var(--font-mono)', whiteSpace:'nowrap', color:'var(--text-secondary)' }}>
                          {format(new Date(f.last_seen), 'yyyy-MM-dd')}
                        </Link>
                      </td>
                      <td style={{ padding:0 }}>
                        <Link to={href} style={{ display:'block', padding:'0.65rem 0.75rem', textDecoration:'none',
                          fontFamily:'var(--font-mono)', fontSize:'0.72rem', color:'var(--accent)', maxWidth:160, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                          {f.cve || f.vuln_id || '—'}
                        </Link>
                      </td>
                      <td style={{ padding:0 }}>
                        <Link to={href} style={{ display:'block', padding:'0.65rem 0.75rem', textDecoration:'none',
                          fontSize:'0.83rem', color:'var(--text-secondary)' }}>
                          {f.project_name}
                        </Link>
                      </td>
                      <td style={{ padding:0 }}>
                        <Link to={href} style={{ display:'block', padding:'0.65rem 0.75rem', textDecoration:'none',
                          fontSize:'0.72rem', color:'var(--text-muted)', fontFamily:'var(--font-mono)', maxWidth:180, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                          {f.file_path ? `${f.file_path}${f.line_start ? `:${f.line_start}` : ''}` : '—'}
                        </Link>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Pagination */}
      {data?.total_pages > 1 && (
        <div style={{ display:'flex', justifyContent:'center', alignItems:'center', gap:8 }}>
          <button className="btn btn-ghost" disabled={page <= 1} onClick={() => setPage(p => p-1)}>‹ Prev</button>
          <span style={{ color:'var(--text-muted)', fontSize:'0.83rem', fontFamily:'var(--font-mono)' }}>
            {page} / {data.total_pages}
          </span>
          <button className="btn btn-ghost" disabled={page >= data.total_pages} onClick={() => setPage(p => p+1)}>Next ›</button>
        </div>
      )}
    </div>
  )
}

function EmptyState() {
  return (
    <div style={{ padding:'3rem', textAlign:'center' }}>
      <div style={{ fontSize:'2.5rem', marginBottom:12 }}>🛡️</div>
      <p style={{ color:'var(--text-secondary)', fontWeight:600 }}>No findings match your filters</p>
      <p style={{ color:'var(--text-muted)', fontSize:'0.83rem', marginTop:6 }}>Try adjusting your filters or clear them</p>
    </div>
  )
}

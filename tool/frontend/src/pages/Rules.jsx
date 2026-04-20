import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchRules, createRule, updateRule, deleteRule, simulateRule, applySingleRule, applyAllRules, exportRules, importRules } from '../api/client.js'
import toast from 'react-hot-toast'

// ── Constants ──────────────────────────────────────────────────────────────
const CONDITION_FIELDS = [
  { value: 'title',       label: 'Title' },
  { value: 'source',      label: 'Source' },
  { value: 'severity',    label: 'Severity' },
  { value: 'status',      label: 'Status' },
  { value: 'vuln_id',     label: 'Identifier' },
  { value: 'cve',         label: 'CVE' },
  { value: 'file_path',   label: 'File path' },
  { value: 'component',   label: 'Component' },
  { value: 'tags',        label: 'Tags' },
  { value: 'description', label: 'Description' },
]
const OPERATORS = [
  { value: 'equals',       label: 'equals' },
  { value: 'not_equals',   label: 'not equals' },
  { value: 'contains',     label: 'contains' },
  { value: 'not_contains', label: 'does not contain' },
  { value: 'starts_with',  label: 'starts with' },
  { value: 'ends_with',    label: 'ends with' },
  { value: 'in',           label: 'is one of (comma-sep)' },
  { value: 'regex',        label: 'regex' },
]
const ACTION_TYPES = [
  { value: 'set_status',   label: 'Set status to' },
  { value: 'set_severity', label: 'Set severity to' },
]
const STATUSES   = ['OPEN','IN_PROGRESS','CLOSED','ACCEPTED_RISK','FALSE_POSITIVE']
const SEVERITIES = ['CRITICAL','HIGH','MEDIUM','LOW','INFO','UNKNOWN']
const SEV_COLOR  = { CRITICAL:'var(--critical)', HIGH:'var(--high)', MEDIUM:'var(--medium)', LOW:'var(--low)', INFO:'var(--info)', UNKNOWN:'var(--unknown)' }

const CRON_PRESETS = [
  { label: 'Every hour',    value: '0 * * * *' },
  { label: 'Every 6h',     value: '0 */6 * * *' },
  { label: 'Every 12h',    value: '0 */12 * * *' },
  { label: 'Every day',    value: '0 2 * * *' },
  { label: 'Every Monday', value: '0 9 * * 1' },
  { label: 'Custom…',      value: 'custom' },
]

let cid = 0
const newCondition = () => ({ _id: ++cid, field: 'source', operator: 'equals', value: '' })
const newAction    = () => ({ _id: ++cid, type: 'set_status', value: 'FALSE_POSITIVE' })

// ── Main ───────────────────────────────────────────────────────────────────
export default function Rules() {
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [editing, setEditing]   = useState(null)
  const [simResult, setSimResult] = useState(null)   // { ruleId, ... }
  const [applyResult, setApplyResult] = useState(null) // { ruleId, ... }
  const [loadingId, setLoadingId] = useState(null)

  const { data: rules, isPending } = useQuery({ queryKey: ['rules'], queryFn: fetchRules })

  const deleteMutation = useMutation({
    mutationFn: deleteRule,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['rules'] }); toast.success('Rule deleted') },
  })
  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }) => updateRule(id, { enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })
  const applyAllMutation = useMutation({
    mutationFn: applyAllRules,
    onSuccess: (r) => toast.success(`${r.rules_applied} changes across ${r.findings_processed} findings`),
  })

  const handleSimulate = async (ruleId) => {
    setLoadingId(`sim-${ruleId}`)
    try {
      const res = await simulateRule(ruleId)
      setSimResult({ ruleId, ...res })
      setApplyResult(null)
    } catch { toast.error('Simulate failed') }
    finally { setLoadingId(null) }
  }

  const handleApply = async (ruleId, ruleName) => {
    setLoadingId(`apply-${ruleId}`)
    try {
      const res = await applySingleRule(ruleId)
      qc.invalidateQueries({ queryKey: ['rules'] })
      setApplyResult({ ruleId, ...res })
      setSimResult(null)
      toast.success(`Rule "${ruleName}": ${res.findings_changed} finding(s) changed`)
    } catch { toast.error('Apply failed') }
    finally { setLoadingId(null) }
  }

  return (
    <div className="animate-in" style={{ display:'flex', flexDirection:'column', gap:'1.25rem' }}>
      {/* Header */}
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-end' }}>
        <div>
          <h1 style={{ fontSize:'1.6rem', fontWeight:800, letterSpacing:'-0.03em' }}>Rules</h1>
          <p style={{ color:'var(--text-secondary)', fontSize:'0.85rem', marginTop:4 }}>
            Auto-triage findings on ingest — change status or severity automatically
          </p>
        </div>
        <div style={{ display:'flex', gap:8, flexWrap:'wrap', alignItems:'center' }}>
          <label className="btn btn-ghost" style={{ fontSize:'0.82rem', cursor:'pointer' }}>
            ↑ Import
            <input type="file" accept=".json" style={{ display:'none' }} onChange={async e => {
              const file = e.target.files[0]; if (!file) return
              try {
                const text = await file.text()
                const res = await importRules(JSON.parse(text))
                qc.invalidateQueries({ queryKey: ['rules'] })
                toast.success(`Imported: ${res.created} created, ${res.skipped} skipped`)
              } catch { toast.error('Import failed') }
              e.target.value = ''
            }} />
          </label>
          <button className="btn btn-ghost" style={{ fontSize:'0.82rem' }} onClick={async () => {
            const data = await exportRules()
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
            const a = document.createElement('a'); a.href = URL.createObjectURL(blob)
            a.download = 'w3gathrvulns-rules.json'; a.click()
          }}>↓ Export</button>
          <button className="btn btn-ghost" disabled={applyAllMutation.isPending}
            onClick={() => applyAllMutation.mutate()}>
            {applyAllMutation.isPending ? '⟳ Running…' : '⟳ Apply all now'}
          </button>
          <button className="btn btn-primary" onClick={() => { setEditing(null); setShowForm(true) }}>
            + New Rule
          </button>
        </div>
      </div>

      {/* Cron info banner */}
      <div className="card" style={{ padding:'0.75rem 1rem', background:'rgba(56,189,248,0.05)', border:'1px solid rgba(56,189,248,0.2)' }}>
        <p style={{ fontSize:'0.8rem', color:'var(--text-muted)', lineHeight:1.7 }}>
          ⚡ Rules run <strong style={{ color:'var(--text-secondary)' }}>automatically on every ingest</strong>.
          {' '}Set a <strong style={{ color:'var(--text-secondary)' }}>cron schedule</strong> on a rule for periodic re-evaluation — the built-in scheduler handles execution automatically.
          {' '}Use <strong style={{ color:'var(--text-secondary)' }}>Apply all now</strong> for an immediate manual run.
        </p>
      </div>

      {/* Form */}
      {showForm && (
        <RuleForm
          initial={editing}
          onClose={() => { setShowForm(false); setEditing(null) }}
          onSaved={() => { qc.invalidateQueries({ queryKey: ['rules'] }); setShowForm(false); setEditing(null) }}
        />
      )}

      {/* Rules list */}
      {isPending ? (
        <div style={{ padding:'2rem', textAlign:'center', color:'var(--text-muted)' }}>Loading…</div>
      ) : !rules?.length ? (
        <EmptyRules onNew={() => { setEditing(null); setShowForm(true) }} />
      ) : (
        <div style={{ display:'flex', flexDirection:'column', gap:'0.75rem' }}>
          {rules.map(rule => (
            <RuleCard
              key={rule.id}
              rule={rule}
              onEdit={() => { setEditing(rule); setShowForm(true) }}
              onDelete={() => { if (window.confirm(`Delete rule "${rule.name}"?`)) deleteMutation.mutate(rule.id) }}
              onToggle={() => toggleMutation.mutate({ id: rule.id, enabled: !rule.enabled })}
              onSimulate={() => handleSimulate(rule.id)}
              onApply={() => handleApply(rule.id, rule.name)}
              simulating={loadingId === `sim-${rule.id}`}
              applying={loadingId === `apply-${rule.id}`}
              simResult={simResult?.ruleId === rule.id ? simResult : null}
              applyResult={applyResult?.ruleId === rule.id ? applyResult : null}
              onCloseResult={() => { setSimResult(null); setApplyResult(null) }}
            />
          ))}
        </div>
      )}
    </div>
  )
}

// ── Rule Card ──────────────────────────────────────────────────────────────
function RuleCard({ rule, onEdit, onDelete, onToggle, onSimulate, onApply, simulating, applying, simResult, applyResult, onCloseResult }) {
  return (
    <div className="card" style={{
      borderLeft: `3px solid ${rule.enabled ? 'var(--accent)' : 'var(--border)'}`,
      opacity: rule.enabled ? 1 : 0.65,
      transition: 'all 0.2s',
    }}>
      {/* Main row */}
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap:12 }}>
        <div style={{ flex:1 }}>
          <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:4, flexWrap:'wrap' }}>
            <span style={{ fontFamily:'var(--font-mono)', fontSize:'0.7rem', color:'var(--text-muted)',
              background:'var(--bg-overlay)', padding:'1px 6px', borderRadius:3 }}>P{rule.priority}</span>
            <h3 style={{ fontSize:'0.95rem', fontWeight:700 }}>{rule.name}</h3>
            {!rule.enabled && (
              <span style={{ fontSize:'0.68rem', color:'var(--text-muted)', background:'var(--bg-overlay)',
                border:'1px solid var(--border)', padding:'1px 6px', borderRadius:3 }}>DISABLED</span>
            )}
            {rule.cron_schedule && (
              <span style={{ fontSize:'0.7rem', fontFamily:'var(--font-mono)', color:'var(--accent)',
                background:'var(--accent-dim)', border:'1px solid rgba(56,189,248,0.3)', padding:'1px 7px', borderRadius:3 }}>
                ⏱ {rule.cron_schedule}
              </span>
            )}
          </div>
          {rule.description && <p style={{ fontSize:'0.82rem', color:'var(--text-muted)', marginBottom:6 }}>{rule.description}</p>}

          {/* Conditions */}
          <div style={{ display:'flex', gap:6, flexWrap:'wrap', marginBottom:4, alignItems:'center' }}>
            <span style={{ fontSize:'0.7rem', color:'var(--text-muted)', fontWeight:700, textTransform:'uppercase', flexShrink:0 }}>
              IF ({rule.conditions_mode}):
            </span>
            {(rule.conditions || []).map((c, i) => (
              <span key={i} style={{ fontSize:'0.72rem', fontFamily:'var(--font-mono)',
                background:'var(--bg-overlay)', border:'1px solid var(--border)',
                padding:'1px 7px', borderRadius:3, color:'var(--text-secondary)' }}>
                {c.field} <span style={{ color:'var(--text-muted)' }}>{c.operator}</span> "{c.value}"
              </span>
            ))}
          </div>

          {/* Actions */}
          <div style={{ display:'flex', gap:6, flexWrap:'wrap', alignItems:'center' }}>
            <span style={{ fontSize:'0.7rem', color:'var(--text-muted)', fontWeight:700, textTransform:'uppercase', flexShrink:0 }}>THEN:</span>
            {(rule.actions || []).map((a, i) => (
              <span key={i} style={{ fontSize:'0.72rem', fontFamily:'var(--font-mono)',
                background: a.type === 'set_severity' ? 'rgba(234,179,8,0.1)' : 'rgba(56,189,248,0.1)',
                border: `1px solid ${a.type === 'set_severity' ? 'rgba(234,179,8,0.3)' : 'rgba(56,189,248,0.3)'}`,
                padding:'1px 7px', borderRadius:3,
                color: a.type === 'set_severity' ? (SEV_COLOR[a.value] || 'var(--medium)') : 'var(--accent)' }}>
                {a.type === 'set_status' ? '⟳' : '⚡'} {a.value}
              </span>
            ))}
          </div>
        </div>

        {/* Controls */}
        <div style={{ display:'flex', gap:6, alignItems:'center', flexShrink:0, flexWrap:'wrap', justifyContent:'flex-end' }}>
          {rule.applied_count > 0 && (
            <span style={{ fontSize:'0.72rem', color:'var(--low)', fontFamily:'var(--font-mono)', whiteSpace:'nowrap' }}>
              ✓ {rule.applied_count}
            </span>
          )}
          {/* Simulate */}
          <button className="btn btn-ghost" style={{ fontSize:'0.75rem', padding:'3px 8px' }}
            onClick={onSimulate} disabled={simulating || applying}
            title="Preview which findings would be affected — no changes applied">
            {simulating ? '⟳' : '▶ Simulate'}
          </button>
          {/* Apply */}
          <button style={{ fontSize:'0.75rem', padding:'3px 10px', borderRadius:4, cursor:'pointer', transition:'all 0.15s',
            background:'rgba(34,197,94,0.1)', color:'var(--low)', border:'1px solid rgba(34,197,94,0.3)',
            opacity: applying ? 0.7 : 1 }}
            onClick={onApply} disabled={applying || simulating}
            title="Apply this rule to all findings NOW">
            {applying ? '⟳' : '⚡ Apply'}
          </button>
          <button className="btn btn-ghost" style={{ fontSize:'0.75rem', padding:'3px 8px' }} onClick={onEdit}>✎ Edit</button>
          <button onClick={onToggle}
            style={{ fontSize:'0.75rem', padding:'3px 10px', borderRadius:4, cursor:'pointer', transition:'all 0.15s',
              background: rule.enabled ? 'rgba(34,197,94,0.1)' : 'var(--bg-elevated)',
              color: rule.enabled ? 'var(--low)' : 'var(--text-muted)',
              border: `1px solid ${rule.enabled ? 'rgba(34,197,94,0.3)' : 'var(--border)'}` }}>
            {rule.enabled ? 'ON' : 'OFF'}
          </button>
          <button className="btn btn-danger" style={{ fontSize:'0.75rem', padding:'3px 8px' }} onClick={onDelete}>✕</button>
        </div>
      </div>

      {/* Simulate result */}
      {simResult && (
        <ResultPanel
          type="simulate"
          count={simResult.matched_count}
          findings={simResult.matched_findings}
          onClose={onCloseResult}
        />
      )}

      {/* Apply result */}
      {applyResult && (
        <div style={{ marginTop:'0.75rem', borderTop:'1px solid var(--border)', paddingTop:'0.75rem', display:'flex', justifyContent:'space-between', alignItems:'center' }}>
          <span style={{ fontSize:'0.85rem', color: applyResult.findings_changed > 0 ? 'var(--low)' : 'var(--text-muted)', fontWeight:600 }}>
            {applyResult.findings_changed > 0
              ? `⚡ Applied: ${applyResult.findings_changed} finding(s) changed`
              : '⚡ Applied: no findings needed changes'}
          </span>
          <button onClick={onCloseResult} style={{ background:'transparent', color:'var(--text-muted)', fontSize:'0.8rem', padding:'2px 6px', border:'none', cursor:'pointer' }}>✕</button>
        </div>
      )}
    </div>
  )
}

// ── Result panel (simulate) ────────────────────────────────────────────────
function ResultPanel({ type, count, findings, onClose }) {
  return (
    <div style={{ marginTop:'1rem', borderTop:'1px solid var(--border)', paddingTop:'0.75rem' }}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:8 }}>
        <span style={{ fontSize:'0.82rem', fontWeight:700, color: count > 0 ? 'var(--accent)' : 'var(--text-muted)' }}>
          {type === 'simulate' ? '▶ Simulate' : '⚡'} — {count > 0 ? `${count} finding(s) would be affected` : 'No findings match'}
        </span>
        <button onClick={onClose} style={{ background:'transparent', color:'var(--text-muted)', fontSize:'0.8rem', padding:'2px 6px', border:'none', cursor:'pointer' }}>✕</button>
      </div>
      {findings?.slice(0,8).map(f => (
        <div key={f.id} style={{ display:'flex', alignItems:'center', gap:8, padding:'5px 0', borderBottom:'1px solid var(--border)', fontSize:'0.82rem' }}>
          <span style={{ fontFamily:'var(--font-mono)', color:'var(--text-muted)', fontSize:'0.72rem', minWidth:36 }}>#{f.short_id}</span>
          <span className={`badge badge-${f.severity}`}>{f.severity.slice(0,4)}</span>
          <span style={{ color:'var(--text-secondary)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', flex:1 }}>{f.title}</span>
          {f.notes && f.notes !== 'no change (already matches)' && (
            <span style={{ fontFamily:'var(--font-mono)', fontSize:'0.7rem', color:'var(--accent)', whiteSpace:'nowrap', flexShrink:0 }}>
              → {f.notes}
            </span>
          )}
          {f.notes === 'no change (already matches)' && (
            <span style={{ fontSize:'0.7rem', color:'var(--text-muted)', whiteSpace:'nowrap' }}>already matches</span>
          )}
        </div>
      ))}
      {count > 8 && (
        <p style={{ fontSize:'0.75rem', color:'var(--text-muted)', marginTop:4, textAlign:'right' }}>…and {count - 8} more</p>
      )}
    </div>
  )
}

// ── Rule Form ──────────────────────────────────────────────────────────────
function RuleForm({ initial, onClose, onSaved }) {
  const [name, setName]               = useState(initial?.name || '')
  const [description, setDescription] = useState(initial?.description || '')
  const [priority, setPriority]       = useState(initial?.priority ?? 100)
  const [mode, setMode]               = useState(initial?.conditions_mode || 'all')
  const [enabled, setEnabled]         = useState(initial?.enabled ?? true)
  const [cronPreset, setCronPreset]   = useState(() => {
    if (!initial?.cron_schedule) return ''
    const found = CRON_PRESETS.find(p => p.value === initial.cron_schedule)
    return found ? found.value : 'custom'
  })
  const [cronCustom, setCronCustom]   = useState(
    initial?.cron_schedule && !CRON_PRESETS.find(p => p.value === initial.cron_schedule && p.value !== 'custom')
      ? initial.cron_schedule : ''
  )
  const [conditions, setConditions] = useState(
    initial?.conditions?.length
      ? initial.conditions.map(c => ({ ...c, _id: ++cid }))
      : [newCondition()]
  )
  const [actions, setActions] = useState(
    initial?.actions?.length
      ? initial.actions.map(a => ({ ...a, _id: ++cid }))
      : [newAction()]
  )

  const getCronValue = () => {
    if (!cronPreset || cronPreset === 'custom') return cronCustom.trim() || null
    return cronPreset
  }

  const saveMutation = useMutation({
    mutationFn: (data) => initial ? updateRule(initial.id, data) : createRule(data),
    onSuccess: () => { toast.success(initial ? 'Rule updated' : 'Rule created'); onSaved() },
    onError: (e) => toast.error(e?.response?.data?.detail || 'Save failed'),
  })

  const handleSave = () => {
    if (!name.trim()) { toast.error('Name is required'); return }
    const validConditions = conditions.filter(c => c.value.trim())
    if (!validConditions.length) { toast.error('At least one condition with a value is required'); return }
    const validActions = actions.filter(a => a.value.trim())
    if (!validActions.length) { toast.error('At least one action is required'); return }
    saveMutation.mutate({
      name: name.trim(),
      description: description.trim() || undefined,
      priority: Number(priority),
      enabled,
      conditions_mode: mode,
      conditions: validConditions.map(({ field, operator, value }) => ({ field, operator, value })),
      actions: validActions.map(({ type, value }) => ({ type, value })),
      cron_schedule: getCronValue(),
    })
  }

  const addCond    = () => setConditions(c => [...c, newCondition()])
  const removeCond = (id) => setConditions(c => c.filter(x => x._id !== id))
  const updateCond = (id, k, v) => setConditions(c => c.map(x => x._id === id ? {...x, [k]:v} : x))
  const addAction    = () => setActions(a => [...a, newAction()])
  const removeAction = (id) => setActions(a => a.filter(x => x._id !== id))
  const updateAction = (id, k, v) => setActions(a => a.map(x => x._id === id ? {...x, [k]:v} : x))
  const getActionValues = (type) => type === 'set_status' ? STATUSES : SEVERITIES

  return (
    <div className="card animate-in" style={{ border:'1px solid var(--accent)' }}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:'1.25rem' }}>
        <h2 style={{ fontSize:'1rem', fontWeight:700 }}>{initial ? 'Edit Rule' : 'New Rule'}</h2>
        <button onClick={onClose} style={{ background:'transparent', color:'var(--text-muted)', fontSize:'1rem', border:'none', cursor:'pointer' }}>✕</button>
      </div>

      {/* Meta */}
      <div style={{ display:'grid', gridTemplateColumns:'1fr auto auto auto', gap:8, marginBottom:'0.75rem' }}>
        <input placeholder="Rule name *" value={name} onChange={e => setName(e.target.value)} style={{ fontSize:'0.9rem' }} />
        <input type="number" value={priority} onChange={e => setPriority(e.target.value)}
          style={{ width:70, fontSize:'0.85rem', textAlign:'center' }} title="Priority (lower = higher priority)" placeholder="Prio" />
        <label style={{ display:'flex', alignItems:'center', gap:6, fontSize:'0.82rem', color:'var(--text-secondary)', cursor:'pointer', whiteSpace:'nowrap' }}>
          <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} style={{ accentColor:'var(--accent)' }} />
          Enabled
        </label>
        <select value={mode} onChange={e => setMode(e.target.value)} style={{ fontSize:'0.82rem', padding:'6px 8px' }}>
          <option value="all">Match ALL</option>
          <option value="any">Match ANY</option>
        </select>
      </div>
      <input placeholder="Description (optional)" value={description} onChange={e => setDescription(e.target.value)}
        style={{ width:'100%', fontSize:'0.85rem', marginBottom:'0.75rem' }} />

      {/* Conditions */}
      <Section label="Conditions (IF)" mode={mode} onAdd={addCond}>
        {conditions.map(c => (
          <CondRow key={c._id} row={c} onChange={(k,v) => updateCond(c._id,k,v)} onRemove={() => removeCond(c._id)} />
        ))}
      </Section>

      {/* Actions */}
      <Section label="Actions (THEN)" onAdd={addAction}>
        {actions.map(a => (
          <div key={a._id} style={{ display:'flex', gap:6, alignItems:'center', marginBottom:6 }}>
            <select value={a.type} onChange={e => { updateAction(a._id,'type',e.target.value); updateAction(a._id,'value', e.target.value==='set_status'?'FALSE_POSITIVE':'LOW') }}
              style={{ fontSize:'0.82rem', padding:'4px 8px', minWidth:160 }}>
              {ACTION_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
            </select>
            <select value={a.value} onChange={e => updateAction(a._id,'value',e.target.value)}
              style={{ fontSize:'0.82rem', padding:'4px 8px', flex:1, color: a.type==='set_severity'?(SEV_COLOR[a.value]||'inherit'):'var(--accent)' }}>
              {getActionValues(a.type).map(v => <option key={v} value={v}>{v.replace(/_/g,' ')}</option>)}
            </select>
            <RemoveBtn onRemove={() => removeAction(a._id)} />
          </div>
        ))}
      </Section>

      {/* Schedule */}
      <div style={{ marginBottom:'1.25rem' }}>
        <div style={{ fontSize:'0.75rem', fontWeight:700, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.08em', marginBottom:8 }}>
          Schedule (optional) — re-runs this rule periodically
        </div>
        <div style={{ display:'flex', gap:6, alignItems:'center', flexWrap:'wrap' }}>
          <select value={cronPreset} onChange={e => setCronPreset(e.target.value)}
            style={{ fontSize:'0.82rem', padding:'4px 8px', minWidth:150 }}>
            <option value="">No schedule (ingest only)</option>
            {CRON_PRESETS.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
          </select>
          {cronPreset === 'custom' && (
            <input value={cronCustom} onChange={e => setCronCustom(e.target.value)}
              placeholder="0 * * * * (cron expression)" style={{ flex:1, fontSize:'0.82rem', fontFamily:'var(--font-mono)' }} />
          )}
          {cronPreset && cronPreset !== 'custom' && (
            <span style={{ fontSize:'0.75rem', fontFamily:'var(--font-mono)', color:'var(--text-muted)' }}>{cronPreset}</span>
          )}
        </div>
        <p style={{ fontSize:'0.72rem', color:'var(--text-muted)', marginTop:6 }}>
          The built-in scheduler will execute this rule automatically on its schedule. No external setup needed.
        </p>
      </div>

      <div style={{ display:'flex', gap:8, justifyContent:'flex-end' }}>
        <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" onClick={handleSave} disabled={saveMutation.isPending}>
          {saveMutation.isPending ? 'Saving…' : (initial ? 'Save changes' : 'Create rule')}
        </button>
      </div>
    </div>
  )
}

// ── Sub-components ─────────────────────────────────────────────────────────
function Section({ label, mode, onAdd, children }) {
  return (
    <div style={{ marginBottom:'1.25rem' }}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:8 }}>
        <span style={{ fontSize:'0.75rem', fontWeight:700, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.08em' }}>
          {label}{mode ? ` (${mode})` : ''}
        </span>
        <button className="btn btn-ghost" style={{ fontSize:'0.75rem', padding:'2px 8px' }} onClick={onAdd}>+ Add</button>
      </div>
      {children}
    </div>
  )
}

function CondRow({ row, onChange, onRemove }) {
  return (
    <div style={{ display:'flex', gap:6, alignItems:'center', marginBottom:6 }}>
      <select value={row.field} onChange={e => onChange('field', e.target.value)}
        style={{ fontSize:'0.82rem', padding:'4px 6px', minWidth:120 }}>
        {CONDITION_FIELDS.map(f => <option key={f.value} value={f.value}>{f.label}</option>)}
      </select>
      <select value={row.operator} onChange={e => onChange('operator', e.target.value)}
        style={{ fontSize:'0.82rem', padding:'4px 6px', minWidth:155 }}>
        {OPERATORS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
      <input value={row.value} onChange={e => onChange('value', e.target.value)}
        placeholder="value…" style={{ flex:1, fontSize:'0.85rem', padding:'4px 8px' }} />
      <RemoveBtn onRemove={onRemove} />
    </div>
  )
}

function RemoveBtn({ onRemove }) {
  return (
    <button onClick={onRemove}
      style={{ background:'transparent', color:'var(--text-muted)', padding:'4px 8px', fontSize:'1rem', transition:'color 0.15s', border:'none', cursor:'pointer' }}
      onMouseEnter={e => e.target.style.color='var(--critical)'}
      onMouseLeave={e => e.target.style.color='var(--text-muted)'}>✕</button>
  )
}

function EmptyRules({ onNew }) {
  return (
    <div className="card" style={{ textAlign:'center', padding:'3rem' }}>
      <div style={{ fontSize:'2.5rem', marginBottom:12 }}>⚡</div>
      <p style={{ color:'var(--text-secondary)', fontWeight:600 }}>No rules yet</p>
      <p style={{ color:'var(--text-muted)', fontSize:'0.83rem', marginTop:6, marginBottom:'1rem' }}>
        Example: mark all INFO trivy findings as ACCEPTED_RISK automatically on ingest
      </p>
      <button className="btn btn-primary" onClick={onNew}>Create first rule</button>
    </div>
  )
}

import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import React, { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchFinding, updateFinding, deleteFinding } from '../api/client.js'
import { format } from 'date-fns'
import toast from 'react-hot-toast'

const STATUSES = ['OPEN','IN_PROGRESS','CLOSED','ACCEPTED_RISK','FALSE_POSITIVE']

export default function FindingDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const qc = useQueryClient()

  const { data: f, isPending } = useQuery({ queryKey: ['finding', id], queryFn: () => fetchFinding(id) })
  const [notes, setNotes]       = useState('')
  const [fpReason, setFpReason] = useState('')
  const [notesOpen, setNotesOpen] = useState(false)
  const [refsOpen, setRefsOpen]   = useState(false)

  const mutation = useMutation({
    mutationFn: (data) => updateFinding(id, data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['finding', id] }); toast.success('Updated') },
    onError:   () => toast.error('Update failed'),
  })
  const delMutation = useMutation({
    mutationFn: () => deleteFinding(id),
    onSuccess:  () => { navigate('/findings'); toast.success('Deleted') },
  })

  if (isPending) return <div style={{ padding:'2rem', color:'var(--text-muted)' }}>Loading…</div>
  if (!f)        return <div style={{ padding:'2rem', color:'var(--critical)' }}>Finding not found</div>

  const ex         = f.extra_data || {}
  const sevColor   = { CRITICAL:'var(--critical)', HIGH:'var(--high)', MEDIUM:'var(--medium)', LOW:'var(--low)', INFO:'var(--info)' }[f.severity] || 'var(--unknown)'
  const references = ex.references || []
  const cweIds     = ex.cwe_ids    || []
  const cvssAll    = ex.cvss       || {}

  return (
    <div className="animate-in" style={{ display:'flex', flexDirection:'column', gap:'1.25rem' }}>
      <button className="btn btn-ghost" style={{ width:'fit-content', fontSize:'0.8rem' }} onClick={() => navigate(-1)}>← Back</button>

      {/* ── Header ── */}
      <div className="card" style={{ borderLeft:`3px solid ${sevColor}`, borderRadius:'0 12px 12px 12px' }}>
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', flexWrap:'wrap', gap:12 }}>
          <div style={{ flex:1 }}>
            <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:8, flexWrap:'wrap' }}>
              {f.short_id && (
                <span style={{ fontFamily:'var(--font-mono)', fontSize:'0.8rem', fontWeight:800, color:'var(--text-muted)', background:'var(--bg-overlay)', border:'1px solid var(--border)', padding:'1px 8px', borderRadius:4 }}>
                  #{f.short_id}
                </span>
              )}
              <span className={`badge badge-${f.severity}`}>{f.severity}</span>
              <span className={`badge badge-${f.status}`}>{f.status.replace(/_/g,' ')}</span>
              <span className="source-chip">{f.source}</span>
              {f.project_name && <span style={{ fontSize:'0.75rem', color:'var(--text-muted)', fontFamily:'var(--font-mono)' }}>📁 {f.project_name}</span>}
              {ex.artifact && <span style={{ fontSize:'0.75rem', color:'var(--text-muted)', fontFamily:'var(--font-mono)' }}>🐳 {ex.artifact}</span>}
            </div>
            <h1 style={{ fontSize:'1.15rem', fontWeight:700, lineHeight:1.4 }}>{f.title}</h1>
            {ex.title_short && ex.title_short !== f.title && (
              <p style={{ fontSize:'0.85rem', color:'var(--text-muted)', marginTop:4, fontStyle:'italic' }}>{ex.title_short}</p>
            )}
          </div>
          <div style={{ display:'flex', gap:6, flexWrap:'wrap' }}>
            {STATUSES.filter(s => s !== f.status).map(s => (
              <button key={s} className="btn btn-ghost" style={{ fontSize:'0.75rem', padding:'4px 10px' }}
                onClick={() => mutation.mutate({ status: s })}>→ {s.replace(/_/g,' ')}</button>
            ))}
            <button className="btn btn-danger" style={{ fontSize:'0.75rem', padding:'4px 10px' }}
              onClick={() => { if (window.confirm('Delete this finding?')) delMutation.mutate() }}>Delete</button>
          </div>
        </div>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'2fr 1fr', gap:'1.25rem' }}>

        {/* ── Left column ── */}
        <div style={{ display:'flex', flexDirection:'column', gap:'1rem' }}>

          {/* Description */}
          {f.description && (
            <div className="card">
              <SectionTitle>Description</SectionTitle>
              <div style={{ color:'var(--text-secondary)', fontSize:'0.88rem', lineHeight:1.7 }} className="md-body">
                <ReactMarkdown remarkPlugins={[remarkGfm]}>{f.description}</ReactMarkdown>
              </div>
            </div>
          )}

          {/* Location */}
          {(f.file_path || f.url) && (
            <div className="card">
              <SectionTitle>Location</SectionTitle>
              {f.file_path && (
                <MetaRow label="File">
                  <div style={{ display:'flex', flexDirection:'column', alignItems:'flex-end', gap:4 }}>
                    <code style={{ fontFamily:'var(--font-mono)', fontSize:'0.8rem', color:'var(--accent)' }}>
                      {f.file_path}{f.line_start ? `:${f.line_start}` : ''}{f.line_end && f.line_end !== f.line_start ? `-${f.line_end}` : ''}
                    </code>
                    {f.git_file_url && (
                      <a href={f.git_file_url} target="_blank" rel="noreferrer"
                        style={{ fontSize:'0.72rem', color:'var(--accent)', background:'var(--accent-dim)', border:'1px solid rgba(56,189,248,0.3)', padding:'2px 8px', borderRadius:4, display:'inline-flex', alignItems:'center', gap:4 }}>
                        <span>↗</span> Open in Git
                      </a>
                    )}
                  </div>
                </MetaRow>
              )}
              {f.url && (
                <MetaRow label="URL">
                  <code style={{ fontFamily:'var(--font-mono)', fontSize:'0.8rem', color:'var(--accent)', wordBreak:'break-all' }}>
                    {f.method && <span style={{ color:'var(--medium)', marginRight:6 }}>{f.method}</span>}
                    {f.url}
                  </code>
                </MetaRow>
              )}
              {f.parameter && <MetaRow label="Param"><code style={{ fontFamily:'var(--font-mono)', fontSize:'0.8rem' }}>{f.parameter}</code></MetaRow>}
              {ex.layer?.Digest && (
                <MetaRow label="Layer">
                  <code style={{ fontFamily:'var(--font-mono)', fontSize:'0.72rem', color:'var(--text-muted)', wordBreak:'break-all' }}>
                    {ex.layer.Digest.slice(0,19)}…
                  </code>
                </MetaRow>
              )}
            </div>
          )}

          {/* CVSS breakdown */}
          {Object.keys(cvssAll).length > 0 && (
            <div className="card">
              <SectionTitle>CVSS Scores</SectionTitle>
              <div style={{ display:'flex', flexDirection:'column', gap:10 }}>
                {Object.entries(cvssAll).map(([src, scores]) => (
                  <div key={src} style={{ background:'var(--bg-elevated)', borderRadius:8, padding:'10px 14px' }}>
                    <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:6 }}>
                      <span style={{ fontSize:'0.75rem', fontWeight:700, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.08em' }}>{src}</span>
                      <div style={{ display:'flex', gap:8 }}>
                        {scores.V3Score != null && (
                          <span style={{ fontFamily:'var(--font-mono)', fontSize:'0.9rem', fontWeight:800, color: cvssColor(scores.V3Score) }}>
                            v3: {scores.V3Score.toFixed(1)}
                          </span>
                        )}
                        {scores.V2Score != null && (
                          <span style={{ fontFamily:'var(--font-mono)', fontSize:'0.85rem', color:'var(--text-muted)' }}>
                            v2: {scores.V2Score.toFixed(1)}
                          </span>
                        )}
                      </div>
                    </div>
                    {scores.V3Score != null && (
                      <CvssBar score={scores.V3Score} max={10} />
                    )}
                    {scores.V3Vector && (
                      <code style={{ display:'block', marginTop:6, fontSize:'0.7rem', color:'var(--text-muted)', fontFamily:'var(--font-mono)', wordBreak:'break-all' }}>
                        {scores.V3Vector}
                      </code>
                    )}
                    {scores.V2Vector && !scores.V3Vector && (
                      <code style={{ display:'block', marginTop:6, fontSize:'0.7rem', color:'var(--text-muted)', fontFamily:'var(--font-mono)' }}>
                        {scores.V2Vector}
                      </code>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* References */}
          {references.length > 0 && (
            <div className="card">
              <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:'0.75rem' }}>
                <SectionTitle style={{ marginBottom:0 }}>References ({references.length})</SectionTitle>
                <button className="btn btn-ghost" style={{ fontSize:'0.75rem', padding:'3px 8px' }}
                  onClick={() => setRefsOpen(o => !o)}>{refsOpen ? 'Collapse' : 'Expand'}</button>
              </div>
              {refsOpen && (
                <div style={{ display:'flex', flexDirection:'column', gap:4 }}>
                  {references.map((ref, i) => (
                    <a key={i} href={ref} target="_blank" rel="noreferrer" style={{
                      fontSize:'0.78rem', color:'var(--accent)', fontFamily:'var(--font-mono)',
                      overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', display:'block',
                    }}>↗ {ref}</a>
                  ))}
                </div>
              )}
              {!refsOpen && (
                <a href={references[0]} target="_blank" rel="noreferrer"
                  style={{ fontSize:'0.78rem', color:'var(--accent)', fontFamily:'var(--font-mono)' }}>
                  ↗ {references[0]}
                </a>
              )}
            </div>
          )}


          {/* Source-specific panels */}
          {(f.source === 'owasp_zap') && (
            <ZapPanel ex={ex} />
          )}
          {(f.source === 'nuclei') && (
            <NucleiPanel ex={ex} />
          )}
          {(f.source === 'gitlab_secrets') && ex.rule_id && (
            <div className="card" style={{ borderLeft:'3px solid var(--critical)' }}>
              <SectionTitle>Secret Detection</SectionTitle>
              {ex.rule_id     && <MetaRow label="Rule"><code style={{ fontFamily:'var(--font-mono)', fontSize:'0.8rem', color:'var(--critical)' }}>{ex.rule_id}</code></MetaRow>}
              {ex.confidence  && <MetaRow label="Confidence"><span style={{ fontSize:'0.8rem' }}>{ex.confidence}</span></MetaRow>}
              {ex.raw_extract_masked && (
                <MetaRow label="Leaked value (masked)">
                  <code style={{ fontFamily:'var(--font-mono)', fontSize:'0.8rem', color:'var(--high)', background:'var(--high-bg)', padding:'2px 6px', borderRadius:4 }}>
                    {ex.raw_extract_masked}
                  </code>
                </MetaRow>
              )}
              {ex.commit_sha && ex.commit_sha !== '0000000' && (
                <MetaRow label="Commit"><code style={{ fontFamily:'var(--font-mono)', fontSize:'0.8rem', color:'var(--text-muted)' }}>{ex.commit_sha.slice(0,12)}</code></MetaRow>
              )}
            </div>
          )}
          {(f.source === 'gitlab_iac') && (
            <div className="card" style={{ borderLeft:'3px solid var(--medium)' }}>
              <SectionTitle>IaC / KICS</SectionTitle>
              {ex.kics_id && <MetaRow label="KICS ID"><code style={{ fontFamily:'var(--font-mono)', fontSize:'0.72rem', color:'var(--medium)', wordBreak:'break-all' }}>{ex.kics_id}</code></MetaRow>}
              {ex.category && <MetaRow label="Category"><span style={{ fontFamily:'var(--font-mono)', fontSize:'0.78rem' }}>{ex.category}</span></MetaRow>}
              {ex.scanner?.name && <MetaRow label="Scanner"><span style={{ fontSize:'0.8rem', color:'var(--text-secondary)' }}>{ex.scanner.name}{ex.scanner_version ? ` v${ex.scanner_version}` : ''}</span></MetaRow>}
              {ex.analyzer_name && <MetaRow label="Analyzer"><span style={{ fontSize:'0.78rem', color:'var(--text-muted)' }}>{ex.analyzer_name}{ex.analyzer_version ? ` v${ex.analyzer_version}` : ''}</span></MetaRow>}
              {ex.doc_url && <MetaRow label="Reference"><a href={ex.doc_url} target="_blank" rel="noreferrer" style={{ fontSize:'0.78rem', color:'var(--accent)' }}>↗ Documentation</a></MetaRow>}
              {ex.gl_finding_id && <MetaRow label="GL Finding ID"><code style={{ fontFamily:'var(--font-mono)', fontSize:'0.68rem', color:'var(--text-muted)', wordBreak:'break-all' }}>{ex.gl_finding_id.slice(0,16)}…</code></MetaRow>}
            </div>
          )}

          {/* Notes */}
          <div className="card">
            <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:'0.75rem' }}>
              <SectionTitle style={{ marginBottom:0 }}>Notes</SectionTitle>
              <button className="btn btn-ghost" style={{ fontSize:'0.75rem', padding:'3px 8px' }}
                onClick={() => setNotesOpen(o => !o)}>{notesOpen ? 'Cancel' : 'Edit'}</button>
            </div>
            {f.false_positive_reason && (
              <div style={{ background:'rgba(100,116,139,0.1)', border:'1px solid rgba(100,116,139,0.2)', borderRadius:6, padding:'10px 12px', marginBottom:8 }}>
                <span style={{ fontSize:'0.72rem', color:'var(--text-muted)', fontWeight:700, textTransform:'uppercase' }}>FP Reason: </span>
                <span style={{ fontSize:'0.85rem', color:'var(--text-secondary)' }}>{f.false_positive_reason}</span>
              </div>
            )}
            {f.notes && !notesOpen && <p style={{ fontSize:'0.85rem', color:'var(--text-secondary)', whiteSpace:'pre-wrap' }}>{f.notes}</p>}
            {!f.notes && !notesOpen && <p style={{ fontSize:'0.83rem', color:'var(--text-muted)' }}>No notes yet.</p>}
            {notesOpen && (
              <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
                <textarea value={notes || f.notes || ''} onChange={e => setNotes(e.target.value)}
                  placeholder="Add notes…" rows={3}
                  style={{ width:'100%', resize:'vertical', fontSize:'0.85rem', lineHeight:1.6 }} />
                <input value={fpReason} onChange={e => setFpReason(e.target.value)}
                  placeholder="False positive reason (optional)" style={{ width:'100%', fontSize:'0.85rem' }} />
                <button className="btn btn-primary" style={{ width:'fit-content' }}
                  onClick={() => mutation.mutate({ notes, false_positive_reason: fpReason || undefined })}>Save</button>
              </div>
            )}
          </div>
        </div>

        {/* ── Right column ── */}
        <div style={{ display:'flex', flexDirection:'column', gap:'1rem' }}>

          {/* Vulnerability IDs */}
          <div className="card">
            <SectionTitle>Identifiers</SectionTitle>
            {f.cve && <MetaRow label="CVE"><CveLink cve={f.cve} /></MetaRow>}
            {ex.semgrep_id && (
              <MetaRow label="Semgrep Rule">
                {ex.semgrep_url
                  ? <a href={ex.semgrep_url} target="_blank" rel="noreferrer"
                      style={{ fontFamily:'var(--font-mono)', fontSize:'0.75rem', color:'var(--accent)', wordBreak:'break-all' }}>
                      ↗ {ex.semgrep_id}
                    </a>
                  : <code style={{ fontFamily:'var(--font-mono)', fontSize:'0.75rem', color:'var(--accent)', wordBreak:'break-all' }}>{ex.semgrep_id}</code>
                }
              </MetaRow>
            )}
            {ex.bandit_test_id && (
              <MetaRow label="Bandit">
                <a href={`https://bandit.readthedocs.io/en/latest/plugins/${ex.bandit_test_id.toLowerCase()}.html`}
                  target="_blank" rel="noreferrer"
                  style={{ fontFamily:'var(--font-mono)', fontSize:'0.78rem', color:'var(--accent)' }}>
                  ↗ {ex.bandit_test_id}
                </a>
              </MetaRow>
            )}
            {ex.eslint_rule_id && <MetaRow label="ESLint Rule"><code style={{ fontFamily:'var(--font-mono)', fontSize:'0.78rem', color:'var(--accent)' }}>{ex.eslint_rule_id}</code></MetaRow>}
            {ex.njsscan_rule_type && (
              <MetaRow label="NJSScan">
                <span style={{ fontSize:'0.75rem', color:'var(--text-muted)', textAlign:'right', fontStyle:'italic' }}>
                  {ex.njsscan_rule_type.length > 60 ? ex.njsscan_rule_type.slice(0,60)+'…' : ex.njsscan_rule_type}
                </span>
              </MetaRow>
            )}
            {ex.primary_url && (
              <MetaRow label="Advisory">
                <a href={ex.primary_url} target="_blank" rel="noreferrer"
                  style={{ fontSize:'0.78rem', color:'var(--accent)', fontFamily:'var(--font-mono)', wordBreak:'break-all' }}>↗ {ex.primary_url.replace('https://','')}</a>
              </MetaRow>
            )}
            {/* CWEs — all of them with links. Handle both formats:
                  Object: {id: "CWE-79", url: "..."} (SAST/GitLab)
                  String: "cwe-200" or "CWE-200" (Nuclei, ZAP) */}
            {ex.cwes?.length > 0 && (
              <MetaRow label={ex.cwes.length > 1 ? `CWEs (${ex.cwes.length})` : 'CWE'}>
                <div style={{ display:'flex', gap:4, flexWrap:'wrap', justifyContent:'flex-end' }}>
                  {ex.cwes.map((cwe, i) => {
                    const isObj  = typeof cwe === 'object' && cwe !== null
                    const cweId  = isObj ? cwe.id  : String(cwe).toUpperCase().startsWith('CWE-') ? String(cwe).toUpperCase() : `CWE-${String(cwe).replace(/^cwe-/i,'')}`
                    const cweNum = cweId.replace('CWE-','')
                    const href   = isObj && cwe.url ? cwe.url : `https://cwe.mitre.org/data/definitions/${cweNum}.html`
                    return (
                      <a key={cweId + i} href={href} target="_blank" rel="noreferrer"
                        style={{ fontFamily:'var(--font-mono)', fontSize:'0.75rem', color:'var(--medium)',
                          background:'rgba(234,179,8,0.1)', border:'1px solid rgba(234,179,8,0.3)', padding:'1px 6px', borderRadius:4 }}>
                        {cweId}
                      </a>
                    )
                  })}
                </div>
              </MetaRow>
            )}
            {/* Fallback for non-SAST sources */}
            {!ex.cwes && cweIds.length > 0 && (
              <MetaRow label="CWE">
                <div style={{ display:'flex', gap:4, flexWrap:'wrap', justifyContent:'flex-end' }}>
                  {cweIds.map(cwe => (
                    <a key={cwe} href={`https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-','')}.html`}
                      target="_blank" rel="noreferrer"
                      style={{ fontFamily:'var(--font-mono)', fontSize:'0.75rem', color:'var(--medium)',
                        background:'rgba(234,179,8,0.1)', border:'1px solid rgba(234,179,8,0.3)', padding:'1px 6px', borderRadius:4 }}>
                      {cwe}
                    </a>
                  ))}
                </div>
              </MetaRow>
            )}
            {/* OWASP categories */}
            {ex.owasp?.length > 0 && (
              <MetaRow label="OWASP">
                <div style={{ display:'flex', gap:4, flexWrap:'wrap', justifyContent:'flex-end' }}>
                  {ex.owasp.map(o => (
                    <span key={o.value} style={{ fontFamily:'var(--font-mono)', fontSize:'0.72rem', color:'var(--info)',
                      background:'rgba(56,189,248,0.08)', border:'1px solid rgba(56,189,248,0.25)', padding:'1px 6px', borderRadius:4 }}
                      title={o.name}>
                      {o.value}
                    </span>
                  ))}
                </div>
              </MetaRow>
            )}
          </div>

          {/* Package info */}
          {(f.component || ex.purl) && (
            <div className="card">
              <SectionTitle>Package</SectionTitle>
              {f.component         && <MetaRow label="Name"><code style={{ fontFamily:'var(--font-mono)', fontSize:'0.8rem' }}>{f.component}</code></MetaRow>}
              {f.component_version && <MetaRow label="Installed"><code style={{ fontFamily:'var(--font-mono)', fontSize:'0.8rem', color:'var(--high)' }}>{f.component_version}</code></MetaRow>}
              {f.fixed_version     && <MetaRow label="Fixed in"><code style={{ fontFamily:'var(--font-mono)', fontSize:'0.8rem', color:'var(--low)' }}>{f.fixed_version}</code></MetaRow>}
              {ex.pkg_status       && <MetaRow label="Status"><StatusPill value={ex.pkg_status} /></MetaRow>}
              {ex.purl             && (
                <MetaRow label="PURL">
                  <code style={{ fontFamily:'var(--font-mono)', fontSize:'0.68rem', color:'var(--text-muted)', wordBreak:'break-all', textAlign:'right' }}>{ex.purl}</code>
                </MetaRow>
              )}
              {ex.data_source?.Name && <MetaRow label="Data source"><span style={{ fontSize:'0.78rem', color:'var(--text-muted)' }}>{ex.data_source.Name}</span></MetaRow>}
            </div>
          )}

          {/* Vendor severity breakdown */}
          {ex.vendor_severity && Object.keys(ex.vendor_severity).length > 0 && (
            <div className="card">
              <SectionTitle>Vendor Severity</SectionTitle>
              {Object.entries(ex.vendor_severity).map(([vendor, score]) => (
                <MetaRow key={vendor} label={vendor}>
                  <VendorSevPill score={score} />
                </MetaRow>
              ))}
              {ex.severity_source && (
                <div style={{ marginTop:8, paddingTop:8, borderTop:'1px solid var(--border)' }}>
                  <MetaRow label="Used source"><span style={{ fontSize:'0.78rem', fontFamily:'var(--font-mono)', color:'var(--accent)' }}>{ex.severity_source}</span></MetaRow>
                </div>
              )}
            </div>
          )}

          {/* Timeline */}
          <div className="card">
            <SectionTitle>Timeline</SectionTitle>
            <MetaRow label="First seen"><Mono>{format(new Date(f.first_seen), 'yyyy-MM-dd HH:mm')}</Mono></MetaRow>
            <MetaRow label="Last seen"><Mono>{format(new Date(f.last_seen), 'yyyy-MM-dd HH:mm')}</Mono></MetaRow>
            {ex.published_date && <MetaRow label="Published"><Mono>{ex.published_date.slice(0,10)}</Mono></MetaRow>}
            {ex.last_modified  && <MetaRow label="NVD updated"><Mono>{ex.last_modified.slice(0,10)}</Mono></MetaRow>}
            {ex.scan_start    && <MetaRow label="Scan started"><Mono>{ex.scan_start.replace('T',' ').slice(0,16)}</Mono></MetaRow>}
            {ex.scan_end      && <MetaRow label="Scan ended"><Mono>{ex.scan_end.replace('T',' ').slice(0,16)}</Mono></MetaRow>}
            {ex.scan_status   && <MetaRow label="Scan status"><span style={{ fontSize:'0.78rem', color: ex.scan_status === 'success' ? 'var(--low)' : 'var(--high)' }}>{ex.scan_status}</span></MetaRow>}
          </div>

          {/* Tags */}
          {f.tags?.length > 0 && (
            <div className="card">
              <SectionTitle>Tags</SectionTitle>
              <div style={{ display:'flex', gap:6, flexWrap:'wrap' }}>
                {f.tags.map(t => (
                  <span key={t} style={{ padding:'2px 8px', background:'var(--bg-overlay)', border:'1px solid var(--border)', borderRadius:4, fontSize:'0.73rem', color:'var(--text-secondary)', fontFamily:'var(--font-mono)' }}>{t}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Sub-components ─────────────────────────────────────────────────────────────

const SectionTitle = ({ children, style }) => (
  <h3 style={{ fontSize:'0.75rem', fontWeight:700, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.1em', marginBottom:'0.75rem', ...style }}>{children}</h3>
)

const MetaRow = ({ label, children }) => (
  <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap:12, marginBottom:8 }}>
    <span style={{ fontSize:'0.78rem', color:'var(--text-muted)', fontWeight:600, whiteSpace:'nowrap', flexShrink:0 }}>{label}</span>
    <span style={{ fontSize:'0.83rem', color:'var(--text-secondary)', textAlign:'right' }}>{children}</span>
  </div>
)

const Mono = ({ children }) => (
  <span style={{ fontFamily:'var(--font-mono)', fontSize:'0.78rem' }}>{children}</span>
)

const CveLink = ({ cve }) => (
  <a href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noreferrer"
    style={{ fontFamily:'var(--font-mono)', fontSize:'0.8rem', color:'var(--critical)',
      background:'var(--critical-bg)', border:'1px solid rgba(244,63,94,0.3)', padding:'1px 7px', borderRadius:4 }}>
    {cve} ↗
  </a>
)

function cvssColor(score) {
  if (score >= 9) return 'var(--critical)'
  if (score >= 7) return 'var(--high)'
  if (score >= 4) return 'var(--medium)'
  return 'var(--low)'
}

function CvssBar({ score, max = 10 }) {
  const pct = Math.min(100, (score / max) * 100)
  const color = cvssColor(score)
  return (
    <div style={{ height:4, background:'var(--bg-overlay)', borderRadius:2, overflow:'hidden', marginTop:4 }}>
      <div style={{ height:'100%', width:`${pct}%`, background:color, borderRadius:2, transition:'width 0.4s ease' }} />
    </div>
  )
}

const VENDOR_SEV = ['', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
function VendorSevPill({ score }) {
  const label = VENDOR_SEV[score] || String(score)
  return <span className={`badge badge-${label || 'UNKNOWN'}`}>{label || score}</span>
}

function StatusPill({ value }) {
  const color = value === 'fixed' ? 'var(--low)' : value === 'affected' ? 'var(--high)' : 'var(--text-muted)'
  return <span style={{ fontFamily:'var(--font-mono)', fontSize:'0.78rem', color, fontWeight:600 }}>{value}</span>
}


// ── ZAP Detail Panel ──────────────────────────────────────────────────────────
function ZapPanel({ ex }) {
  const [showInstances, setShowInstances] = React.useState(false)
  if (!ex) return null
  const instances = ex.instances || []
  return (
    <>
      {/* ZAP classification card */}
      <div className="card" style={{ borderLeft:'3px solid var(--high)' }}>
        <SectionTitle>ZAP Scan Details</SectionTitle>
        {ex.plugin_id && <MetaRow label="Plugin ID"><code style={{ fontFamily:'var(--font-mono)', fontSize:'0.8rem', color:'var(--accent)' }}>{ex.plugin_id}</code></MetaRow>}
        {ex.alert_ref && <MetaRow label="Alert Ref"><code style={{ fontFamily:'var(--font-mono)', fontSize:'0.8rem', color:'var(--text-muted)' }}>{ex.alert_ref}</code></MetaRow>}
        {ex.confidence && <MetaRow label="Confidence"><span style={{ fontSize:'0.82rem', color:'var(--text-secondary)' }}>{ex.confidence}</span></MetaRow>}
        {ex.riskdesc && <MetaRow label="Risk"><span style={{ fontSize:'0.82rem', fontFamily:'var(--font-mono)', color:'var(--high)' }}>{ex.riskdesc}</span></MetaRow>}
        {ex.systemic && <MetaRow label="Systemic"><span style={{ fontSize:'0.78rem', color:'var(--critical)', fontWeight:700 }}>Yes — affects whole site</span></MetaRow>}
        {ex.instance_count != null && <MetaRow label="Instances"><span style={{ fontFamily:'var(--font-mono)', fontSize:'0.82rem', color:'var(--accent)' }}>{ex.instance_count} URL(s) affected</span></MetaRow>}
        {ex.site && <MetaRow label="Target"><code style={{ fontFamily:'var(--font-mono)', fontSize:'0.78rem', color:'var(--text-muted)' }}>{ex.ssl ? '🔒 ' : ''}{ex.site}{ex.port && ex.port !== '80' && ex.port !== '443' ? `:${ex.port}` : ''}</code></MetaRow>}
        {ex.wasc_id && (
          <MetaRow label="WASC">
            <a href={ex.wasc_url || '#'} target="_blank" rel="noreferrer"
              style={{ fontFamily:'var(--font-mono)', fontSize:'0.75rem', color:'var(--medium)',
                background:'rgba(234,179,8,0.1)', border:'1px solid rgba(234,179,8,0.3)', padding:'1px 6px', borderRadius:4 }}>
              {ex.wasc_id}
            </a>
          </MetaRow>
        )}
        {ex.cwe_id && (
          <MetaRow label="CWE">
            <a href={ex.cwe_url || `https://cwe.mitre.org/data/definitions/${ex.cwe_id.replace('CWE-','')}.html`}
              target="_blank" rel="noreferrer"
              style={{ fontFamily:'var(--font-mono)', fontSize:'0.75rem', color:'var(--medium)',
                background:'rgba(234,179,8,0.1)', border:'1px solid rgba(234,179,8,0.3)', padding:'1px 6px', borderRadius:4 }}>
              {ex.cwe_id}
            </a>
          </MetaRow>
        )}
        {ex.zap_version && (
          <div style={{ marginTop:8, paddingTop:8, borderTop:'1px solid var(--border)' }}>
            <MetaRow label="ZAP version"><span style={{ fontFamily:'var(--font-mono)', fontSize:'0.75rem', color:'var(--text-muted)' }}>{ex.zap_version}</span></MetaRow>
            {ex.generated_at && <MetaRow label="Scan date"><span style={{ fontFamily:'var(--font-mono)', fontSize:'0.75rem', color:'var(--text-muted)' }}>{ex.generated_at}</span></MetaRow>}
          </div>
        )}
      </div>

      {/* Instances list */}
      {instances.length > 0 && (
        <div className="card">
          <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:'0.75rem' }}>
            <SectionTitle style={{ marginBottom:0 }}>
              Affected URLs ({instances.length})
            </SectionTitle>
            <button className="btn btn-ghost" style={{ fontSize:'0.75rem', padding:'3px 8px' }}
              onClick={() => setShowInstances(s => !s)}>
              {showInstances ? 'Collapse' : 'Expand'}
            </button>
          </div>
          {/* Always show first URL */}
          <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
            {(showInstances ? instances : instances.slice(0,2)).map((inst, i) => (
              <div key={inst.id || i} style={{ background:'var(--bg-elevated)', borderRadius:6, padding:'8px 12px' }}>
                <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom: (inst.param || inst.evidence || inst.attack) ? 4 : 0 }}>
                  <span style={{ fontFamily:'var(--font-mono)', fontSize:'0.7rem', color:'var(--accent)',
                    background:'var(--accent-dim)', padding:'1px 5px', borderRadius:3, flexShrink:0 }}>
                    {inst.method || 'GET'}
                  </span>
                  <a href={inst.uri} target="_blank" rel="noreferrer"
                    style={{ fontFamily:'var(--font-mono)', fontSize:'0.75rem', color:'var(--text-secondary)',
                      wordBreak:'break-all', flex:1 }}>
                    {inst.uri}
                  </a>
                </div>
                {inst.param && (
                  <div style={{ fontSize:'0.72rem', color:'var(--text-muted)', fontFamily:'var(--font-mono)', marginTop:3 }}>
                    <span style={{ color:'var(--text-muted)', marginRight:6 }}>param:</span>
                    <code style={{ color:'var(--medium)' }}>{inst.param}</code>
                  </div>
                )}
                {inst.evidence && (
                  <div style={{ fontSize:'0.72rem', marginTop:3 }}>
                    <span style={{ color:'var(--text-muted)', marginRight:6, fontFamily:'var(--font-mono)' }}>evidence:</span>
                    <code style={{ fontFamily:'var(--font-mono)', color:'var(--high)', background:'var(--high-bg)', padding:'1px 5px', borderRadius:3 }}>
                      {inst.evidence.length > 80 ? inst.evidence.slice(0,80)+'…' : inst.evidence}
                    </code>
                  </div>
                )}
                {inst.otherinfo && inst.otherinfo.trim() && (
                  <div style={{ fontSize:'0.7rem', color:'var(--text-muted)', marginTop:3, fontStyle:'italic' }}>
                    {inst.otherinfo.trim().slice(0,120)}{inst.otherinfo.length > 120 ? '…' : ''}
                  </div>
                )}
              </div>
            ))}
            {!showInstances && instances.length > 2 && (
              <button className="btn btn-ghost" style={{ fontSize:'0.75rem', padding:'4px 10px', alignSelf:'flex-start' }}
                onClick={() => setShowInstances(true)}>
                Show {instances.length - 2} more…
              </button>
            )}
          </div>
        </div>
      )}

      {/* References */}
      {ex.references?.length > 0 && (
        <div className="card">
          <SectionTitle>References ({ex.references.length})</SectionTitle>
          <div style={{ display:'flex', flexDirection:'column', gap:4 }}>
            {ex.references.map((ref, i) => (
              <a key={i} href={ref} target="_blank" rel="noreferrer"
                style={{ fontSize:'0.78rem', color:'var(--accent)', fontFamily:'var(--font-mono)',
                  overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', display:'block' }}>
                ↗ {ref}
              </a>
            ))}
          </div>
        </div>
      )}

      {/* Scan insights */}
      {ex.insights?.length > 0 && (
        <div className="card">
          <SectionTitle>Scan Insights</SectionTitle>
          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:6 }}>
            {ex.insights.map((ins, i) => (
              <div key={i} style={{ display:'flex', justifyContent:'space-between', alignItems:'center',
                background:'var(--bg-elevated)', borderRadius:6, padding:'6px 10px' }}>
                <span style={{ fontSize:'0.75rem', color:'var(--text-muted)' }}>{ins.description}</span>
                <span style={{ fontFamily:'var(--font-mono)', fontSize:'0.82rem', fontWeight:700, color:'var(--accent)', marginLeft:8, flexShrink:0 }}>
                  {ins.statistic}{ins.description?.toLowerCase().includes('percentage') ? '%' : ''}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </>
  )
}


// ── Nuclei Detail Panel ───────────────────────────────────────────────────────
function NucleiPanel({ ex }) {
  const [showTraffic, setShowTraffic] = React.useState(false)
  if (!ex) return null
  return (
    <>
      {/* Template + match details */}
      <div className="card" style={{ borderLeft:'3px solid var(--accent)' }}>
        <SectionTitle>Nuclei Template</SectionTitle>
        {ex.template_id && (
          <MetaRow label="Template ID">
            {ex.template_url
              ? <a href={ex.template_url} target="_blank" rel="noreferrer"
                  style={{ fontFamily:'var(--font-mono)', fontSize:'0.78rem', color:'var(--accent)' }}>
                  ↗ {ex.template_id}
                </a>
              : <code style={{ fontFamily:'var(--font-mono)', fontSize:'0.78rem', color:'var(--accent)' }}>{ex.template_id}</code>
            }
          </MetaRow>
        )}
        {ex.scan_type && (
          <MetaRow label="Scan type">
            <span style={{ fontFamily:'var(--font-mono)', fontSize:'0.78rem',
              background:'var(--bg-overlay)', border:'1px solid var(--border)', padding:'1px 7px', borderRadius:4 }}>
              {ex.scan_type}
            </span>
          </MetaRow>
        )}
        {ex.matcher_name && <MetaRow label="Matcher"><code style={{ fontFamily:'var(--font-mono)', fontSize:'0.78rem', color:'var(--medium)' }}>{ex.matcher_name}</code></MetaRow>}
        {ex.extractor_name && <MetaRow label="Extractor"><code style={{ fontFamily:'var(--font-mono)', fontSize:'0.78rem', color:'var(--medium)' }}>{ex.extractor_name}</code></MetaRow>}
        {ex.matched_at && (
          <MetaRow label="Matched at">
            <code style={{ fontFamily:'var(--font-mono)', fontSize:'0.75rem', color:'var(--text-secondary)', wordBreak:'break-all' }}>{ex.matched_at}</code>
          </MetaRow>
        )}
        {ex.ip && <MetaRow label="IP"><code style={{ fontFamily:'var(--font-mono)', fontSize:'0.78rem', color:'var(--text-muted)' }}>{ex.ip}</code></MetaRow>}
        {ex.verified && <MetaRow label="Verified"><span style={{ color:'var(--low)', fontSize:'0.78rem', fontWeight:700 }}>✓ Template verified</span></MetaRow>}
        {ex.max_requests != null && <MetaRow label="Requests"><span style={{ fontFamily:'var(--font-mono)', fontSize:'0.78rem', color:'var(--text-muted)' }}>{ex.max_requests}</span></MetaRow>}
        {ex.shodan_query && (
          <MetaRow label="Shodan">
            <a href={`https://www.shodan.io/search?query=${encodeURIComponent(ex.shodan_query)}`}
              target="_blank" rel="noreferrer"
              style={{ fontSize:'0.75rem', color:'var(--accent)', fontFamily:'var(--font-mono)', wordBreak:'break-all' }}>
              ↗ {ex.shodan_query.slice(0,60)}{ex.shodan_query.length > 60 ? '…' : ''}
            </a>
          </MetaRow>
        )}
        {ex.authors?.length > 0 && (
          <MetaRow label="Authors">
            <span style={{ fontSize:'0.75rem', color:'var(--text-muted)' }}>
              {(Array.isArray(ex.authors) ? ex.authors : [ex.authors]).join(', ')}
            </span>
          </MetaRow>
        )}
      </div>

      {/* Extracted results */}
      {ex.extracted_results?.length > 0 && (
        <div className="card">
          <SectionTitle>Extracted Results ({ex.extracted_results.length})</SectionTitle>
          <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
            {ex.extracted_results.map((r, i) => (
              <div key={i} style={{ background:'var(--bg-elevated)', borderRadius:6, padding:'8px 12px' }}>
                <code style={{ fontFamily:'var(--font-mono)', fontSize:'0.78rem', color:'var(--accent)', wordBreak:'break-all' }}>
                  {r}
                </code>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Classification */}
      {(ex.cwes?.length > 0 || ex.cvss_metrics) && (
        <div className="card">
          <SectionTitle>Classification</SectionTitle>
          {ex.cwes?.length > 0 && (
            <MetaRow label="CWE">
              <div style={{ display:'flex', gap:4, flexWrap:'wrap', justifyContent:'flex-end' }}>
                {ex.cwes.map(cwe => (
                  <a key={cwe} href={`https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-','').replace('cwe-','')}.html`}
                    target="_blank" rel="noreferrer"
                    style={{ fontFamily:'var(--font-mono)', fontSize:'0.75rem', color:'var(--medium)',
                      background:'rgba(234,179,8,0.1)', border:'1px solid rgba(234,179,8,0.3)', padding:'1px 6px', borderRadius:4 }}>
                    {cwe}
                  </a>
                ))}
              </div>
            </MetaRow>
          )}
          {ex.cvss_metrics && (
            <MetaRow label="CVSS Vector">
              <code style={{ fontFamily:'var(--font-mono)', fontSize:'0.7rem', color:'var(--text-muted)', wordBreak:'break-all' }}>
                {ex.cvss_metrics}
              </code>
            </MetaRow>
          )}
        </div>
      )}

      {/* References */}
      {ex.references?.length > 0 && (
        <div className="card">
          <SectionTitle>References ({ex.references.length})</SectionTitle>
          {ex.references.map((ref, i) => (
            <a key={i} href={ref} target="_blank" rel="noreferrer"
              style={{ display:'block', fontSize:'0.78rem', color:'var(--accent)',
                fontFamily:'var(--font-mono)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', marginBottom:4 }}>
              ↗ {ref}
            </a>
          ))}
        </div>
      )}

      {/* curl + traffic */}
      {(ex.curl_command || ex.request_snippet) && (
        <div className="card">
          <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:'0.75rem' }}>
            <SectionTitle style={{ marginBottom:0 }}>Traffic</SectionTitle>
            <button className="btn btn-ghost" style={{ fontSize:'0.75rem', padding:'3px 8px' }}
              onClick={() => setShowTraffic(s => !s)}>
              {showTraffic ? 'Hide' : 'Show'}
            </button>
          </div>
          {ex.curl_command && (
            <div style={{ marginBottom: showTraffic ? 10 : 0 }}>
              <div style={{ fontSize:'0.7rem', color:'var(--text-muted)', marginBottom:4, textTransform:'uppercase', letterSpacing:'0.06em' }}>curl command</div>
              <pre style={{ background:'var(--bg-elevated)', borderRadius:6, padding:'8px 12px',
                fontSize:'0.72rem', fontFamily:'var(--font-mono)', color:'var(--text-secondary)',
                overflowX:'auto', margin:0, whiteSpace:'pre-wrap', wordBreak:'break-all' }}>
                {ex.curl_command}
              </pre>
            </div>
          )}
          {showTraffic && ex.request_snippet && (
            <div style={{ marginTop:10 }}>
              <div style={{ fontSize:'0.7rem', color:'var(--text-muted)', marginBottom:4, textTransform:'uppercase', letterSpacing:'0.06em' }}>request (excerpt)</div>
              <pre style={{ background:'var(--bg-elevated)', borderRadius:6, padding:'8px 12px',
                fontSize:'0.7rem', fontFamily:'var(--font-mono)', color:'var(--text-secondary)',
                overflowX:'auto', margin:0, whiteSpace:'pre-wrap', wordBreak:'break-all', maxHeight:200 }}>
                {ex.request_snippet}
              </pre>
            </div>
          )}
          {showTraffic && ex.response_snippet && (
            <div style={{ marginTop:10 }}>
              <div style={{ fontSize:'0.7rem', color:'var(--text-muted)', marginBottom:4, textTransform:'uppercase', letterSpacing:'0.06em' }}>response (excerpt)</div>
              <pre style={{ background:'var(--bg-elevated)', borderRadius:6, padding:'8px 12px',
                fontSize:'0.7rem', fontFamily:'var(--font-mono)', color:'var(--text-secondary)',
                overflowX:'auto', margin:0, whiteSpace:'pre-wrap', wordBreak:'break-all', maxHeight:200 }}>
                {ex.response_snippet}
              </pre>
            </div>
          )}
        </div>
      )}
    </>
  )
}

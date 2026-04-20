import React, { useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchProject, fetchProjectScans, fetchFindings, updateProject } from '../api/client.js'
import { format } from 'date-fns'
import toast from 'react-hot-toast'

const SOURCE_ICON = { trivy:'🐳', gitlab_sast:'🔬', gitlab_iac:'☁️', gitlab_secrets:'🔑', owasp_zap:'🕷️', nuclei:'⚡', unknown:'❓' }
const GIT_PROVIDERS = ['gitlab','github','bitbucket','azure','gitea','other']

export default function ProjectDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [editOpen, setEditOpen] = useState(false)

  const { data: project, isPending } = useQuery({ queryKey: ['project', id], queryFn: () => fetchProject(id) })
  const { data: scans }   = useQuery({ queryKey: ['scans', id],             queryFn: () => fetchProjectScans(id) })
  const { data: findings } = useQuery({ queryKey: ['findings-project', id], queryFn: () => fetchFindings({ project_id: id, page_size: 10, page: 1 }) })

  const [form, setForm] = useState(null)
  const openEdit = () => {
    setForm({
      description:    project.description    || '',
      repository_url: project.repository_url || '',
      git_provider:   project.git_provider   || 'gitlab',
      default_branch: project.default_branch || 'main',
    })
    setEditOpen(true)
  }

  const saveMutation = useMutation({
    mutationFn: (data) => updateProject(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['project', id] })
      setEditOpen(false)
      toast.success('Project updated')
    },
    onError: () => toast.error('Update failed'),
  })

  if (isPending) return <div style={{ padding:'2rem', color:'var(--text-muted)' }}>Loading…</div>
  if (!project)  return <div style={{ padding:'2rem', color:'var(--critical)' }}>Project not found</div>

  return (
    <div className="animate-in" style={{ display:'flex', flexDirection:'column', gap:'1.25rem' }}>
      <button className="btn btn-ghost" style={{ width:'fit-content', fontSize:'0.8rem' }} onClick={() => navigate('/projects')}>← Back to Projects</button>

      {/* Header card */}
      <div className="card">
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', flexWrap:'wrap', gap:12 }}>
          <div>
            <h1 style={{ fontSize:'1.5rem', fontWeight:800, letterSpacing:'-0.03em' }}>{project.name}</h1>
            {project.description && <p style={{ color:'var(--text-secondary)', marginTop:4, fontSize:'0.88rem' }}>{project.description}</p>}
            {project.repository_url && (
              <a href={project.repository_url} target="_blank" rel="noreferrer"
                style={{ color:'var(--accent)', fontSize:'0.8rem', fontFamily:'var(--font-mono)', marginTop:6, display:'inline-block' }}>
                🔗 {project.repository_url}
              </a>
            )}
            {project.git_provider && (
              <div style={{ marginTop:4, display:'flex', gap:8, alignItems:'center' }}>
                <span style={{ fontSize:'0.72rem', color:'var(--text-muted)', fontFamily:'var(--font-mono)',
                  background:'var(--bg-overlay)', border:'1px solid var(--border)', padding:'1px 6px', borderRadius:3 }}>
                  {project.git_provider}
                </span>
                {project.default_branch && (
                  <span style={{ fontSize:'0.72rem', color:'var(--text-muted)', fontFamily:'var(--font-mono)',
                    background:'var(--bg-overlay)', border:'1px solid var(--border)', padding:'1px 6px', borderRadius:3 }}>
                    ⎇ {project.default_branch}
                  </span>
                )}
              </div>
            )}
          </div>
          <div style={{ display:'flex', gap:8 }}>
            <button className="btn btn-ghost" style={{ fontSize:'0.83rem' }} onClick={openEdit}>✎ Edit project</button>
            <Link to={`/findings?project_id=${id}`} className="btn btn-ghost" style={{ fontSize:'0.83rem' }}>View all findings →</Link>
          </div>
        </div>

        {/* Edit form inline */}
        {editOpen && form && (
          <div style={{ marginTop:'1.25rem', borderTop:'1px solid var(--border)', paddingTop:'1.25rem' }}>
            <h3 style={{ fontSize:'0.85rem', fontWeight:700, marginBottom:'0.75rem', color:'var(--text-secondary)' }}>Edit Project Settings</h3>
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:10, marginBottom:10 }}>
              <div>
                <label style={{ fontSize:'0.72rem', color:'var(--text-muted)', display:'block', marginBottom:4, textTransform:'uppercase', letterSpacing:'0.06em' }}>Repository URL</label>
                <input value={form.repository_url} onChange={e => setForm(f => ({...f, repository_url: e.target.value}))}
                  placeholder="https://gitlab.com/group/repo" style={{ width:'100%', fontSize:'0.85rem' }} />
              </div>
              <div>
                <label style={{ fontSize:'0.72rem', color:'var(--text-muted)', display:'block', marginBottom:4, textTransform:'uppercase', letterSpacing:'0.06em' }}>Description</label>
                <input value={form.description} onChange={e => setForm(f => ({...f, description: e.target.value}))}
                  placeholder="Project description" style={{ width:'100%', fontSize:'0.85rem' }} />
              </div>
              <div>
                <label style={{ fontSize:'0.72rem', color:'var(--text-muted)', display:'block', marginBottom:4, textTransform:'uppercase', letterSpacing:'0.06em' }}>Git Provider</label>
                <select value={form.git_provider} onChange={e => setForm(f => ({...f, git_provider: e.target.value}))}
                  style={{ width:'100%', fontSize:'0.85rem', padding:'6px 10px' }}>
                  {GIT_PROVIDERS.map(p => <option key={p} value={p}>{p}</option>)}
                </select>
              </div>
              <div>
                <label style={{ fontSize:'0.72rem', color:'var(--text-muted)', display:'block', marginBottom:4, textTransform:'uppercase', letterSpacing:'0.06em' }}>Default Branch</label>
                <input value={form.default_branch} onChange={e => setForm(f => ({...f, default_branch: e.target.value}))}
                  placeholder="main" style={{ width:'100%', fontSize:'0.85rem' }} />
              </div>
            </div>
            <div style={{ display:'flex', gap:8 }}>
              <button className="btn btn-primary" disabled={saveMutation.isPending} onClick={() => saveMutation.mutate(form)}>
                {saveMutation.isPending ? 'Saving…' : 'Save'}
              </button>
              <button className="btn btn-ghost" onClick={() => setEditOpen(false)}>Cancel</button>
            </div>
            <p style={{ fontSize:'0.75rem', color:'var(--text-muted)', marginTop:8 }}>
              💡 The Repository URL + Git Provider + Branch are used to generate direct links to source files in finding details.
            </p>
          </div>
        )}

        {/* Stats */}
        <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:'1rem', marginTop:'1.25rem' }}>
          <StatCard label="Open"     value={project.open_findings}  color="var(--accent)"         />
          <StatCard label="Critical" value={project.critical_count} color="var(--critical)"        />
          <StatCard label="Total"    value={project.findings_count} color="var(--text-secondary)"  />
          <StatCard label="Scans"    value={scans?.length || 0}     color="var(--text-secondary)"  />
        </div>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:'1.25rem' }}>
        {/* Scan history */}
        <div className="card">
          <h3 style={{ fontSize:'0.8rem', fontWeight:700, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.1em', marginBottom:'1rem' }}>Scan History</h3>
          {!scans?.length ? (
            <p style={{ color:'var(--text-muted)', fontSize:'0.85rem' }}>No scans yet</p>
          ) : scans.map(s => (
            <div key={s.id} style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'0.6rem 0', borderBottom:'1px solid var(--border)' }}>
              <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                <span style={{ fontSize:'1.1rem' }}>{SOURCE_ICON[s.source] || '🔍'}</span>
                <div>
                  <div style={{ fontSize:'0.83rem', fontWeight:600, fontFamily:'var(--font-mono)', color:'var(--text-secondary)' }}>{s.source}</div>
                  {(s.branch || s.commit_sha) && (
                    <div style={{ fontSize:'0.7rem', color:'var(--text-muted)', fontFamily:'var(--font-mono)' }}>
                      {s.branch && `⎇ ${s.branch}`}{s.commit_sha && ` · ${s.commit_sha.slice(0,8)}`}
                    </div>
                  )}
                </div>
              </div>
              <div style={{ textAlign:'right' }}>
                <div style={{ fontSize:'0.83rem', fontWeight:700, color: s.findings_count > 0 ? 'var(--high)' : 'var(--low)' }}>{s.findings_count} findings</div>
                <div style={{ fontSize:'0.7rem', color:'var(--text-muted)', fontFamily:'var(--font-mono)' }}>{format(new Date(s.scan_date), 'yyyy-MM-dd HH:mm')}</div>
              </div>
            </div>
          ))}
        </div>

        {/* Recent findings */}
        <div className="card">
          <h3 style={{ fontSize:'0.8rem', fontWeight:700, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.1em', marginBottom:'1rem' }}>Recent Findings</h3>
          {!findings?.items?.length ? (
            <p style={{ color:'var(--text-muted)', fontSize:'0.85rem' }}>No findings</p>
          ) : findings.items.slice(0,8).map(f => (
            <Link key={f.id} to={`/findings/${f.short_id || f.id}`} style={{ display:'flex', alignItems:'center', gap:10, padding:'0.55rem 0', borderBottom:'1px solid var(--border)', textDecoration:'none' }}>
              <span className={`badge badge-${f.severity}`} style={{ flexShrink:0 }}>{f.severity.slice(0,4)}</span>
              <span style={{ fontSize:'0.82rem', color:'var(--text-secondary)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', flex:1 }}>{f.title}</span>
            </Link>
          ))}
        </div>
      </div>
    </div>
  )
}

const StatCard = ({ label, value, color }) => (
  <div style={{ background:'var(--bg-elevated)', borderRadius:8, padding:12, textAlign:'center' }}>
    <div style={{ fontSize:'1.5rem', fontWeight:800, color, fontFamily:'var(--font-mono)' }}>{value}</div>
    <div style={{ fontSize:'0.7rem', color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.08em', marginTop:2 }}>{label}</div>
  </div>
)

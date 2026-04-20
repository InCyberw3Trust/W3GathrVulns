import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { fetchProjects, createProject, deleteProject, exportProjects, importProjects } from '../api/client.js'
import toast from 'react-hot-toast'

export default function Projects() {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ name:'', description:'', repository_url:'' })

  const { data: projects, isPending } = useQuery({ queryKey: ['projects'], queryFn: fetchProjects })

  const createMutation = useMutation({
    mutationFn: createProject,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['projects'] }); setShowForm(false); setForm({ name:'', description:'', repository_url:'' }); toast.success('Project created') },
    onError: (e) => toast.error(e?.response?.data?.detail || 'Failed to create'),
  })

  const deleteMutation = useMutation({
    mutationFn: deleteProject,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['projects'] }); toast.success('Deleted') },
  })

  const totalFindings = projects?.reduce((a, p) => a + (p.findings_count || 0), 0) || 0
  const totalCritical = projects?.reduce((a, p) => a + (p.critical_count || 0), 0) || 0

  return (
    <div className="animate-in" style={{ display:'flex', flexDirection:'column', gap:'1.25rem' }}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-end' }}>
        <div>
          <h1 style={{ fontSize:'1.6rem', fontWeight:800, letterSpacing:'-0.03em' }}>Projects</h1>
          <p style={{ color:'var(--text-secondary)', fontSize:'0.85rem', marginTop:4 }}>
            {projects?.length || 0} projects · {totalFindings.toLocaleString()} findings · {totalCritical} critical
          </p>
        </div>
        <div style={{ display:'flex', gap:8 }}>
        <button className="btn btn-ghost" style={{ fontSize:'0.82rem' }} onClick={async () => {
          const data = await exportProjects()
          const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
          const a = document.createElement('a'); a.href = URL.createObjectURL(blob)
          a.download = 'w3gathrvulns-projects.json'; a.click()
        }}>↓ Export</button>
        <label className="btn btn-ghost" style={{ fontSize:'0.82rem', cursor:'pointer' }}>
          ↑ Import
          <input type="file" accept=".json" style={{ display:'none' }} onChange={async e => {
            const file = e.target.files[0]; if (!file) return
            try {
              const text = await file.text()
              const res = await importProjects(JSON.parse(text))
              qc.invalidateQueries({ queryKey: ['projects'] })
              toast.success(`Imported: ${res.created} created, ${res.skipped} skipped`)
            } catch { toast.error('Import failed — check JSON format') }
            e.target.value = ''
          }} />
        </label>
        <button className="btn btn-primary" onClick={() => setShowForm(s => !s)}>
          {showForm ? 'Cancel' : '+ New Project'}
        </button>
      </div>
      </div>

      {showForm && (
        <div className="card animate-in">
          <h3 style={{ fontSize:'0.9rem', fontWeight:700, marginBottom:'1rem' }}>Create Project</h3>
          <div style={{ display:'flex', flexDirection:'column', gap:10 }}>
            <input placeholder="Project name *" value={form.name} onChange={e => setForm(f => ({...f, name:e.target.value}))} style={{ fontSize:'0.9rem' }} />
            <input placeholder="Description" value={form.description} onChange={e => setForm(f => ({...f, description:e.target.value}))} style={{ fontSize:'0.9rem' }} />
            <input placeholder="Repository URL" value={form.repository_url} onChange={e => setForm(f => ({...f, repository_url:e.target.value}))} style={{ fontSize:'0.9rem' }} />
            <button className="btn btn-primary" style={{ width:'fit-content' }}
              disabled={!form.name || createMutation.isPending}
              onClick={() => createMutation.mutate(form)}>
              {createMutation.isPending ? 'Creating…' : 'Create'}
            </button>
          </div>
        </div>
      )}

      {isPending ? (
        <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(280px,1fr))', gap:'1rem' }}>
          {[...Array(6)].map((_,i) => <div key={i} style={{ height:140, background:'var(--bg-surface)', borderRadius:12, border:'1px solid var(--border)' }} />)}
        </div>
      ) : !projects?.length ? (
        <div className="card" style={{ textAlign:'center', padding:'3rem' }}>
          <div style={{ fontSize:'2.5rem', marginBottom:12 }}>📂</div>
          <p style={{ color:'var(--text-secondary)', fontWeight:600 }}>No projects yet</p>
          <p style={{ color:'var(--text-muted)', fontSize:'0.83rem', marginTop:6 }}>Create a project or push a scan from your CI/CD pipeline</p>
        </div>
      ) : (
        <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(280px,1fr))', gap:'1rem' }}>
          {projects.map(p => (
            <ProjectCard key={p.id} project={p}
              onOpen={() => navigate(`/projects/${p.id}`)}
              onDelete={() => { if (window.confirm(`Delete ${p.name}?`)) deleteMutation.mutate(p.id) }} />
          ))}
        </div>
      )}
    </div>
  )
}

function ProjectCard({ project: p, onOpen, onDelete }) {
  const riskColor = p.critical_count > 0 ? 'var(--critical)' : p.open_findings > 10 ? 'var(--high)' : p.open_findings > 0 ? 'var(--medium)' : 'var(--low)'
  return (
    <div className="card" style={{ cursor:'pointer', transition:'border-color 0.15s', position:'relative' }}
      onClick={onOpen}
      onMouseEnter={e => e.currentTarget.style.borderColor = 'var(--border-light)'}
      onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--border)'}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:12 }}>
        <div style={{ flex:1, minWidth:0 }}>
          <h3 style={{ fontSize:'0.95rem', fontWeight:700, marginBottom:4, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{p.name}</h3>
          {p.description && <p style={{ fontSize:'0.78rem', color:'var(--text-muted)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{p.description}</p>}
        </div>
        <button onClick={e => { e.stopPropagation(); onDelete() }}
          style={{ background:'transparent', color:'var(--text-muted)', fontSize:'0.85rem', padding:'2px 6px', borderRadius:4, flexShrink:0, transition:'color 0.15s' }}
          onMouseEnter={e => e.target.style.color='var(--critical)'} onMouseLeave={e => e.target.style.color='var(--text-muted)'}>✕</button>
      </div>
      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:8, marginBottom:12 }}>
        <StatMini label="Open"     value={p.open_findings}  color="var(--accent)"    />
        <StatMini label="Critical" value={p.critical_count} color="var(--critical)"  />
        <StatMini label="Total"    value={p.findings_count} color="var(--text-muted)" />
      </div>
      <div style={{ height:3, background:'var(--bg-overlay)', borderRadius:2, overflow:'hidden' }}>
        <div style={{ height:'100%', borderRadius:2, background:riskColor,
          width: p.findings_count > 0 ? `${Math.min(100,(p.open_findings/Math.max(p.findings_count,1))*100)}%` : '0%',
          transition:'width 0.4s ease' }} />
      </div>
    </div>
  )
}

const StatMini = ({ label, value, color }) => (
  <div>
    <div style={{ fontSize:'1.1rem', fontWeight:800, fontFamily:'var(--font-mono)', color }}>{value}</div>
    <div style={{ fontSize:'0.68rem', color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.06em' }}>{label}</div>
  </div>
)

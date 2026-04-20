import React, { useState } from 'react';

const BASE = window.location.origin + '/api/v1';

const TOOLS = [
  {
    id: 'trivy',
    name: 'Trivy',
    icon: '🐳',
    color: '#38bdf8',
    endpoint: 'POST /api/v1/ingest/trivy',
    desc: 'Container image & filesystem scanning (vulnerabilities, misconfigs, secrets)',
    gitlab: `trivy-scan:
  stage: scan
  image: aquasec/trivy:latest
  script:
    - trivy image --format json --output trivy-results.json $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
    - |
      curl -s -X POST "${BASE}/ingest/trivy?project=$CI_PROJECT_NAME&branch=$CI_COMMIT_REF_NAME&commit=$CI_COMMIT_SHA&pipeline=$CI_PIPELINE_ID" \\
        -H "Content-Type: application/json" \\
        -d @trivy-results.json
  artifacts:
    paths: [trivy-results.json]`,
    curl: `# Trivy image scan
trivy image --format json --output results.json myimage:latest
curl -X POST "${BASE}/ingest/trivy?project=my-project&branch=main" \\
  -H "Content-Type: application/json" \\
  -d @results.json`,
  },
  {
    id: 'gitlab-sast',
    name: 'GitLab SAST (Semgrep)',
    icon: '🔬',
    color: '#f97316',
    endpoint: 'POST /api/v1/ingest/gitlab-sast',
    desc: 'GitLab SAST report from gl-sast-report.json',
    gitlab: `# Add to your .gitlab-ci.yml
include:
  - template: Security/SAST.gitlab-ci.yml

upload-sast:
  stage: .post
  script:
    - |
      curl -s -X POST "${BASE}/ingest/gitlab-sast?project=$CI_PROJECT_NAME&branch=$CI_COMMIT_REF_NAME&commit=$CI_COMMIT_SHA&pipeline=$CI_PIPELINE_ID" \\
        -H "Content-Type: application/json" \\
        -d @gl-sast-report.json
  dependencies: [semgrep-sast]`,
    curl: `curl -X POST "${BASE}/ingest/gitlab-sast?project=my-project&branch=main" \\
  -H "Content-Type: application/json" \\
  -d @gl-sast-report.json`,
  },
  {
    id: 'gitlab-iac',
    name: 'GitLab IaC Scanning',
    icon: '☁️',
    color: '#a855f7',
    endpoint: 'POST /api/v1/ingest/gitlab-iac',
    desc: 'GitLab IaC scanning report (Terraform, Kubernetes, Dockerfile)',
    gitlab: `include:
  - template: Security/SAST-IaC.gitlab-ci.yml

upload-iac:
  stage: .post
  script:
    - |
      curl -s -X POST "${BASE}/ingest/gitlab-iac?project=$CI_PROJECT_NAME&branch=$CI_COMMIT_REF_NAME&pipeline=$CI_PIPELINE_ID" \\
        -H "Content-Type: application/json" \\
        -d @gl-sast-report.json
  dependencies: [kics-iac-sast]`,
    curl: `curl -X POST "${BASE}/ingest/gitlab-iac?project=my-project&branch=main" \\
  -H "Content-Type: application/json" \\
  -d @gl-iac-report.json`,
  },
  {
    id: 'gitlab-secrets',
    name: 'GitLab Secret Detection',
    icon: '🔑',
    color: '#eab308',
    endpoint: 'POST /api/v1/ingest/gitlab-secrets',
    desc: 'GitLab secret detection report (API keys, tokens, passwords)',
    gitlab: `include:
  - template: Security/Secret-Detection.gitlab-ci.yml

upload-secrets:
  stage: .post
  script:
    - |
      curl -s -X POST "${BASE}/ingest/gitlab-secrets?project=$CI_PROJECT_NAME&branch=$CI_COMMIT_REF_NAME&pipeline=$CI_PIPELINE_ID" \\
        -H "Content-Type: application/json" \\
        -d @gl-secret-detection-report.json
  dependencies: [secret-detection]`,
    curl: `curl -X POST "${BASE}/ingest/gitlab-secrets?project=my-project" \\
  -H "Content-Type: application/json" \\
  -d @gl-secret-detection-report.json`,
  },
  {
    id: 'owasp',
    name: 'OWASP ZAP',
    icon: '🕷️',
    color: '#f43f5e',
    endpoint: 'POST /api/v1/ingest/owasp-zap',
    desc: 'OWASP ZAP DAST scan (active/passive web scanning)',
    gitlab: `owasp-zap:
  stage: scan
  image: ghcr.io/zaproxy/zaproxy:stable
  script:
    - mkdir -p /zap/wrk
    - zap-baseline.py -t $APP_URL -J zap-report.json || true
    - |
      curl -s -X POST "${BASE}/ingest/owasp-zap?project=$CI_PROJECT_NAME&branch=$CI_COMMIT_REF_NAME&pipeline=$CI_PIPELINE_ID" \\
        -H "Content-Type: application/json" \\
        -d @/zap/wrk/zap-report.json`,
    curl: `# Run ZAP baseline scan
docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \\
  -t https://target.example.com -J /tmp/report.json
curl -X POST "${BASE}/ingest/owasp-zap?project=my-app" \\
  -H "Content-Type: application/json" \\
  -d @/tmp/report.json`,
  },
  {
    id: 'nuclei',
    name: 'Nuclei',
    icon: '⚡',
    color: '#22c55e',
    endpoint: 'POST /api/v1/ingest/nuclei',
    desc: 'Nuclei template-based vulnerability scanner',
    gitlab: `nuclei-scan:
  stage: scan
  image: projectdiscovery/nuclei:latest
  script:
    - nuclei -u $APP_URL -json -o nuclei-results.json -severity critical,high,medium || true
    - |
      curl -s -X POST "${BASE}/ingest/nuclei?project=$CI_PROJECT_NAME&branch=$CI_COMMIT_REF_NAME&pipeline=$CI_PIPELINE_ID" \\
        -H "Content-Type: application/json" \\
        -d "[$(cat nuclei-results.json | tr '\\n' ',' | sed 's/,$//'  )]"`,
    curl: `# Nuclei outputs JSONL — wrap in array
# Run scan (JSONL output, one JSON object per line)
nuclei -u https://target.com -jsonl -o results.jsonl

# Convert JSONL → JSON array  ← use jq -s '.' (NOT '{payload:.}')
jq -s '{payload: .}' results.jsonl > results.json

curl -k -X POST "${BASE}/ingest/nuclei?project=my-app" \\
  -H "Content-Type: application/json" \\
  -d @results.json`,
  },
];

export default function Docs() {
  const [active, setActive] = useState('trivy');
  const [tab, setTab] = useState('gitlab');

  const tool = TOOLS.find(t => t.id === active);

  return (
    <div className="animate-in" style={{ display:'flex', flexDirection:'column', gap:'1.25rem' }}>
      <div>
        <h1 style={{ fontSize:'1.6rem', fontWeight:800, letterSpacing:'-0.03em' }}>API Integration</h1>
        <p style={{ color:'var(--text-secondary)', fontSize:'0.85rem', marginTop:4 }}>
          Push scan results from your CI/CD pipelines to W3GathrVulns
        </p>
      </div>

      {/* Query params doc */}
      <div className="card" style={{ borderLeft:'3px solid var(--accent)' }}>
        <h3 style={{ fontSize:'0.8rem', fontWeight:700, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.1em', marginBottom:'0.75rem' }}>
          Common Query Parameters
        </h3>
        <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(200px, 1fr))', gap:'0.75rem' }}>
          {[
            { name:'project', req:true,  desc:'Project name (auto-created if new)' },
            { name:'branch',  req:false, desc:'Git branch name' },
            { name:'commit',  req:false, desc:'Git commit SHA' },
            { name:'pipeline',req:false, desc:'CI/CD pipeline ID' },
            { name:'repo_url',req:false, desc:'Repository URL' },
          ].map(p => (
            <div key={p.name} style={{ display:'flex', flexDirection:'column', gap:4 }}>
              <div style={{ display:'flex', alignItems:'center', gap:6 }}>
                <code style={{ fontFamily:'var(--font-mono)', fontSize:'0.8rem', color:'var(--accent)' }}>{p.name}</code>
                {p.req && <span style={{ fontSize:'0.65rem', color:'var(--critical)', fontWeight:700, background:'var(--critical-bg)', padding:'1px 5px', borderRadius:3 }}>required</span>}
              </div>
              <span style={{ fontSize:'0.78rem', color:'var(--text-muted)' }}>{p.desc}</span>
            </div>
          ))}
        </div>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'200px 1fr', gap:'1.25rem' }}>
        {/* Tool selector */}
        <div className="card" style={{ padding:'0.5rem', height:'fit-content' }}>
          {TOOLS.map(t => (
            <button key={t.id} onClick={() => setActive(t.id)} style={{
              display:'flex', alignItems:'center', gap:8, width:'100%',
              padding:'0.6rem 0.75rem', borderRadius:6, textAlign:'left',
              background: active === t.id ? 'var(--bg-overlay)' : 'transparent',
              color: active === t.id ? 'var(--text-primary)' : 'var(--text-muted)',
              border: active === t.id ? `1px solid ${t.color}44` : '1px solid transparent',
              fontSize:'0.83rem', fontWeight:600, transition:'all 0.15s',
            }}>
              <span>{t.icon}</span>
              <span>{t.name}</span>
            </button>
          ))}
        </div>

        {/* Tool detail */}
        {tool && (
          <div style={{ display:'flex', flexDirection:'column', gap:'1rem' }}>
            <div className="card" style={{ borderLeft:`3px solid ${tool.color}` }}>
              <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:8 }}>
                <span style={{ fontSize:'1.5rem' }}>{tool.icon}</span>
                <h2 style={{ fontSize:'1.1rem', fontWeight:700 }}>{tool.name}</h2>
              </div>
              <p style={{ color:'var(--text-secondary)', fontSize:'0.88rem', marginBottom:10 }}>{tool.desc}</p>
              <code style={{ fontFamily:'var(--font-mono)', fontSize:'0.8rem', color:'var(--accent)', background:'var(--bg-elevated)', padding:'4px 10px', borderRadius:4, display:'inline-block' }}>
                {tool.endpoint}
              </code>
            </div>

            {/* Code tabs */}
            <div className="card" style={{ padding:0, overflow:'hidden' }}>
              <div style={{ display:'flex', borderBottom:'1px solid var(--border)' }}>
                {[['gitlab','GitLab CI'],['curl','curl / shell']].map(([id, label]) => (
                  <button key={id} onClick={() => setTab(id)} style={{
                    padding:'0.7rem 1.25rem', fontSize:'0.82rem', fontWeight:600,
                    background: tab === id ? 'var(--bg-elevated)' : 'transparent',
                    color: tab === id ? 'var(--text-primary)' : 'var(--text-muted)',
                    borderBottom: tab === id ? `2px solid ${tool.color}` : '2px solid transparent',
                    transition:'all 0.15s',
                  }}>{label}</button>
                ))}
              </div>
              <pre style={{
                padding:'1.25rem', margin:0, overflowX:'auto',
                fontFamily:'var(--font-mono)', fontSize:'0.78rem',
                color:'var(--text-secondary)', lineHeight:1.7,
                background:'var(--bg-elevated)',
              }}>
                <code>{tab === 'gitlab' ? tool.gitlab : tool.curl}</code>
              </pre>
              <div style={{ padding:'0.75rem 1.25rem', borderTop:'1px solid var(--border)', background:'var(--bg-surface)' }}>
                <button className="btn btn-ghost" style={{ fontSize:'0.75rem', padding:'3px 10px' }}
                  onClick={() => { navigator.clipboard.writeText(tab === 'gitlab' ? tool.gitlab : tool.curl); }}>
                  📋 Copy
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* API reference link */}
      <div className="card" style={{ display:'flex', justifyContent:'space-between', alignItems:'center' }}>
        <div>
          <p style={{ fontWeight:600, fontSize:'0.9rem' }}>Full API Reference</p>
          <p style={{ fontSize:'0.8rem', color:'var(--text-muted)', marginTop:2 }}>Interactive docs with request/response schemas</p>
        </div>
        <a href="/api/docs" target="_blank" rel="noreferrer" className="btn btn-primary">
          Open Swagger UI →
        </a>
      </div>
    </div>
  );
}

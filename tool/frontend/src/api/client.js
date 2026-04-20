import axios from 'axios'

const BASE = '/api/v1'
const TOKEN_KEY = 'w3g_token'

export const api = axios.create({
  baseURL: BASE,
  paramsSerializer: {
    serialize: (params) => {
      const parts = []
      for (const [key, value] of Object.entries(params)) {
        if (value === undefined || value === null) continue
        if (Array.isArray(value)) {
          for (const v of value) parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(v)}`)
        } else {
          parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
        }
      }
      return parts.join('&')
    },
  },
})

// Attach JWT to every request
api.interceptors.request.use(config => {
  const token = localStorage.getItem(TOKEN_KEY)
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// On 401: clear token and redirect to /login
api.interceptors.response.use(
  res => res,
  err => {
    if (err.response?.status === 401) {
      localStorage.removeItem(TOKEN_KEY)
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

// ── Stats ─────────────────────────────────────────────────────
export const fetchDashboard = (params = {}) => api.get('/stats/dashboard', { params }).then(r => r.data)

// ── Findings ──────────────────────────────────────────────────
export const fetchFindings     = (params) => api.get('/findings', { params }).then(r => r.data)
export const fetchFinding      = (id)     => api.get(`/findings/${id}`).then(r => r.data)
export const updateFinding     = (id, data) => api.patch(`/findings/${id}`, data).then(r => r.data)
export const batchUpdateFindings = (data) => api.patch('/findings/batch', data).then(r => r.data)
export const deleteFinding     = (id)     => api.delete(`/findings/${id}`)

// ── Projects ──────────────────────────────────────────────────
export const fetchProjects      = ()     => api.get('/projects').then(r => r.data)
export const fetchProject       = (id)   => api.get(`/projects/${id}`).then(r => r.data)
export const fetchProjectScans  = (id)   => api.get(`/projects/${id}/scans`).then(r => r.data)
export const createProject      = (data) => api.post('/projects', data).then(r => r.data)
export const updateProject      = (id, data) => api.patch(`/projects/${id}`, data).then(r => r.data)
export const deleteProject      = (id)   => api.delete(`/projects/${id}`)

// ── Rules ─────────────────────────────────────────────────────
export const fetchRules      = ()         => api.get('/rules').then(r => r.data)
export const fetchRule        = (id)      => api.get(`/rules/${id}`).then(r => r.data)
export const createRule       = (data)    => api.post('/rules', data).then(r => r.data)
export const updateRule       = (id, data) => api.patch(`/rules/${id}`, data).then(r => r.data)
export const deleteRule       = (id)      => api.delete(`/rules/${id}`)
export const testRule         = (id)      => api.post(`/rules/${id}/test`).then(r => r.data)
export const simulateRule     = (id)      => api.post(`/rules/${id}/simulate`).then(r => r.data)
export const applySingleRule  = (id)      => api.post(`/rules/${id}/apply`).then(r => r.data)
export const applyAllRules    = ()        => api.post('/rules/apply-all').then(r => r.data)

// ── Export ────────────────────────────────────────────────────
export const exportFile = async (format, params = {}) => {
  const res = await api.get(`/export/${format}`, { params, responseType: 'blob' })
  const ext = format === 'pdf' ? 'pdf' : 'csv'
  const objUrl = URL.createObjectURL(res.data)
  const a = document.createElement('a')
  a.href = objUrl
  a.download = `findings.${ext}`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(objUrl)
}

// ── Debug / Ingest ────────────────────────────────────────────────────────────
export const ingestSample   = (tool, payload, params) =>
  api.post(`/ingest/${tool}`, payload, { params }).then(r => r.data)
export const deleteProjectByName = async (name) => {
  const projects = await api.get('/projects').then(r => r.data)
  const p = projects.find(x => x.name === name)
  if (p) return api.delete(`/projects/${p.id}`)
}

// ── Settings ──────────────────────────────────────────────────────────────────
export const fetchTokens        = ()     => api.get('/settings/tokens').then(r => r.data)
export const regenerateToken    = (type) => api.post('/settings/regenerate-token', { token_type: type }).then(r => r.data)
export const changePassword     = (data) => api.post('/settings/change-password', data).then(r => r.data)

// ── App config (public) ───────────────────────────────────────────────────────
export const fetchAppConfig = () => api.get('/app-config').then(r => r.data)

// ── Import / Export ───────────────────────────────────────────────────────────
export const exportProjects = () =>
  api.get('/projects/export').then(r => r.data)
export const importProjects = (data) =>
  api.post('/projects/import', data).then(r => r.data)
export const exportRules = () =>
  api.get('/rules/export').then(r => r.data)
export const importRules = (data) =>
  api.post('/rules/import', data).then(r => r.data)

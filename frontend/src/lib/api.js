import axios from 'axios'

const api = axios.create({ baseURL: '/api' })

export const getRuns = (params) => api.get('/runs', { params })
export const getRun = (id) => api.get(`/runs/${id}`)
export const createRun = (data) => api.post('/runs', data)
export const cancelRun = (id) => api.post(`/runs/${id}/cancel`)
export const relaunchRun = (id) => api.post(`/runs/${id}/relaunch`)
export const getRunStages = (id) => api.get(`/runs/${id}/stages`)
export const getRunFindings = (id, params) => api.get(`/runs/${id}/findings`, { params })
export const getRunTickets = (id) => api.get(`/runs/${id}/tickets`)
export const getReleaseNotes = (id) => api.get(`/runs/${id}/release-notes`)

export const getProjects = () => api.get('/projects')
export const createProject = (data) => api.post('/projects', data)
export const deleteProject = (id) => api.delete(`/projects/${id}`)

export const getPolicies = () => api.get('/policies')
export const getPolicy = (id) => api.get(`/policies/${id}`)
export const createPolicy = (data) => api.post('/policies', data)
export const updatePolicy = (id, data) => api.put(`/policies/${id}`, data)
export const deletePolicy = (id) => api.delete(`/policies/${id}`)

export const getTickets = (params) => api.get('/tickets', { params })
export const updateTicket = (id, data) => api.patch(`/tickets/${id}`, data)

export const getStats = () => api.get('/stats')

export const createWsConnection = (runId) => {
  const wsUrl = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws/runs/${runId}`
  return new WebSocket(wsUrl)
}

export const createGlobalWs = () => {
  const wsUrl = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws/global`
  return new WebSocket(wsUrl)
}

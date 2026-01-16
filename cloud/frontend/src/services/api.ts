import axios from 'axios'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const envApiUrl = (import.meta as any).env?.VITE_API_URL ?? ''
const baseUrl = `${envApiUrl}/api/v1`

export const apiClient = axios.create({
  baseURL: baseUrl,
  timeout: 10000
})

// 规则管理 API
export const rulesApi = {
  list: async () => {
    const { data } = await apiClient.get('/rules')
    return data
  },

  get: async (version: string) => {
    const { data } = await apiClient.get(`/rules/${version}`)
    return data
  },

  create: async (payload: { content: string; description: string }) => {
    const { data } = await apiClient.post('/rules', payload)
    return data
  }
}

// 日志查询 API
export const logsApi = {
  query: async (params: {
    start_time?: string
    end_time?: string
    probe_id?: string
    severity?: number
    limit?: number
    offset?: number
  }) => {
    const { data } = await apiClient.get('/logs', { params })
    return data
  },

  stats: async (hours: number = 24) => {
    const { data } = await apiClient.get('/logs/stats', { params: { hours } })
    return data
  }
}

// 探针管理 API
export const probesApi = {
  list: async () => {
    const { data } = await apiClient.get('/probes')
    return data
  },

  get: async (probeId: string) => {
    const { data } = await apiClient.get(`/probes/${probeId}`)
    return data
  }
}

// 仪表盘统计 API
export const dashboardApi = {
  getOverview: async () => {
    const [probesRes, logsStatsRes] = await Promise.all([
      apiClient.get('/probes'),
      apiClient.get('/logs/stats', { params: { hours: 24 } })
    ])
    return {
      probes: probesRes.data,
      stats: logsStatsRes.data
    }
  }
}

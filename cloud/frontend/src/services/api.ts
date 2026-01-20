import axios from 'axios'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const envApiUrl = (import.meta as any).env?.VITE_API_URL ?? ''
// VITE_API_URL 应该是 '' 或完整的 API 前缀如 '/api/v1'
const baseUrl = envApiUrl ? `${envApiUrl}/v1` : '/api/v1'

export const apiClient = axios.create({
  baseURL: baseUrl,
  timeout: 30000  // 增加超时时间以支持大文件下载
})

// ========== 规则下载与更新 API ==========
export const ruleUpdateApi = {
  // 触发规则下载
  triggerDownload: async (force: boolean = false) => {
    const { data } = await apiClient.post('/rules/download', { force })
    return data
  },

  // 获取下载状态
  getDownloadStatus: async () => {
    const { data } = await apiClient.get('/rules/download/status')
    return data
  },

  // 取消下载
  cancelDownload: async () => {
    const { data } = await apiClient.post('/rules/download/cancel')
    return data
  },

  // 获取变更预览
  getPreview: async () => {
    const { data } = await apiClient.get('/rules/preview')
    return data
  },

  // 确认更新
  confirmUpdate: async (applyChanges: boolean, description?: string) => {
    const { data } = await apiClient.post('/rules/update', {
      apply_changes: applyChanges,
      description
    })
    return data
  }
}

// ========== 规则列表与详情 API ==========
export const rulesApi = {
  // 获取规则列表（支持筛选）
  list: async (params?: {
    classtype?: string
    category?: string
    severity?: number
    protocol?: string
    enabled?: boolean
    search?: string
    limit?: number
    offset?: number
  }) => {
    const { data } = await apiClient.get('/rules', { params })
    return data
  },

  // 获取规则详情（按 SID）
  getBySid: async (sid: number) => {
    const { data } = await apiClient.get(`/rules/${sid}`)
    return data
  },

  // 切换规则启用状态
  toggle: async (sid: number, enabled: boolean) => {
    const { data } = await apiClient.put(`/rules/${sid}/toggle`, null, {
      params: { enabled }
    })
    return data
  },

  // 获取规则分类统计
  getCategories: async () => {
    const { data } = await apiClient.get('/rules/categories')
    return data
  },

  // 获取规则版本列表
  getVersions: async (limit: number = 20, offset: number = 0) => {
    const { data } = await apiClient.get('/rules/versions', {
      params: { limit, offset }
    })
    return data
  },

  // 获取最新规则版本
  getLatest: async () => {
    const { data } = await apiClient.get('/rules/latest')
    return data
  },

  // 获取指定版本规则
  getByVersion: async (version: string) => {
    const { data } = await apiClient.get(`/rules/version/${version}`)
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

// ========== 攻击测试 API ==========
export const attacksApi = {
  // 创建测试
  createTest: async (data: {
    name?: string
    rule_sids: number[]
    probe_id: string
    config?: Record<string, unknown>
  }) => {
    const { data: result } = await apiClient.post('/attacks/tests', data)
    return result
  },

  // 获取测试列表
  listTests: async (params?: {
    status?: string
    probe_id?: string
    limit?: number
    offset?: number
  }) => {
    const { data } = await apiClient.get('/attacks/tests', { params })
    return data
  },

  // 获取测试详情
  getTest: async (testId: string) => {
    const { data } = await apiClient.get(`/attacks/tests/${testId}`)
    return data
  },

  // 启动测试
  startTest: async (testId: string) => {
    const { data } = await apiClient.post(`/attacks/tests/${testId}/start`)
    return data
  },

  // 取消测试
  cancelTest: async (testId: string) => {
    const { data } = await apiClient.post(`/attacks/tests/${testId}/cancel`)
    return data
  },

  // 获取测试项列表
  getTestItems: async (testId: string, params?: {
    status?: string
    limit?: number
    offset?: number
  }) => {
    const { data } = await apiClient.get(`/attacks/tests/${testId}/items`, { params })
    return data
  },

  // 获取攻击模板列表
  listTemplates: async (params?: {
    protocol?: string
    attack_type?: string
  }) => {
    const { data } = await apiClient.get('/attacks/templates', { params })
    return data
  },

  // 创建攻击模板
  createTemplate: async (data: {
    name: string
    attack_type: string
    protocol?: string
    template_config?: Record<string, unknown>
    description?: string
    classtype?: string
  }) => {
    const { data: result } = await apiClient.post('/attacks/templates', data)
    return result
  }
}

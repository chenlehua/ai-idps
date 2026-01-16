import { useState, useCallback, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useWebSocket } from '../../hooks/useWebSocket'
import { logsApi, probesApi } from '../../services/api'

interface LogEntry {
  id?: string
  node_id?: string
  probe_id?: string
  instance_id?: string
  probe_type?: string
  timestamp?: string
  src_ip?: string
  dest_ip?: string
  src_port?: number
  dest_port?: number
  protocol?: string
  alert_msg?: string
  signature_id?: number
  severity?: number
  category?: string
}

interface LogFilters {
  probe_id?: string
  severity?: number[]
  probe_type?: string
}

const SEVERITY_CONFIG: Record<number, { label: string; color: string; bg: string }> = {
  1: { label: '严重', color: 'text-white', bg: 'bg-red-600' },
  2: { label: '高', color: 'text-white', bg: 'bg-orange-500' },
  3: { label: '中', color: 'text-gray-900', bg: 'bg-yellow-400' },
  4: { label: '低', color: 'text-white', bg: 'bg-green-500' }
}

export default function LogsPage() {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [filters, setFilters] = useState<LogFilters>({})
  const [isPaused, setIsPaused] = useState(false)
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null)
  const [viewMode, setViewMode] = useState<'realtime' | 'history'>('realtime')
  
  // 历史日志查询参数
  const [historyParams, setHistoryParams] = useState({
    limit: 100,
    offset: 0,
    severity: undefined as number | undefined,
    probe_id: undefined as string | undefined
  })

  // 获取探针列表用于过滤
  const { data: probesData } = useQuery({
    queryKey: ['probes'],
    queryFn: () => probesApi.list()
  })

  // 历史日志查询
  const { data: historyData, isLoading: historyLoading, refetch: refetchHistory } = useQuery({
    queryKey: ['logs-history', historyParams],
    queryFn: () => logsApi.query(historyParams),
    enabled: viewMode === 'history'
  })

  // WebSocket 消息处理
  const handleMessage = useCallback((data: any) => {
    if (data.event === 'log' && !isPaused) {
      setLogs(prev => {
        const newLog = {
          ...data.data,
          id: data.data.id || `${Date.now()}-${Math.random()}`
        }
        return [newLog, ...prev].slice(0, 500) // 保留最新500条
      })
    }
  }, [isPaused])

  // WebSocket URL - 使用当前页面的 host
  const wsUrl = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/api/v1/ws/logs`

  const { isConnected, subscribe } = useWebSocket({
    url: wsUrl,
    onMessage: handleMessage,
    onConnect: () => {
      console.log('WebSocket connected')
      subscribe(filters)
    }
  })

  // 当过滤器变化时重新订阅
  useEffect(() => {
    if (isConnected) {
      subscribe(filters)
    }
  }, [filters, isConnected, subscribe])

  const handleFilterChange = (key: string, value: any) => {
    const newFilters = { ...filters, [key]: value || undefined }
    setFilters(newFilters)
    
    if (viewMode === 'history') {
      setHistoryParams(prev => ({ ...prev, [key]: value || undefined }))
    }
  }

  const clearLogs = () => {
    setLogs([])
  }

  const getSeverityBadge = (severity: number | undefined) => {
    const config = severity ? SEVERITY_CONFIG[severity] : SEVERITY_CONFIG[4]
    return (
      <span className={`inline-flex rounded px-2 py-0.5 text-xs font-medium ${config?.bg || 'bg-gray-400'} ${config?.color || 'text-white'}`}>
        {config?.label || severity || '未知'}
      </span>
    )
  }

  const probes = probesData?.probes || []
  const displayLogs = viewMode === 'realtime' ? logs : (historyData?.logs || [])

  return (
    <div className="space-y-4">
      {/* 头部 */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h1 className="text-2xl font-semibold">日志展示</h1>
        <div className="flex items-center gap-3">
          {/* 连接状态 */}
          <div className="flex items-center gap-2 text-sm">
            <span
              className={`h-2.5 w-2.5 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`}
            />
            <span className="text-gray-600">
              {isConnected ? 'WebSocket 已连接' : 'WebSocket 未连接'}
            </span>
          </div>

          {/* 视图切换 */}
          <div className="flex rounded-lg border">
            <button
              onClick={() => setViewMode('realtime')}
              className={`px-3 py-1.5 text-sm ${viewMode === 'realtime' ? 'bg-blue-600 text-white' : 'text-gray-600 hover:bg-gray-100'}`}
            >
              实时
            </button>
            <button
              onClick={() => {
                setViewMode('history')
                refetchHistory()
              }}
              className={`px-3 py-1.5 text-sm ${viewMode === 'history' ? 'bg-blue-600 text-white' : 'text-gray-600 hover:bg-gray-100'}`}
            >
              历史
            </button>
          </div>
        </div>
      </div>

      {/* 过滤器和控制栏 */}
      <div className="flex flex-wrap items-center gap-3 rounded-lg border bg-white p-4 shadow-sm">
        {/* 严重级别筛选 */}
        <select
          className="rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none"
          onChange={(e) => handleFilterChange('severity', e.target.value ? parseInt(e.target.value) : undefined)}
        >
          <option value="">所有级别</option>
          <option value="1">严重 (1)</option>
          <option value="2">高 (2)</option>
          <option value="3">中 (3)</option>
          <option value="4">低 (4)</option>
        </select>

        {/* 探针筛选 */}
        <select
          className="rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none"
          onChange={(e) => handleFilterChange('probe_id', e.target.value)}
        >
          <option value="">所有探针</option>
          {probes.map((probe: any) => (
            <option key={probe.node_id} value={probe.node_id}>
              {probe.name} ({probe.node_id})
            </option>
          ))}
        </select>

        <div className="flex-1" />

        {/* 实时模式控制 */}
        {viewMode === 'realtime' && (
          <>
            <button
              onClick={() => setIsPaused(!isPaused)}
              className={`rounded-lg px-4 py-2 text-sm text-white ${isPaused ? 'bg-green-600 hover:bg-green-700' : 'bg-yellow-500 hover:bg-yellow-600'}`}
            >
              {isPaused ? '继续' : '暂停'}
            </button>
            <button
              onClick={clearLogs}
              className="rounded-lg bg-gray-500 px-4 py-2 text-sm text-white hover:bg-gray-600"
            >
              清空
            </button>
          </>
        )}

        {/* 历史模式刷新 */}
        {viewMode === 'history' && (
          <button
            onClick={() => refetchHistory()}
            disabled={historyLoading}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700 disabled:opacity-50"
          >
            {historyLoading ? '加载中...' : '刷新'}
          </button>
        )}

        <span className="text-sm text-gray-500">
          共 {displayLogs.length} 条
        </span>
      </div>

      {/* 日志表格 */}
      <div className="overflow-hidden rounded-lg border bg-white shadow-sm">
        <div className="overflow-x-auto">
          <table className="min-w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="whitespace-nowrap px-4 py-3 text-left text-sm font-medium text-gray-500">
                  级别
                </th>
                <th className="whitespace-nowrap px-4 py-3 text-left text-sm font-medium text-gray-500">
                  时间
                </th>
                <th className="whitespace-nowrap px-4 py-3 text-left text-sm font-medium text-gray-500">
                  探针
                </th>
                <th className="whitespace-nowrap px-4 py-3 text-left text-sm font-medium text-gray-500">
                  源 IP
                </th>
                <th className="whitespace-nowrap px-4 py-3 text-left text-sm font-medium text-gray-500">
                  目标 IP
                </th>
                <th className="whitespace-nowrap px-4 py-3 text-left text-sm font-medium text-gray-500">
                  协议
                </th>
                <th className="px-4 py-3 text-left text-sm font-medium text-gray-500">
                  告警信息
                </th>
                <th className="whitespace-nowrap px-4 py-3 text-left text-sm font-medium text-gray-500">
                  操作
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {displayLogs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-12 text-center text-gray-500">
                    {viewMode === 'realtime' 
                      ? (isPaused ? '已暂停，点击"继续"接收新日志' : '等待告警日志...') 
                      : (historyLoading ? '加载中...' : '暂无历史日志')}
                  </td>
                </tr>
              ) : (
                displayLogs.map((log: LogEntry, index: number) => (
                  <tr key={log.id || index} className="hover:bg-gray-50">
                    <td className="whitespace-nowrap px-4 py-3">
                      {getSeverityBadge(log.severity)}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-sm text-gray-500">
                      {log.timestamp ? new Date(log.timestamp).toLocaleString('zh-CN') : '-'}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-sm">
                      <div className="font-medium">{log.node_id || log.probe_id || '-'}</div>
                      <div className="text-xs text-gray-400">{log.probe_type || '-'}</div>
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 font-mono text-sm">
                      {log.src_ip || '-'}
                      {log.src_port ? `:${log.src_port}` : ''}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 font-mono text-sm">
                      {log.dest_ip || '-'}
                      {log.dest_port ? `:${log.dest_port}` : ''}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-sm text-gray-600">
                      {log.protocol || '-'}
                    </td>
                    <td className="max-w-md truncate px-4 py-3 text-sm">
                      {log.alert_msg || log.category || '-'}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3">
                      <button
                        onClick={() => setSelectedLog(log)}
                        className="text-sm text-blue-600 hover:text-blue-800 hover:underline"
                      >
                        详情
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* 日志详情弹窗 */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
          <div className="max-h-[80vh] w-full max-w-2xl overflow-hidden rounded-lg bg-white shadow-xl">
            <div className="flex items-center justify-between border-b px-6 py-4">
              <h3 className="text-lg font-semibold">告警详情</h3>
              <button
                onClick={() => setSelectedLog(null)}
                className="text-gray-400 hover:text-gray-600"
              >
                <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div className="max-h-[60vh] overflow-y-auto p-6">
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <div className="text-sm font-medium text-gray-500">严重级别</div>
                    <div className="mt-1">{getSeverityBadge(selectedLog.severity)}</div>
                  </div>
                  <div>
                    <div className="text-sm font-medium text-gray-500">时间</div>
                    <div className="mt-1 text-sm">
                      {selectedLog.timestamp ? new Date(selectedLog.timestamp).toLocaleString('zh-CN') : '-'}
                    </div>
                  </div>
                  <div>
                    <div className="text-sm font-medium text-gray-500">探针 ID</div>
                    <div className="mt-1 font-mono text-sm">{selectedLog.node_id || selectedLog.probe_id || '-'}</div>
                  </div>
                  <div>
                    <div className="text-sm font-medium text-gray-500">探针类型</div>
                    <div className="mt-1 text-sm">{selectedLog.probe_type || '-'}</div>
                  </div>
                  <div>
                    <div className="text-sm font-medium text-gray-500">源 IP:端口</div>
                    <div className="mt-1 font-mono text-sm">
                      {selectedLog.src_ip || '-'}:{selectedLog.src_port || '-'}
                    </div>
                  </div>
                  <div>
                    <div className="text-sm font-medium text-gray-500">目标 IP:端口</div>
                    <div className="mt-1 font-mono text-sm">
                      {selectedLog.dest_ip || '-'}:{selectedLog.dest_port || '-'}
                    </div>
                  </div>
                  <div>
                    <div className="text-sm font-medium text-gray-500">协议</div>
                    <div className="mt-1 text-sm">{selectedLog.protocol || '-'}</div>
                  </div>
                  <div>
                    <div className="text-sm font-medium text-gray-500">签名 ID</div>
                    <div className="mt-1 font-mono text-sm">{selectedLog.signature_id || '-'}</div>
                  </div>
                </div>
                <div>
                  <div className="text-sm font-medium text-gray-500">类别</div>
                  <div className="mt-1 text-sm">{selectedLog.category || '-'}</div>
                </div>
                <div>
                  <div className="text-sm font-medium text-gray-500">告警信息</div>
                  <div className="mt-1 rounded-lg bg-gray-100 p-3 text-sm">
                    {selectedLog.alert_msg || '-'}
                  </div>
                </div>
                <div>
                  <div className="text-sm font-medium text-gray-500">原始数据</div>
                  <pre className="mt-1 max-h-48 overflow-auto rounded-lg bg-gray-900 p-3 text-xs text-gray-100">
                    {JSON.stringify(selectedLog, null, 2)}
                  </pre>
                </div>
              </div>
            </div>
            <div className="border-t px-6 py-4">
              <button
                onClick={() => setSelectedLog(null)}
                className="rounded-lg border border-gray-300 px-4 py-2 text-gray-700 hover:bg-gray-50"
              >
                关闭
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

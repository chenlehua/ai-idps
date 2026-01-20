import { useState, useCallback, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useWebSocket } from '../../hooks/useWebSocket'
import { logsApi, probesApi } from '../../services/api'
import { Card, Button, Badge, Select, Modal, StatusDot } from '../../components/common'

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

const SEVERITY_CONFIG: Record<number, { label: string; variant: 'error' | 'warning' | 'info' | 'success' }> = {
  1: { label: '严重', variant: 'error' },
  2: { label: '高', variant: 'warning' },
  3: { label: '中', variant: 'info' },
  4: { label: '低', variant: 'success' }
}

export default function LogsPage() {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [filters, setFilters] = useState<LogFilters>({})
  const [isPaused, setIsPaused] = useState(false)
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null)
  const [viewMode, setViewMode] = useState<'realtime' | 'history'>('realtime')
  
  const [historyParams, setHistoryParams] = useState({
    limit: 100,
    offset: 0,
    severity: undefined as number | undefined,
    probe_id: undefined as string | undefined
  })

  const { data: probesData } = useQuery({
    queryKey: ['probes'],
    queryFn: () => probesApi.list()
  })

  const { data: historyData, isLoading: historyLoading, refetch: refetchHistory } = useQuery({
    queryKey: ['logs-history', historyParams],
    queryFn: () => logsApi.query(historyParams),
    enabled: viewMode === 'history'
  })

  const handleMessage = useCallback((data: any) => {
    if (data.event === 'log' && !isPaused) {
      setLogs(prev => {
        const newLog = {
          ...data.data,
          id: data.data.id || `${Date.now()}-${Math.random()}`
        }
        return [newLog, ...prev].slice(0, 500)
      })
    }
  }, [isPaused])

  const wsUrl = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/api/v1/ws/logs`

  const { isConnected, subscribe } = useWebSocket({
    url: wsUrl,
    onMessage: handleMessage,
    onConnect: () => {
      subscribe(filters)
    }
  })

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

  const probes = probesData?.probes || []
  const displayLogs = viewMode === 'realtime' ? logs : (historyData?.logs || [])

  return (
    <div className="space-y-6 animate-fade-in">
      {/* 页面标题 */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">日志展示</h1>
          <p className="mt-1 text-sm text-slate-500">实时告警日志与历史查询</p>
        </div>
        <div className="flex items-center gap-3">
          {/* 连接状态 */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-100 text-sm text-slate-600">
            <StatusDot status={isConnected ? 'online' : 'offline'} pulse={isConnected} />
            {isConnected ? 'WebSocket 已连接' : 'WebSocket 未连接'}
          </div>

          {/* 视图切换 */}
          <div className="flex rounded-lg border border-slate-200 overflow-hidden">
            <button
              onClick={() => setViewMode('realtime')}
              className={`px-3 py-1.5 text-sm transition-colors ${viewMode === 'realtime' ? 'bg-stripe-primary text-white' : 'bg-white text-slate-600 hover:bg-slate-50'}`}
            >
              实时
            </button>
            <button
              onClick={() => {
                setViewMode('history')
                refetchHistory()
              }}
              className={`px-3 py-1.5 text-sm transition-colors ${viewMode === 'history' ? 'bg-stripe-primary text-white' : 'bg-white text-slate-600 hover:bg-slate-50'}`}
            >
              历史
            </button>
          </div>
        </div>
      </div>

      {/* 过滤器和控制栏 */}
      <Card>
        <Card.Body className="py-4">
          <div className="flex flex-wrap items-center gap-3">
            {/* 严重级别筛选 */}
            <Select
              value={String(historyParams.severity || '')}
              onChange={(e) => handleFilterChange('severity', e.target.value ? parseInt(e.target.value) : undefined)}
              placeholder="所有级别"
              options={[
                { value: '1', label: '严重 (1)' },
                { value: '2', label: '高 (2)' },
                { value: '3', label: '中 (3)' },
                { value: '4', label: '低 (4)' },
              ]}
              className="w-40"
            />

            {/* 探针筛选 */}
            <Select
              value={historyParams.probe_id || ''}
              onChange={(e) => handleFilterChange('probe_id', e.target.value)}
              placeholder="所有探针"
              options={probes.map((probe: any) => ({
                value: probe.node_id,
                label: `${probe.name} (${probe.node_id})`
              }))}
              className="w-56"
            />

            <div className="flex-1" />

            {/* 实时模式控制 */}
            {viewMode === 'realtime' && (
              <>
                <Button
                  variant={isPaused ? 'success' : 'secondary'}
                  size="sm"
                  onClick={() => setIsPaused(!isPaused)}
                  icon={
                    isPaused ? (
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                    ) : (
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                    )
                  }
                >
                  {isPaused ? '继续' : '暂停'}
                </Button>
                <Button variant="secondary" size="sm" onClick={clearLogs}>
                  清空
                </Button>
              </>
            )}

            {/* 历史模式刷新 */}
            {viewMode === 'history' && (
              <Button
                variant="primary"
                size="sm"
                onClick={() => refetchHistory()}
                loading={historyLoading}
              >
                刷新
              </Button>
            )}

            <span className="text-sm text-slate-500">
              共 {displayLogs.length} 条
            </span>
          </div>
        </Card.Body>
      </Card>

      {/* 日志表格 */}
      <Card>
        <div className="overflow-x-auto">
          <table className="min-w-full">
            <thead className="bg-slate-50">
              <tr>
                <th className="whitespace-nowrap px-4 py-3 text-left text-sm font-semibold text-slate-700">级别</th>
                <th className="whitespace-nowrap px-4 py-3 text-left text-sm font-semibold text-slate-700">时间</th>
                <th className="whitespace-nowrap px-4 py-3 text-left text-sm font-semibold text-slate-700">探针</th>
                <th className="whitespace-nowrap px-4 py-3 text-left text-sm font-semibold text-slate-700">源 IP</th>
                <th className="whitespace-nowrap px-4 py-3 text-left text-sm font-semibold text-slate-700">目标 IP</th>
                <th className="whitespace-nowrap px-4 py-3 text-left text-sm font-semibold text-slate-700">协议</th>
                <th className="px-4 py-3 text-left text-sm font-semibold text-slate-700">告警信息</th>
                <th className="whitespace-nowrap px-4 py-3 text-left text-sm font-semibold text-slate-700">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {displayLogs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-12 text-center text-slate-400">
                    <div className="flex flex-col items-center">
                      <svg className="w-12 h-12 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                      </svg>
                      {viewMode === 'realtime' 
                        ? (isPaused ? '已暂停，点击"继续"接收新日志' : '等待告警日志...') 
                        : (historyLoading ? '加载中...' : '暂无历史日志')}
                    </div>
                  </td>
                </tr>
              ) : (
                displayLogs.map((log: LogEntry, index: number) => (
                  <tr key={log.id || index} className="hover:bg-slate-50 transition-colors">
                    <td className="whitespace-nowrap px-4 py-3">
                      <Badge variant={SEVERITY_CONFIG[log.severity || 4]?.variant || 'info'}>
                        {SEVERITY_CONFIG[log.severity || 4]?.label || log.severity || '未知'}
                      </Badge>
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-sm text-slate-500">
                      {log.timestamp ? new Date(log.timestamp).toLocaleString('zh-CN') : '-'}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3">
                      <div className="font-medium text-sm text-slate-700">{log.node_id || log.probe_id || '-'}</div>
                      <div className="text-xs text-slate-400">{log.probe_type || '-'}</div>
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 font-mono text-sm text-slate-700">
                      {log.src_ip || '-'}
                      {log.src_port ? `:${log.src_port}` : ''}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 font-mono text-sm text-slate-700">
                      {log.dest_ip || '-'}
                      {log.dest_port ? `:${log.dest_port}` : ''}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-sm text-slate-600">
                      {log.protocol || '-'}
                    </td>
                    <td className="max-w-md truncate px-4 py-3 text-sm text-slate-700">
                      {log.alert_msg || log.category || '-'}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3">
                      <Button variant="text" size="sm" onClick={() => setSelectedLog(log)}>
                        详情
                      </Button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* 日志详情弹窗 */}
      <Modal
        isOpen={selectedLog !== null}
        onClose={() => setSelectedLog(null)}
        title="告警详情"
        size="md"
        footer={<Button variant="secondary" onClick={() => setSelectedLog(null)}>关闭</Button>}
      >
        {selectedLog && (
          <div className="space-y-6">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <div className="text-sm font-medium text-slate-500">严重级别</div>
                <div className="mt-1">
                  <Badge variant={SEVERITY_CONFIG[selectedLog.severity || 4]?.variant || 'info'}>
                    {SEVERITY_CONFIG[selectedLog.severity || 4]?.label || selectedLog.severity || '未知'}
                  </Badge>
                </div>
              </div>
              <div>
                <div className="text-sm font-medium text-slate-500">时间</div>
                <div className="mt-1 text-sm text-slate-900">
                  {selectedLog.timestamp ? new Date(selectedLog.timestamp).toLocaleString('zh-CN') : '-'}
                </div>
              </div>
              <div>
                <div className="text-sm font-medium text-slate-500">探针 ID</div>
                <div className="mt-1 font-mono text-sm text-slate-900">{selectedLog.node_id || selectedLog.probe_id || '-'}</div>
              </div>
              <div>
                <div className="text-sm font-medium text-slate-500">探针类型</div>
                <div className="mt-1 text-sm text-slate-900">{selectedLog.probe_type || '-'}</div>
              </div>
              <div>
                <div className="text-sm font-medium text-slate-500">源 IP:端口</div>
                <div className="mt-1 font-mono text-sm text-slate-900">
                  {selectedLog.src_ip || '-'}:{selectedLog.src_port || '-'}
                </div>
              </div>
              <div>
                <div className="text-sm font-medium text-slate-500">目标 IP:端口</div>
                <div className="mt-1 font-mono text-sm text-slate-900">
                  {selectedLog.dest_ip || '-'}:{selectedLog.dest_port || '-'}
                </div>
              </div>
              <div>
                <div className="text-sm font-medium text-slate-500">协议</div>
                <div className="mt-1 text-sm text-slate-900">{selectedLog.protocol || '-'}</div>
              </div>
              <div>
                <div className="text-sm font-medium text-slate-500">签名 ID</div>
                <div className="mt-1 font-mono text-sm text-slate-900">{selectedLog.signature_id || '-'}</div>
              </div>
            </div>

            <div>
              <div className="text-sm font-medium text-slate-500">类别</div>
              <div className="mt-1 text-sm text-slate-900">{selectedLog.category || '-'}</div>
            </div>

            <div>
              <div className="text-sm font-medium text-slate-500">告警信息</div>
              <div className="mt-1 rounded-lg bg-slate-100 p-3 text-sm text-slate-900">
                {selectedLog.alert_msg || '-'}
              </div>
            </div>

            <div>
              <div className="text-sm font-medium text-slate-500">原始数据</div>
              <pre className="mt-1 max-h-48 overflow-auto rounded-lg bg-slate-900 p-3 text-xs text-slate-100">
                {JSON.stringify(selectedLog, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </Modal>
    </div>
  )
}

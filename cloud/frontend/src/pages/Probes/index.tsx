import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { probesApi } from '../../services/api'
import { formatDistanceToNow } from 'date-fns'
import { zhCN } from 'date-fns/locale'

interface ProbeInstance {
  instance_id: string
  node_id: string
  probe_type: string
  interface?: string
  status: 'running' | 'stopped' | 'error'
  last_seen?: string
  metrics?: Record<string, any>
}

interface ProbeNode {
  node_id: string
  name: string
  ip_address: string
  status: 'online' | 'offline' | 'unknown'
  last_seen?: string
  current_rule_version?: string
  system_status?: Record<string, any>
  created_at?: string
  updated_at?: string
  instances?: ProbeInstance[]
}

const STATUS_CONFIG = {
  online: { label: '在线', color: 'bg-green-500', textColor: 'text-green-700', bgColor: 'bg-green-50' },
  offline: { label: '离线', color: 'bg-red-500', textColor: 'text-red-700', bgColor: 'bg-red-50' },
  unknown: { label: '未知', color: 'bg-gray-400', textColor: 'text-gray-700', bgColor: 'bg-gray-50' },
  running: { label: '运行中', color: 'bg-green-500', textColor: 'text-green-700', bgColor: 'bg-green-50' },
  stopped: { label: '已停止', color: 'bg-yellow-500', textColor: 'text-yellow-700', bgColor: 'bg-yellow-50' },
  error: { label: '错误', color: 'bg-red-500', textColor: 'text-red-700', bgColor: 'bg-red-50' }
}

export default function ProbesPage() {
  const [selectedProbe, setSelectedProbe] = useState<ProbeNode | null>(null)
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid')
  const [filterStatus, setFilterStatus] = useState<string>('')

  const { data: probesData, isLoading, refetch } = useQuery({
    queryKey: ['probes'],
    queryFn: () => probesApi.list(),
    refetchInterval: 30000 // 30秒自动刷新
  })

  const probes: ProbeNode[] = probesData?.probes || []
  
  // 过滤探针
  const filteredProbes = filterStatus 
    ? probes.filter(p => p.status === filterStatus)
    : probes

  // 统计
  const onlineCount = probes.filter(p => p.status === 'online').length
  const offlineCount = probes.filter(p => p.status === 'offline').length
  const totalCount = probes.length

  const getStatusBadge = (status: string) => {
    const config = STATUS_CONFIG[status as keyof typeof STATUS_CONFIG] || STATUS_CONFIG.unknown
    return (
      <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${config.bgColor} ${config.textColor}`}>
        <span className={`h-1.5 w-1.5 rounded-full ${config.color}`} />
        {config.label}
      </span>
    )
  }

  const formatLastSeen = (lastSeen?: string) => {
    if (!lastSeen) return '从未'
    try {
      return formatDistanceToNow(new Date(lastSeen), { addSuffix: true, locale: zhCN })
    } catch {
      return lastSeen
    }
  }

  return (
    <div className="space-y-6">
      {/* 头部 */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h1 className="text-2xl font-semibold">探针管理</h1>
        <div className="flex items-center gap-3">
          <button
            onClick={() => refetch()}
            disabled={isLoading}
            className="rounded-lg border border-gray-300 px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
          >
            {isLoading ? '刷新中...' : '刷新'}
          </button>
        </div>
      </div>

      {/* 统计卡片 */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div 
          className={`cursor-pointer rounded-lg border p-4 transition-colors ${filterStatus === '' ? 'border-blue-500 bg-blue-50' : 'bg-white hover:bg-gray-50'}`}
          onClick={() => setFilterStatus('')}
        >
          <div className="text-sm text-gray-500">全部探针</div>
          <div className="mt-1 text-2xl font-bold">{totalCount}</div>
        </div>
        <div 
          className={`cursor-pointer rounded-lg border p-4 transition-colors ${filterStatus === 'online' ? 'border-green-500 bg-green-50' : 'bg-white hover:bg-gray-50'}`}
          onClick={() => setFilterStatus(filterStatus === 'online' ? '' : 'online')}
        >
          <div className="flex items-center gap-2 text-sm text-gray-500">
            <span className="h-2 w-2 rounded-full bg-green-500" />
            在线
          </div>
          <div className="mt-1 text-2xl font-bold text-green-600">{onlineCount}</div>
        </div>
        <div 
          className={`cursor-pointer rounded-lg border p-4 transition-colors ${filterStatus === 'offline' ? 'border-red-500 bg-red-50' : 'bg-white hover:bg-gray-50'}`}
          onClick={() => setFilterStatus(filterStatus === 'offline' ? '' : 'offline')}
        >
          <div className="flex items-center gap-2 text-sm text-gray-500">
            <span className="h-2 w-2 rounded-full bg-red-500" />
            离线
          </div>
          <div className="mt-1 text-2xl font-bold text-red-600">{offlineCount}</div>
        </div>
      </div>

      {/* 视图切换 */}
      <div className="flex items-center justify-between">
        <div className="text-sm text-gray-500">
          {filterStatus ? `显示 ${filteredProbes.length} 个${STATUS_CONFIG[filterStatus as keyof typeof STATUS_CONFIG]?.label || ''}探针` : `共 ${totalCount} 个探针`}
        </div>
        <div className="flex rounded-lg border">
          <button
            onClick={() => setViewMode('grid')}
            className={`px-3 py-1.5 text-sm ${viewMode === 'grid' ? 'bg-gray-100' : 'hover:bg-gray-50'}`}
          >
            卡片
          </button>
          <button
            onClick={() => setViewMode('list')}
            className={`px-3 py-1.5 text-sm ${viewMode === 'list' ? 'bg-gray-100' : 'hover:bg-gray-50'}`}
          >
            列表
          </button>
        </div>
      </div>

      {/* 探针列表 */}
      {isLoading ? (
        <div className="rounded-lg border bg-white p-12 text-center text-gray-500">
          加载中...
        </div>
      ) : filteredProbes.length === 0 ? (
        <div className="rounded-lg border bg-white p-12 text-center text-gray-500">
          {filterStatus ? '没有符合条件的探针' : '暂无探针数据'}
        </div>
      ) : viewMode === 'grid' ? (
        /* 卡片视图 */
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {filteredProbes.map((probe) => (
            <div
              key={probe.node_id}
              className="cursor-pointer rounded-lg border bg-white p-5 shadow-sm transition-shadow hover:shadow-md"
              onClick={() => setSelectedProbe(probe)}
            >
              <div className="flex items-start justify-between">
                <div>
                  <h3 className="font-semibold text-gray-900">{probe.name}</h3>
                  <p className="mt-0.5 font-mono text-xs text-gray-400">{probe.node_id}</p>
                </div>
                {getStatusBadge(probe.status)}
              </div>

              <div className="mt-4 space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-500">IP 地址</span>
                  <span className="font-mono">{probe.ip_address}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">规则版本</span>
                  <span className="font-mono text-xs">{probe.current_rule_version || '-'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">最后心跳</span>
                  <span>{formatLastSeen(probe.last_seen)}</span>
                </div>
              </div>

              {/* 探针实例 */}
              {probe.instances && probe.instances.length > 0 && (
                <div className="mt-4 border-t pt-3">
                  <div className="mb-2 text-xs font-medium text-gray-500">探针实例 ({probe.instances.length})</div>
                  <div className="flex flex-wrap gap-2">
                    {probe.instances.map((instance) => (
                      <span
                        key={instance.instance_id}
                        className={`inline-flex items-center gap-1 rounded px-2 py-1 text-xs ${
                          instance.status === 'running' ? 'bg-green-100 text-green-700' :
                          instance.status === 'error' ? 'bg-red-100 text-red-700' :
                          'bg-gray-100 text-gray-600'
                        }`}
                      >
                        <span className={`h-1.5 w-1.5 rounded-full ${STATUS_CONFIG[instance.status]?.color || 'bg-gray-400'}`} />
                        {instance.probe_type}
                        {instance.interface && <span className="text-gray-400">({instance.interface})</span>}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        /* 列表视图 */
        <div className="overflow-hidden rounded-lg border bg-white shadow-sm">
          <table className="min-w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-sm font-medium text-gray-500">名称</th>
                <th className="px-6 py-3 text-left text-sm font-medium text-gray-500">状态</th>
                <th className="px-6 py-3 text-left text-sm font-medium text-gray-500">IP 地址</th>
                <th className="px-6 py-3 text-left text-sm font-medium text-gray-500">规则版本</th>
                <th className="px-6 py-3 text-left text-sm font-medium text-gray-500">最后心跳</th>
                <th className="px-6 py-3 text-left text-sm font-medium text-gray-500">实例数</th>
                <th className="px-6 py-3 text-left text-sm font-medium text-gray-500">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {filteredProbes.map((probe) => (
                <tr key={probe.node_id} className="hover:bg-gray-50">
                  <td className="px-6 py-4">
                    <div className="font-medium text-gray-900">{probe.name}</div>
                    <div className="font-mono text-xs text-gray-400">{probe.node_id}</div>
                  </td>
                  <td className="px-6 py-4">
                    {getStatusBadge(probe.status)}
                  </td>
                  <td className="whitespace-nowrap px-6 py-4 font-mono text-sm">
                    {probe.ip_address}
                  </td>
                  <td className="whitespace-nowrap px-6 py-4 font-mono text-sm text-gray-500">
                    {probe.current_rule_version || '-'}
                  </td>
                  <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-500">
                    {formatLastSeen(probe.last_seen)}
                  </td>
                  <td className="whitespace-nowrap px-6 py-4 text-sm">
                    {probe.instances?.length || 0}
                  </td>
                  <td className="whitespace-nowrap px-6 py-4">
                    <button
                      onClick={() => setSelectedProbe(probe)}
                      className="text-sm text-blue-600 hover:text-blue-800 hover:underline"
                    >
                      详情
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* 探针详情弹窗 */}
      {selectedProbe && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
          <div className="max-h-[85vh] w-full max-w-2xl overflow-hidden rounded-lg bg-white shadow-xl">
            <div className="flex items-center justify-between border-b px-6 py-4">
              <div>
                <h3 className="text-lg font-semibold">{selectedProbe.name}</h3>
                <p className="font-mono text-sm text-gray-400">{selectedProbe.node_id}</p>
              </div>
              <button
                onClick={() => setSelectedProbe(null)}
                className="text-gray-400 hover:text-gray-600"
              >
                <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div className="max-h-[65vh] overflow-y-auto p-6">
              <div className="space-y-6">
                {/* 基本信息 */}
                <div>
                  <h4 className="mb-3 font-medium text-gray-900">基本信息</h4>
                  <div className="grid grid-cols-2 gap-4 rounded-lg bg-gray-50 p-4">
                    <div>
                      <div className="text-sm text-gray-500">状态</div>
                      <div className="mt-1">{getStatusBadge(selectedProbe.status)}</div>
                    </div>
                    <div>
                      <div className="text-sm text-gray-500">IP 地址</div>
                      <div className="mt-1 font-mono">{selectedProbe.ip_address}</div>
                    </div>
                    <div>
                      <div className="text-sm text-gray-500">规则版本</div>
                      <div className="mt-1 font-mono text-sm">{selectedProbe.current_rule_version || '-'}</div>
                    </div>
                    <div>
                      <div className="text-sm text-gray-500">最后心跳</div>
                      <div className="mt-1">{formatLastSeen(selectedProbe.last_seen)}</div>
                    </div>
                    <div>
                      <div className="text-sm text-gray-500">注册时间</div>
                      <div className="mt-1 text-sm">
                        {selectedProbe.created_at ? new Date(selectedProbe.created_at).toLocaleString('zh-CN') : '-'}
                      </div>
                    </div>
                    <div>
                      <div className="text-sm text-gray-500">更新时间</div>
                      <div className="mt-1 text-sm">
                        {selectedProbe.updated_at ? new Date(selectedProbe.updated_at).toLocaleString('zh-CN') : '-'}
                      </div>
                    </div>
                  </div>
                </div>

                {/* 探针实例 */}
                <div>
                  <h4 className="mb-3 font-medium text-gray-900">
                    探针实例 ({selectedProbe.instances?.length || 0})
                  </h4>
                  {selectedProbe.instances && selectedProbe.instances.length > 0 ? (
                    <div className="space-y-3">
                      {selectedProbe.instances.map((instance) => (
                        <div key={instance.instance_id} className="rounded-lg border p-4">
                          <div className="flex items-center justify-between">
                            <div>
                              <div className="font-medium">{instance.probe_type}</div>
                              <div className="font-mono text-xs text-gray-400">{instance.instance_id}</div>
                            </div>
                            {getStatusBadge(instance.status)}
                          </div>
                          <div className="mt-3 grid grid-cols-2 gap-2 text-sm">
                            <div>
                              <span className="text-gray-500">网络接口: </span>
                              <span className="font-mono">{instance.interface || '-'}</span>
                            </div>
                            <div>
                              <span className="text-gray-500">最后活跃: </span>
                              <span>{formatLastSeen(instance.last_seen)}</span>
                            </div>
                          </div>
                          {instance.metrics && Object.keys(instance.metrics).length > 0 && (
                            <div className="mt-3">
                              <div className="text-sm text-gray-500">性能指标:</div>
                              <pre className="mt-1 rounded bg-gray-100 p-2 text-xs">
                                {JSON.stringify(instance.metrics, null, 2)}
                              </pre>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="rounded-lg border border-dashed p-6 text-center text-gray-500">
                      暂无探针实例
                    </div>
                  )}
                </div>

                {/* 系统状态 */}
                {selectedProbe.system_status && Object.keys(selectedProbe.system_status).length > 0 && (
                  <div>
                    <h4 className="mb-3 font-medium text-gray-900">系统状态</h4>
                    <pre className="rounded-lg bg-gray-900 p-4 text-sm text-gray-100">
                      {JSON.stringify(selectedProbe.system_status, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </div>
            <div className="border-t px-6 py-4">
              <button
                onClick={() => setSelectedProbe(null)}
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

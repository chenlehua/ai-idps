import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { probesApi } from '../../services/api'
import { formatDistanceToNow } from 'date-fns'
import { zhCN } from 'date-fns/locale'
import { Card, Button, Badge, Modal, StatCard, StatusDot } from '../../components/common'

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

const statusConfig: Record<string, { label: string; variant: 'success' | 'error' | 'warning' | 'gray' }> = {
  online: { label: '在线', variant: 'success' },
  offline: { label: '离线', variant: 'error' },
  unknown: { label: '未知', variant: 'gray' },
  running: { label: '运行中', variant: 'success' },
  stopped: { label: '已停止', variant: 'warning' },
  error: { label: '错误', variant: 'error' }
}

export default function ProbesPage() {
  const [selectedProbe, setSelectedProbe] = useState<ProbeNode | null>(null)
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid')
  const [filterStatus, setFilterStatus] = useState<string>('')

  const { data: probesData, isLoading, refetch } = useQuery({
    queryKey: ['probes'],
    queryFn: () => probesApi.list(),
    refetchInterval: 30000
  })

  const probes: ProbeNode[] = probesData?.probes || []
  
  const filteredProbes = filterStatus 
    ? probes.filter(p => p.status === filterStatus)
    : probes

  const onlineCount = probes.filter(p => p.status === 'online').length
  const offlineCount = probes.filter(p => p.status === 'offline').length
  const totalCount = probes.length

  const formatLastSeen = (lastSeen?: string) => {
    if (!lastSeen) return '从未'
    try {
      return formatDistanceToNow(new Date(lastSeen), { addSuffix: true, locale: zhCN })
    } catch {
      return lastSeen
    }
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* 页面标题 */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">探针管理</h1>
          <p className="mt-1 text-sm text-slate-500">管理和监控所有探针节点</p>
        </div>
        <Button
          variant="secondary"
          onClick={() => refetch()}
          loading={isLoading}
          icon={
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
          }
        >
          刷新
        </Button>
      </div>

      {/* 统计卡片 */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard
          title="全部探针"
          value={totalCount}
          variant={filterStatus === '' ? 'info' : 'default'}
          onClick={() => setFilterStatus('')}
          className={filterStatus === '' ? 'ring-2 ring-info/30' : ''}
        />
        <StatCard
          title="在线探针"
          value={onlineCount}
          variant={filterStatus === 'online' ? 'success' : 'default'}
          onClick={() => setFilterStatus(filterStatus === 'online' ? '' : 'online')}
          className={filterStatus === 'online' ? 'ring-2 ring-success/30' : ''}
          icon={<StatusDot status="online" size="lg" />}
        />
        <StatCard
          title="离线探针"
          value={offlineCount}
          variant={filterStatus === 'offline' ? 'error' : 'default'}
          onClick={() => setFilterStatus(filterStatus === 'offline' ? '' : 'offline')}
          className={filterStatus === 'offline' ? 'ring-2 ring-error/30' : ''}
          icon={<StatusDot status="offline" size="lg" />}
        />
      </div>

      {/* 视图切换 */}
      <div className="flex items-center justify-between">
        <div className="text-sm text-slate-500">
          {filterStatus ? `显示 ${filteredProbes.length} 个${statusConfig[filterStatus]?.label || ''}探针` : `共 ${totalCount} 个探针`}
        </div>
        <div className="flex rounded-lg border border-slate-200 overflow-hidden">
          <button
            onClick={() => setViewMode('grid')}
            className={`px-3 py-1.5 text-sm transition-colors ${viewMode === 'grid' ? 'bg-stripe-primary text-white' : 'bg-white text-slate-600 hover:bg-slate-50'}`}
          >
            卡片
          </button>
          <button
            onClick={() => setViewMode('list')}
            className={`px-3 py-1.5 text-sm transition-colors ${viewMode === 'list' ? 'bg-stripe-primary text-white' : 'bg-white text-slate-600 hover:bg-slate-50'}`}
          >
            列表
          </button>
        </div>
      </div>

      {/* 探针列表 */}
      {isLoading ? (
        <Card>
          <Card.Body className="flex items-center justify-center py-12 text-slate-400">
            <svg className="animate-spin h-6 w-6 mr-2" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            加载中...
          </Card.Body>
        </Card>
      ) : filteredProbes.length === 0 ? (
        <Card>
          <Card.Body className="flex flex-col items-center justify-center py-12 text-slate-400">
            <svg className="w-12 h-12 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
            </svg>
            {filterStatus ? '没有符合条件的探针' : '暂无探针数据'}
          </Card.Body>
        </Card>
      ) : viewMode === 'grid' ? (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {filteredProbes.map((probe) => (
            <Card
              key={probe.node_id}
              hoverable
              className="cursor-pointer"
              onClick={() => setSelectedProbe(probe)}
            >
              <Card.Body>
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="font-semibold text-slate-900">{probe.name}</h3>
                    <p className="mt-0.5 font-mono text-xs text-slate-400">{probe.node_id}</p>
                  </div>
                  <Badge variant={statusConfig[probe.status]?.variant || 'gray'} dot>
                    {statusConfig[probe.status]?.label || probe.status}
                  </Badge>
                </div>

                <div className="mt-4 space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-slate-500">IP 地址</span>
                    <span className="font-mono text-slate-700">{probe.ip_address}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">规则版本</span>
                    <span className="font-mono text-xs text-slate-700">{probe.current_rule_version || '-'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">最后心跳</span>
                    <span className="text-slate-700">{formatLastSeen(probe.last_seen)}</span>
                  </div>
                </div>

                {probe.instances && probe.instances.length > 0 && (
                  <div className="mt-4 pt-3 border-t border-slate-100">
                    <div className="mb-2 text-xs font-medium text-slate-500">探针实例 ({probe.instances.length})</div>
                    <div className="flex flex-wrap gap-2">
                      {probe.instances.map((instance) => (
                        <Badge
                          key={instance.instance_id}
                          variant={statusConfig[instance.status]?.variant || 'gray'}
                          dot
                        >
                          {instance.probe_type}
                          {instance.interface && <span className="text-slate-400 ml-1">({instance.interface})</span>}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              </Card.Body>
            </Card>
          ))}
        </div>
      ) : (
        <Card>
          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead className="bg-slate-50">
                <tr>
                  <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">名称</th>
                  <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">状态</th>
                  <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">IP 地址</th>
                  <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">规则版本</th>
                  <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">最后心跳</th>
                  <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">实例数</th>
                  <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredProbes.map((probe) => (
                  <tr key={probe.node_id} className="hover:bg-slate-50 transition-colors">
                    <td className="px-6 py-4">
                      <div className="font-medium text-slate-900">{probe.name}</div>
                      <div className="font-mono text-xs text-slate-400">{probe.node_id}</div>
                    </td>
                    <td className="px-6 py-4">
                      <Badge variant={statusConfig[probe.status]?.variant || 'gray'} dot>
                        {statusConfig[probe.status]?.label || probe.status}
                      </Badge>
                    </td>
                    <td className="whitespace-nowrap px-6 py-4 font-mono text-sm text-slate-700">
                      {probe.ip_address}
                    </td>
                    <td className="whitespace-nowrap px-6 py-4 font-mono text-sm text-slate-500">
                      {probe.current_rule_version || '-'}
                    </td>
                    <td className="whitespace-nowrap px-6 py-4 text-sm text-slate-500">
                      {formatLastSeen(probe.last_seen)}
                    </td>
                    <td className="whitespace-nowrap px-6 py-4 text-sm text-slate-700">
                      {probe.instances?.length || 0}
                    </td>
                    <td className="whitespace-nowrap px-6 py-4">
                      <Button variant="text" size="sm" onClick={() => setSelectedProbe(probe)}>
                        详情
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* 探针详情弹窗 */}
      <Modal
        isOpen={selectedProbe !== null}
        onClose={() => setSelectedProbe(null)}
        title={selectedProbe?.name}
        size="md"
        footer={<Button variant="secondary" onClick={() => setSelectedProbe(null)}>关闭</Button>}
      >
        {selectedProbe && (
          <div className="space-y-6">
            <p className="font-mono text-sm text-slate-400">{selectedProbe.node_id}</p>

            {/* 基本信息 */}
            <div>
              <h4 className="mb-3 font-medium text-slate-900">基本信息</h4>
              <div className="grid grid-cols-2 gap-4 rounded-lg bg-slate-50 p-4">
                <div>
                  <div className="text-sm text-slate-500">状态</div>
                  <div className="mt-1">
                    <Badge variant={statusConfig[selectedProbe.status]?.variant || 'gray'} dot>
                      {statusConfig[selectedProbe.status]?.label || selectedProbe.status}
                    </Badge>
                  </div>
                </div>
                <div>
                  <div className="text-sm text-slate-500">IP 地址</div>
                  <div className="mt-1 font-mono text-slate-900">{selectedProbe.ip_address}</div>
                </div>
                <div>
                  <div className="text-sm text-slate-500">规则版本</div>
                  <div className="mt-1 font-mono text-sm text-slate-900">{selectedProbe.current_rule_version || '-'}</div>
                </div>
                <div>
                  <div className="text-sm text-slate-500">最后心跳</div>
                  <div className="mt-1 text-slate-900">{formatLastSeen(selectedProbe.last_seen)}</div>
                </div>
                <div>
                  <div className="text-sm text-slate-500">注册时间</div>
                  <div className="mt-1 text-sm text-slate-900">
                    {selectedProbe.created_at ? new Date(selectedProbe.created_at).toLocaleString('zh-CN') : '-'}
                  </div>
                </div>
                <div>
                  <div className="text-sm text-slate-500">更新时间</div>
                  <div className="mt-1 text-sm text-slate-900">
                    {selectedProbe.updated_at ? new Date(selectedProbe.updated_at).toLocaleString('zh-CN') : '-'}
                  </div>
                </div>
              </div>
            </div>

            {/* 探针实例 */}
            <div>
              <h4 className="mb-3 font-medium text-slate-900">
                探针实例 ({selectedProbe.instances?.length || 0})
              </h4>
              {selectedProbe.instances && selectedProbe.instances.length > 0 ? (
                <div className="space-y-3">
                  {selectedProbe.instances.map((instance) => (
                    <div key={instance.instance_id} className="rounded-lg border border-slate-200 p-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <div className="font-medium text-slate-900">{instance.probe_type}</div>
                          <div className="font-mono text-xs text-slate-400">{instance.instance_id}</div>
                        </div>
                        <Badge variant={statusConfig[instance.status]?.variant || 'gray'} dot>
                          {statusConfig[instance.status]?.label || instance.status}
                        </Badge>
                      </div>
                      <div className="mt-3 grid grid-cols-2 gap-2 text-sm">
                        <div>
                          <span className="text-slate-500">网络接口: </span>
                          <span className="font-mono text-slate-700">{instance.interface || '-'}</span>
                        </div>
                        <div>
                          <span className="text-slate-500">最后活跃: </span>
                          <span className="text-slate-700">{formatLastSeen(instance.last_seen)}</span>
                        </div>
                      </div>
                      {instance.metrics && Object.keys(instance.metrics).length > 0 && (
                        <div className="mt-3">
                          <div className="text-sm text-slate-500 mb-1">性能指标:</div>
                          <pre className="rounded-lg bg-slate-900 p-2 text-xs text-slate-100 overflow-x-auto">
                            {JSON.stringify(instance.metrics, null, 2)}
                          </pre>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="rounded-lg border border-dashed border-slate-200 p-6 text-center text-slate-400">
                  暂无探针实例
                </div>
              )}
            </div>

            {/* 系统状态 */}
            {selectedProbe.system_status && Object.keys(selectedProbe.system_status).length > 0 && (
              <div>
                <h4 className="mb-3 font-medium text-slate-900">系统状态</h4>
                <pre className="rounded-lg bg-slate-900 p-4 text-sm text-slate-100 overflow-x-auto">
                  {JSON.stringify(selectedProbe.system_status, null, 2)}
                </pre>
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  )
}

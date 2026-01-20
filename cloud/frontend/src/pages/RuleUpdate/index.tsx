import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ruleUpdateApi, rulesApi } from '../../services/api'
import { Card, Button, Badge, Input, Tabs, ProgressBar, StatCard } from '../../components/common'

// 类型定义
interface DownloadStatus {
  status: 'idle' | 'downloading' | 'parsing' | 'comparing' | 'ready' | 'error'
  progress: number
  message: string
  task_id: string
  total_bytes: number
  downloaded_bytes: number
}

interface RulePreviewItem {
  sid: number
  msg: string | null
  classtype: string | null
  category: string | null
  severity: number
  protocol: string | null
  change_type: string
  changes?: Array<{ field: string; old_value: string; new_value: string }>
}

interface ChangeSummary {
  added_count: number
  modified_count: number
  deleted_count: number
  unchanged_count: number
  total_changes: number
  has_changes: boolean
}

interface ChangePreview {
  summary: ChangeSummary
  added_rules: RulePreviewItem[]
  modified_rules: RulePreviewItem[]
  deleted_rules: RulePreviewItem[]
  added_total: number
  modified_total: number
  deleted_total: number
  generated_at: string
}

interface RuleVersion {
  id: number
  version: string
  checksum: string
  description: string | null
  is_active: boolean
  created_at: string
  rule_count: number
}

// 状态显示映射
const statusConfig: Record<string, { label: string; variant: 'gray' | 'info' | 'warning' | 'success' | 'error' }> = {
  idle: { label: '空闲', variant: 'gray' },
  downloading: { label: '下载中', variant: 'info' },
  parsing: { label: '解析中', variant: 'warning' },
  comparing: { label: '比较中', variant: 'warning' },
  ready: { label: '就绪', variant: 'success' },
  error: { label: '错误', variant: 'error' }
}

// 严重级别颜色
const severityConfig: Record<number, { variant: 'error' | 'warning' | 'info' | 'gray' }> = {
  1: { variant: 'error' },
  2: { variant: 'warning' },
  3: { variant: 'info' },
  4: { variant: 'gray' }
}

export default function RuleUpdatePage() {
  const [activeTab, setActiveTab] = useState<'download' | 'preview' | 'versions'>('download')
  const [description, setDescription] = useState('')
  const [pollingEnabled, setPollingEnabled] = useState(false)

  const queryClient = useQueryClient()

  // 获取下载状态
  const { data: downloadStatus, isLoading: statusLoading } = useQuery<DownloadStatus>({
    queryKey: ['download-status'],
    queryFn: () => ruleUpdateApi.getDownloadStatus(),
    refetchInterval: pollingEnabled ? 1000 : false
  })

  // 获取变更预览
  const { data: preview, isLoading: previewLoading, refetch: refetchPreview } = useQuery<ChangePreview>({
    queryKey: ['rule-preview'],
    queryFn: () => ruleUpdateApi.getPreview(),
    enabled: downloadStatus?.status === 'ready'
  })

  // 获取版本列表
  const { data: versionsData, isLoading: versionsLoading } = useQuery({
    queryKey: ['rule-versions'],
    queryFn: () => rulesApi.getVersions()
  })

  // 触发下载
  const downloadMutation = useMutation({
    mutationFn: (force: boolean) => ruleUpdateApi.triggerDownload(force),
    onSuccess: () => {
      setPollingEnabled(true)
      queryClient.invalidateQueries({ queryKey: ['download-status'] })
    }
  })

  // 取消下载
  const cancelMutation = useMutation({
    mutationFn: () => ruleUpdateApi.cancelDownload(),
    onSuccess: () => {
      setPollingEnabled(false)
      queryClient.invalidateQueries({ queryKey: ['download-status'] })
    }
  })

  // 确认更新
  const updateMutation = useMutation({
    mutationFn: () => ruleUpdateApi.confirmUpdate(true, description),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rule-versions'] })
      queryClient.invalidateQueries({ queryKey: ['download-status'] })
      setDescription('')
      setActiveTab('versions')
    }
  })

  // 监听状态变化
  useEffect(() => {
    if (downloadStatus?.status === 'ready' || downloadStatus?.status === 'error' || downloadStatus?.status === 'idle') {
      setPollingEnabled(false)
    }
    if (downloadStatus?.status === 'ready') {
      refetchPreview()
      setActiveTab('preview')
    }
  }, [downloadStatus?.status, refetchPreview])

  const versions: RuleVersion[] = versionsData?.versions || []
  const status = downloadStatus?.status || 'idle'
  const statusInfo = statusConfig[status] || statusConfig.idle

  const tabs = [
    { key: 'download', label: '下载更新' },
    { key: 'preview', label: '变更预览', badge: preview?.summary?.has_changes ? preview.summary.total_changes : undefined },
    { key: 'versions', label: '版本历史' }
  ]

  return (
    <div className="space-y-6 animate-fade-in">
      {/* 页面标题 */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">规则更新</h1>
          <p className="mt-1 text-sm text-slate-500">下载、预览和应用规则更新</p>
        </div>
        <Badge variant={statusInfo.variant} dot>
          {statusInfo.label}
        </Badge>
      </div>

      {/* 标签页 */}
      <Tabs
        tabs={tabs}
        activeKey={activeTab}
        onChange={(key) => setActiveTab(key as any)}
      />

      {/* 下载更新标签页 */}
      {activeTab === 'download' && (
        <div className="space-y-6">
          {/* 下载卡片 */}
          <Card>
            <Card.Header>从 ET Open 下载规则</Card.Header>
            <Card.Body>
              <p className="mb-6 text-slate-600">
                点击下方按钮从 Emerging Threats Open 下载最新的入侵检测规则。
                下载完成后可以预览变更并选择性应用更新。
              </p>

              {/* 进度显示 */}
              {(status === 'downloading' || status === 'parsing' || status === 'comparing') && (
                <div className="mb-6 p-4 rounded-lg bg-slate-50">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-slate-700">{downloadStatus?.message || '处理中...'}</span>
                    <span className="text-sm text-slate-500">{downloadStatus?.progress?.toFixed(1)}%</span>
                  </div>
                  <ProgressBar value={downloadStatus?.progress || 0} variant="primary" />
                  {downloadStatus?.downloaded_bytes && downloadStatus.downloaded_bytes > 0 && (
                    <div className="mt-2 text-xs text-slate-500">
                      已下载: {(downloadStatus.downloaded_bytes / 1024 / 1024).toFixed(2)} MB
                      {downloadStatus.total_bytes && downloadStatus.total_bytes > 0 && (
                        <> / {(downloadStatus.total_bytes / 1024 / 1024).toFixed(2)} MB</>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* 错误提示 */}
              {status === 'error' && (
                <div className="mb-6 p-4 rounded-lg bg-error-light border border-error/20">
                  <div className="flex items-center gap-2 text-error">
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <span className="font-medium">下载失败</span>
                  </div>
                  <p className="mt-1 text-sm text-error-dark">{downloadStatus?.message || '请重试'}</p>
                </div>
              )}

              {/* 就绪提示 */}
              {status === 'ready' && (
                <div className="mb-6 p-4 rounded-lg bg-success-light border border-success/20">
                  <div className="flex items-center gap-2 text-success-dark">
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <span className="font-medium">规则下载完成！</span>
                  </div>
                  <p className="mt-1 text-sm text-success-dark">请切换到"变更预览"标签页查看变更内容。</p>
                </div>
              )}

              {/* 操作按钮 */}
              <div className="flex gap-3">
                {status === 'idle' || status === 'error' ? (
                  <>
                    <Button
                      onClick={() => downloadMutation.mutate(false)}
                      loading={downloadMutation.isPending}
                    >
                      开始下载
                    </Button>
                    <Button
                      variant="secondary"
                      onClick={() => downloadMutation.mutate(true)}
                      disabled={downloadMutation.isPending}
                    >
                      强制重新下载
                    </Button>
                  </>
                ) : status === 'downloading' || status === 'parsing' || status === 'comparing' ? (
                  <Button
                    variant="danger"
                    onClick={() => cancelMutation.mutate()}
                    loading={cancelMutation.isPending}
                  >
                    取消下载
                  </Button>
                ) : status === 'ready' ? (
                  <Button
                    variant="success"
                    onClick={() => setActiveTab('preview')}
                  >
                    查看变更预览
                  </Button>
                ) : null}
              </div>
            </Card.Body>
          </Card>

          {/* 说明卡片 */}
          <Card>
            <Card.Header>关于 ET Open 规则</Card.Header>
            <Card.Body>
              <ul className="space-y-3">
                {[
                  'Emerging Threats Open 是一个免费的开源入侵检测规则集',
                  '包含针对恶意软件、漏洞利用、网络扫描等威胁的检测规则',
                  '规则会定期更新，建议每周至少同步一次',
                  '下载的规则会自动进行解析、分类和增量对比'
                ].map((text, index) => (
                  <li key={index} className="flex items-start gap-3 text-slate-600">
                    <svg className="w-5 h-5 text-stripe-primary flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    {text}
                  </li>
                ))}
              </ul>
            </Card.Body>
          </Card>
        </div>
      )}

      {/* 变更预览标签页 */}
      {activeTab === 'preview' && (
        <div className="space-y-6">
          {previewLoading || statusLoading ? (
            <Card>
              <Card.Body className="flex items-center justify-center py-12 text-slate-400">
                <svg className="animate-spin h-6 w-6 mr-2" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                加载中...
              </Card.Body>
            </Card>
          ) : !preview ? (
            <Card>
              <Card.Body className="flex flex-col items-center justify-center py-12 text-slate-400">
                <svg className="w-12 h-12 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                暂无预览数据，请先下载规则
              </Card.Body>
            </Card>
          ) : !preview.summary.has_changes ? (
            <Card>
              <Card.Body className="flex flex-col items-center justify-center py-12 text-slate-400">
                <svg className="w-12 h-12 mb-3 text-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <p className="text-slate-600">没有发现规则变更，当前规则库已是最新</p>
              </Card.Body>
            </Card>
          ) : (
            <>
              {/* 变更摘要 */}
              <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
                <StatCard
                  title="新增规则"
                  value={`+${preview.summary.added_count}`}
                  variant="success"
                />
                <StatCard
                  title="修改规则"
                  value={`~${preview.summary.modified_count}`}
                  variant="warning"
                />
                <StatCard
                  title="删除规则"
                  value={`-${preview.summary.deleted_count}`}
                  variant="error"
                />
                <StatCard
                  title="未变更规则"
                  value={preview.summary.unchanged_count.toString()}
                  variant="default"
                />
              </div>

              {/* 新增规则列表 */}
              {preview.added_rules.length > 0 && (
                <Card>
                  <Card.Header className="text-success-dark">
                    新增规则 ({preview.added_total})
                  </Card.Header>
                  <div className="max-h-64 overflow-y-auto">
                    <table className="min-w-full">
                      <thead className="bg-slate-50 sticky top-0">
                        <tr>
                          <th className="px-6 py-3 text-left text-sm font-medium text-slate-700">SID</th>
                          <th className="px-6 py-3 text-left text-sm font-medium text-slate-700">消息</th>
                          <th className="px-6 py-3 text-left text-sm font-medium text-slate-700">分类</th>
                          <th className="px-6 py-3 text-left text-sm font-medium text-slate-700">级别</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {preview.added_rules.slice(0, 50).map((rule) => (
                          <tr key={rule.sid} className="hover:bg-slate-50">
                            <td className="whitespace-nowrap px-6 py-3 font-mono text-sm">{rule.sid}</td>
                            <td className="px-6 py-3 text-sm text-slate-600 truncate max-w-xs">{rule.msg || '-'}</td>
                            <td className="px-6 py-3 text-sm text-slate-500">{rule.classtype || '-'}</td>
                            <td className="px-6 py-3">
                              <Badge variant={severityConfig[rule.severity]?.variant || 'gray'}>{rule.severity}</Badge>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {preview.added_total > 50 && (
                      <div className="border-t px-6 py-3 text-sm text-slate-500 text-center">
                        还有 {preview.added_total - 50} 条规则...
                      </div>
                    )}
                  </div>
                </Card>
              )}

              {/* 修改规则列表 */}
              {preview.modified_rules.length > 0 && (
                <Card>
                  <Card.Header className="text-warning-dark">
                    修改规则 ({preview.modified_total})
                  </Card.Header>
                  <div className="max-h-64 overflow-y-auto">
                    <table className="min-w-full">
                      <thead className="bg-slate-50 sticky top-0">
                        <tr>
                          <th className="px-6 py-3 text-left text-sm font-medium text-slate-700">SID</th>
                          <th className="px-6 py-3 text-left text-sm font-medium text-slate-700">消息</th>
                          <th className="px-6 py-3 text-left text-sm font-medium text-slate-700">变更内容</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {preview.modified_rules.slice(0, 50).map((rule) => (
                          <tr key={rule.sid} className="hover:bg-slate-50">
                            <td className="whitespace-nowrap px-6 py-3 font-mono text-sm">{rule.sid}</td>
                            <td className="px-6 py-3 text-sm text-slate-600 truncate max-w-xs">{rule.msg || '-'}</td>
                            <td className="px-6 py-3 text-sm text-slate-500">
                              {rule.changes?.map((change, idx) => (
                                <Badge key={idx} variant="gray" className="mr-1">{change.field}</Badge>
                              )) || 'rev 变更'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {preview.modified_total > 50 && (
                      <div className="border-t px-6 py-3 text-sm text-slate-500 text-center">
                        还有 {preview.modified_total - 50} 条规则...
                      </div>
                    )}
                  </div>
                </Card>
              )}

              {/* 删除规则列表 */}
              {preview.deleted_rules.length > 0 && (
                <Card>
                  <Card.Header className="text-error-dark">
                    删除规则 ({preview.deleted_total})
                  </Card.Header>
                  <div className="max-h-64 overflow-y-auto">
                    <table className="min-w-full">
                      <thead className="bg-slate-50 sticky top-0">
                        <tr>
                          <th className="px-6 py-3 text-left text-sm font-medium text-slate-700">SID</th>
                          <th className="px-6 py-3 text-left text-sm font-medium text-slate-700">消息</th>
                          <th className="px-6 py-3 text-left text-sm font-medium text-slate-700">分类</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {preview.deleted_rules.slice(0, 50).map((rule) => (
                          <tr key={rule.sid} className="hover:bg-slate-50">
                            <td className="whitespace-nowrap px-6 py-3 font-mono text-sm">{rule.sid}</td>
                            <td className="px-6 py-3 text-sm text-slate-600 truncate max-w-xs">{rule.msg || '-'}</td>
                            <td className="px-6 py-3 text-sm text-slate-500">{rule.classtype || '-'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {preview.deleted_total > 50 && (
                      <div className="border-t px-6 py-3 text-sm text-slate-500 text-center">
                        还有 {preview.deleted_total - 50} 条规则...
                      </div>
                    )}
                  </div>
                </Card>
              )}

              {/* 确认更新 */}
              <Card>
                <Card.Header>确认更新</Card.Header>
                <Card.Body>
                  <div className="mb-4">
                    <Input
                      label="版本描述 (可选)"
                      value={description}
                      onChange={(e) => setDescription(e.target.value)}
                      placeholder="例如：更新 ET Open 规则 2024-01"
                    />
                  </div>
                  <div className="flex gap-3">
                    <Button
                      variant="success"
                      onClick={() => updateMutation.mutate()}
                      loading={updateMutation.isPending}
                    >
                      应用更新
                    </Button>
                    <Button
                      variant="secondary"
                      onClick={() => downloadMutation.mutate(true)}
                      disabled={downloadMutation.isPending}
                    >
                      重新下载
                    </Button>
                  </div>
                  {updateMutation.isError && (
                    <p className="mt-3 text-sm text-error">
                      更新失败: {(updateMutation.error as Error).message}
                    </p>
                  )}
                </Card.Body>
              </Card>
            </>
          )}
        </div>
      )}

      {/* 版本历史标签页 */}
      {activeTab === 'versions' && (
        <Card>
          <Card.Header>版本历史</Card.Header>
          {versionsLoading ? (
            <Card.Body className="flex items-center justify-center py-12 text-slate-400">
              <svg className="animate-spin h-6 w-6 mr-2" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              加载中...
            </Card.Body>
          ) : versions.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="min-w-full">
                <thead className="bg-slate-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">版本</th>
                    <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">描述</th>
                    <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">规则数</th>
                    <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">状态</th>
                    <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">创建时间</th>
                    <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">校验和</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {versions.map((version) => (
                    <tr key={version.id} className="hover:bg-slate-50">
                      <td className="whitespace-nowrap px-6 py-4 font-mono text-sm">{version.version}</td>
                      <td className="px-6 py-4 text-sm text-slate-600">{version.description || '-'}</td>
                      <td className="whitespace-nowrap px-6 py-4 text-sm text-slate-500">
                        {version.rule_count?.toLocaleString() || '-'}
                      </td>
                      <td className="whitespace-nowrap px-6 py-4">
                        <Badge variant={version.is_active ? 'success' : 'gray'}>
                          {version.is_active ? '当前使用' : '历史版本'}
                        </Badge>
                      </td>
                      <td className="whitespace-nowrap px-6 py-4 text-sm text-slate-500">
                        {new Date(version.created_at).toLocaleString('zh-CN')}
                      </td>
                      <td className="whitespace-nowrap px-6 py-4">
                        <span className="font-mono text-xs text-slate-400">
                          {version.checksum?.slice(0, 16)}...
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Card.Body className="flex flex-col items-center justify-center py-12 text-slate-400">
              <svg className="w-12 h-12 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              暂无规则版本，请先下载并应用规则更新
            </Card.Body>
          )}
        </Card>
      )}
    </div>
  )
}

import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ruleUpdateApi, rulesApi } from '../../services/api'

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
const statusMap: Record<string, { label: string; color: string }> = {
  idle: { label: '空闲', color: 'gray' },
  downloading: { label: '下载中', color: 'blue' },
  parsing: { label: '解析中', color: 'yellow' },
  comparing: { label: '比较中', color: 'yellow' },
  ready: { label: '就绪', color: 'green' },
  error: { label: '错误', color: 'red' }
}

// 严重级别颜色
const severityColors: Record<number, string> = {
  1: 'text-red-600 bg-red-50',
  2: 'text-orange-600 bg-orange-50',
  3: 'text-yellow-600 bg-yellow-50',
  4: 'text-blue-600 bg-blue-50'
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
  const statusInfo = statusMap[status] || statusMap.idle

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">规则更新</h1>
        <div className="flex items-center gap-2">
          <span className={`inline-flex items-center rounded-full px-3 py-1 text-sm font-medium bg-${statusInfo.color}-100 text-${statusInfo.color}-800`}>
            <span className={`mr-2 h-2 w-2 rounded-full bg-${statusInfo.color}-500`}></span>
            {statusInfo.label}
          </span>
        </div>
      </div>

      {/* 标签页 */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          <button
            onClick={() => setActiveTab('download')}
            className={`border-b-2 py-4 px-1 text-sm font-medium ${
              activeTab === 'download'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700'
            }`}
          >
            下载更新
          </button>
          <button
            onClick={() => setActiveTab('preview')}
            className={`border-b-2 py-4 px-1 text-sm font-medium ${
              activeTab === 'preview'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700'
            }`}
          >
            变更预览
            {preview?.summary?.has_changes && (
              <span className="ml-2 rounded-full bg-blue-100 px-2 py-0.5 text-xs text-blue-600">
                {preview.summary.total_changes}
              </span>
            )}
          </button>
          <button
            onClick={() => setActiveTab('versions')}
            className={`border-b-2 py-4 px-1 text-sm font-medium ${
              activeTab === 'versions'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700'
            }`}
          >
            版本历史
          </button>
        </nav>
      </div>

      {/* 下载更新标签页 */}
      {activeTab === 'download' && (
        <div className="space-y-6">
          {/* 下载卡片 */}
          <div className="rounded-lg border bg-white p-6 shadow-sm">
            <h2 className="mb-4 text-lg font-semibold">从 ET Open 下载规则</h2>
            <p className="mb-6 text-sm text-gray-600">
              点击下方按钮从 Emerging Threats Open 下载最新的入侵检测规则。
              下载完成后可以预览变更并选择性应用更新。
            </p>

            {/* 进度显示 */}
            {(status === 'downloading' || status === 'parsing' || status === 'comparing') && (
              <div className="mb-6">
                <div className="mb-2 flex items-center justify-between text-sm">
                  <span className="text-gray-600">{downloadStatus?.message || '处理中...'}</span>
                  <span className="text-gray-500">{downloadStatus?.progress?.toFixed(1)}%</span>
                </div>
                <div className="h-2 w-full rounded-full bg-gray-200">
                  <div
                    className="h-2 rounded-full bg-blue-600 transition-all duration-300"
                    style={{ width: `${downloadStatus?.progress || 0}%` }}
                  ></div>
                </div>
                {downloadStatus?.downloaded_bytes && downloadStatus.downloaded_bytes > 0 && (
                  <div className="mt-2 text-xs text-gray-500">
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
              <div className="mb-6 rounded-lg bg-red-50 p-4 text-sm text-red-700">
                {downloadStatus?.message || '下载失败，请重试'}
              </div>
            )}

            {/* 就绪提示 */}
            {status === 'ready' && (
              <div className="mb-6 rounded-lg bg-green-50 p-4 text-sm text-green-700">
                规则下载完成！请切换到"变更预览"标签页查看变更内容。
              </div>
            )}

            {/* 操作按钮 */}
            <div className="flex gap-3">
              {status === 'idle' || status === 'error' ? (
                <>
                  <button
                    onClick={() => downloadMutation.mutate(false)}
                    disabled={downloadMutation.isPending}
                    className="rounded-lg bg-blue-600 px-4 py-2 text-white hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {downloadMutation.isPending ? '启动中...' : '开始下载'}
                  </button>
                  <button
                    onClick={() => downloadMutation.mutate(true)}
                    disabled={downloadMutation.isPending}
                    className="rounded-lg border border-gray-300 px-4 py-2 text-gray-700 hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    强制重新下载
                  </button>
                </>
              ) : status === 'downloading' || status === 'parsing' || status === 'comparing' ? (
                <button
                  onClick={() => cancelMutation.mutate()}
                  disabled={cancelMutation.isPending}
                  className="rounded-lg border border-red-300 px-4 py-2 text-red-600 hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  取消下载
                </button>
              ) : status === 'ready' ? (
                <button
                  onClick={() => setActiveTab('preview')}
                  className="rounded-lg bg-green-600 px-4 py-2 text-white hover:bg-green-700"
                >
                  查看变更预览
                </button>
              ) : null}
            </div>
          </div>

          {/* 说明卡片 */}
          <div className="rounded-lg border bg-white p-6 shadow-sm">
            <h3 className="mb-3 font-semibold">关于 ET Open 规则</h3>
            <ul className="space-y-2 text-sm text-gray-600">
              <li className="flex items-start">
                <span className="mr-2 text-blue-500">•</span>
                Emerging Threats Open 是一个免费的开源入侵检测规则集
              </li>
              <li className="flex items-start">
                <span className="mr-2 text-blue-500">•</span>
                包含针对恶意软件、漏洞利用、网络扫描等威胁的检测规则
              </li>
              <li className="flex items-start">
                <span className="mr-2 text-blue-500">•</span>
                规则会定期更新，建议每周至少同步一次
              </li>
              <li className="flex items-start">
                <span className="mr-2 text-blue-500">•</span>
                下载的规则会自动进行解析、分类和增量对比
              </li>
            </ul>
          </div>
        </div>
      )}

      {/* 变更预览标签页 */}
      {activeTab === 'preview' && (
        <div className="space-y-6">
          {previewLoading || statusLoading ? (
            <div className="rounded-lg border bg-white p-6 shadow-sm text-center text-gray-500">
              加载中...
            </div>
          ) : !preview ? (
            <div className="rounded-lg border bg-white p-6 shadow-sm text-center text-gray-500">
              暂无预览数据，请先下载规则
            </div>
          ) : !preview.summary.has_changes ? (
            <div className="rounded-lg border bg-white p-6 shadow-sm text-center text-gray-500">
              没有发现规则变更，当前规则库已是最新
            </div>
          ) : (
            <>
              {/* 变更摘要 */}
              <div className="grid grid-cols-4 gap-4">
                <div className="rounded-lg border bg-white p-4 shadow-sm">
                  <div className="text-sm text-gray-500">新增规则</div>
                  <div className="mt-1 text-2xl font-semibold text-green-600">
                    +{preview.summary.added_count}
                  </div>
                </div>
                <div className="rounded-lg border bg-white p-4 shadow-sm">
                  <div className="text-sm text-gray-500">修改规则</div>
                  <div className="mt-1 text-2xl font-semibold text-yellow-600">
                    ~{preview.summary.modified_count}
                  </div>
                </div>
                <div className="rounded-lg border bg-white p-4 shadow-sm">
                  <div className="text-sm text-gray-500">删除规则</div>
                  <div className="mt-1 text-2xl font-semibold text-red-600">
                    -{preview.summary.deleted_count}
                  </div>
                </div>
                <div className="rounded-lg border bg-white p-4 shadow-sm">
                  <div className="text-sm text-gray-500">未变更规则</div>
                  <div className="mt-1 text-2xl font-semibold text-gray-600">
                    {preview.summary.unchanged_count}
                  </div>
                </div>
              </div>

              {/* 新增规则列表 */}
              {preview.added_rules.length > 0 && (
                <div className="rounded-lg border bg-white shadow-sm">
                  <div className="border-b px-6 py-4">
                    <h3 className="font-semibold text-green-600">
                      新增规则 ({preview.added_total})
                    </h3>
                  </div>
                  <div className="max-h-64 overflow-y-auto">
                    <table className="min-w-full">
                      <thead className="bg-gray-50 sticky top-0">
                        <tr>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">SID</th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">消息</th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">分类</th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">严重级别</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-200">
                        {preview.added_rules.slice(0, 50).map((rule) => (
                          <tr key={rule.sid} className="hover:bg-gray-50">
                            <td className="whitespace-nowrap px-6 py-3 font-mono text-sm">{rule.sid}</td>
                            <td className="px-6 py-3 text-sm text-gray-600 truncate max-w-xs">{rule.msg || '-'}</td>
                            <td className="px-6 py-3 text-sm text-gray-500">{rule.classtype || '-'}</td>
                            <td className="px-6 py-3">
                              <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${severityColors[rule.severity] || 'text-gray-600 bg-gray-50'}`}>
                                {rule.severity}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {preview.added_total > 50 && (
                      <div className="border-t px-6 py-3 text-sm text-gray-500 text-center">
                        还有 {preview.added_total - 50} 条规则...
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* 修改规则列表 */}
              {preview.modified_rules.length > 0 && (
                <div className="rounded-lg border bg-white shadow-sm">
                  <div className="border-b px-6 py-4">
                    <h3 className="font-semibold text-yellow-600">
                      修改规则 ({preview.modified_total})
                    </h3>
                  </div>
                  <div className="max-h-64 overflow-y-auto">
                    <table className="min-w-full">
                      <thead className="bg-gray-50 sticky top-0">
                        <tr>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">SID</th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">消息</th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">变更内容</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-200">
                        {preview.modified_rules.slice(0, 50).map((rule) => (
                          <tr key={rule.sid} className="hover:bg-gray-50">
                            <td className="whitespace-nowrap px-6 py-3 font-mono text-sm">{rule.sid}</td>
                            <td className="px-6 py-3 text-sm text-gray-600 truncate max-w-xs">{rule.msg || '-'}</td>
                            <td className="px-6 py-3 text-sm text-gray-500">
                              {rule.changes?.map((change, idx) => (
                                <span key={idx} className="mr-2 text-xs">
                                  {change.field}
                                </span>
                              )) || 'rev 变更'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {preview.modified_total > 50 && (
                      <div className="border-t px-6 py-3 text-sm text-gray-500 text-center">
                        还有 {preview.modified_total - 50} 条规则...
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* 删除规则列表 */}
              {preview.deleted_rules.length > 0 && (
                <div className="rounded-lg border bg-white shadow-sm">
                  <div className="border-b px-6 py-4">
                    <h3 className="font-semibold text-red-600">
                      删除规则 ({preview.deleted_total})
                    </h3>
                  </div>
                  <div className="max-h-64 overflow-y-auto">
                    <table className="min-w-full">
                      <thead className="bg-gray-50 sticky top-0">
                        <tr>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">SID</th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">消息</th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">分类</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-200">
                        {preview.deleted_rules.slice(0, 50).map((rule) => (
                          <tr key={rule.sid} className="hover:bg-gray-50">
                            <td className="whitespace-nowrap px-6 py-3 font-mono text-sm">{rule.sid}</td>
                            <td className="px-6 py-3 text-sm text-gray-600 truncate max-w-xs">{rule.msg || '-'}</td>
                            <td className="px-6 py-3 text-sm text-gray-500">{rule.classtype || '-'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {preview.deleted_total > 50 && (
                      <div className="border-t px-6 py-3 text-sm text-gray-500 text-center">
                        还有 {preview.deleted_total - 50} 条规则...
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* 确认更新 */}
              <div className="rounded-lg border bg-white p-6 shadow-sm">
                <h3 className="mb-4 font-semibold">确认更新</h3>
                <div className="mb-4">
                  <label className="mb-2 block text-sm font-medium text-gray-700">
                    版本描述 (可选)
                  </label>
                  <input
                    type="text"
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    className="w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                    placeholder="例如：更新 ET Open 规则 2024-01"
                  />
                </div>
                <div className="flex gap-3">
                  <button
                    onClick={() => updateMutation.mutate()}
                    disabled={updateMutation.isPending}
                    className="rounded-lg bg-green-600 px-4 py-2 text-white hover:bg-green-700 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {updateMutation.isPending ? '更新中...' : '应用更新'}
                  </button>
                  <button
                    onClick={() => downloadMutation.mutate(true)}
                    disabled={downloadMutation.isPending}
                    className="rounded-lg border border-gray-300 px-4 py-2 text-gray-700 hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    重新下载
                  </button>
                </div>
                {updateMutation.isError && (
                  <div className="mt-3 text-sm text-red-600">
                    更新失败: {(updateMutation.error as Error).message}
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      )}

      {/* 版本历史标签页 */}
      {activeTab === 'versions' && (
        <div className="rounded-lg border bg-white shadow-sm">
          <div className="border-b px-6 py-4">
            <h2 className="text-lg font-semibold">版本历史</h2>
          </div>

          {versionsLoading ? (
            <div className="p-6 text-gray-500">加载中...</div>
          ) : versions.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="min-w-full">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-sm font-medium text-gray-500">版本</th>
                    <th className="px-6 py-3 text-left text-sm font-medium text-gray-500">描述</th>
                    <th className="px-6 py-3 text-left text-sm font-medium text-gray-500">规则数</th>
                    <th className="px-6 py-3 text-left text-sm font-medium text-gray-500">状态</th>
                    <th className="px-6 py-3 text-left text-sm font-medium text-gray-500">创建时间</th>
                    <th className="px-6 py-3 text-left text-sm font-medium text-gray-500">校验和</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {versions.map((version) => (
                    <tr key={version.id} className="hover:bg-gray-50">
                      <td className="whitespace-nowrap px-6 py-4">
                        <span className="font-mono text-sm">{version.version}</span>
                      </td>
                      <td className="px-6 py-4">
                        <span className="text-sm text-gray-600">
                          {version.description || '-'}
                        </span>
                      </td>
                      <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-500">
                        {version.rule_count?.toLocaleString() || '-'}
                      </td>
                      <td className="whitespace-nowrap px-6 py-4">
                        {version.is_active ? (
                          <span className="inline-flex rounded-full bg-green-100 px-2 py-1 text-xs font-medium text-green-800">
                            当前使用
                          </span>
                        ) : (
                          <span className="inline-flex rounded-full bg-gray-100 px-2 py-1 text-xs font-medium text-gray-600">
                            历史版本
                          </span>
                        )}
                      </td>
                      <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-500">
                        {new Date(version.created_at).toLocaleString('zh-CN')}
                      </td>
                      <td className="whitespace-nowrap px-6 py-4">
                        <span className="font-mono text-xs text-gray-400">
                          {version.checksum?.slice(0, 16)}...
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="p-6 text-center text-gray-500">
              暂无规则版本，请先下载并应用规则更新
            </div>
          )}
        </div>
      )}
    </div>
  )
}

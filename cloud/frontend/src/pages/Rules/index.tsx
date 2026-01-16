import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { rulesApi } from '../../services/api'

interface RuleVersion {
  id: number
  version: string
  checksum: string
  description: string
  is_active: boolean
  created_at: string
}

export default function RulesPage() {
  const [content, setContent] = useState('')
  const [description, setDescription] = useState('')
  const [selectedVersion, setSelectedVersion] = useState<string | null>(null)
  const [viewingContent, setViewingContent] = useState<string | null>(null)
  const [isEditorOpen, setIsEditorOpen] = useState(false)
  
  const queryClient = useQueryClient()

  // 获取规则版本列表
  const { data: rulesData, isLoading } = useQuery({
    queryKey: ['rules'],
    queryFn: () => rulesApi.list()
  })

  // 获取特定版本规则内容
  const { data: ruleContent, isLoading: contentLoading } = useQuery({
    queryKey: ['rule', selectedVersion],
    queryFn: () => rulesApi.get(selectedVersion!),
    enabled: !!selectedVersion
  })

  // 创建新规则版本
  const createMutation = useMutation({
    mutationFn: (data: { content: string; description: string }) =>
      rulesApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      setContent('')
      setDescription('')
      setIsEditorOpen(false)
    }
  })

  const handleCreate = () => {
    if (content.trim()) {
      createMutation.mutate({ content, description })
    }
  }

  const handleViewRule = (version: string) => {
    setSelectedVersion(version)
    setViewingContent(null)
  }

  // 当规则内容加载完成时更新
  if (ruleContent && selectedVersion && !viewingContent) {
    setViewingContent(ruleContent.content)
  }

  const versions: RuleVersion[] = rulesData?.versions || []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">规则管理</h1>
        <button
          onClick={() => setIsEditorOpen(!isEditorOpen)}
          className="rounded-lg bg-blue-600 px-4 py-2 text-white hover:bg-blue-700"
        >
          {isEditorOpen ? '取消' : '创建新版本'}
        </button>
      </div>

      {/* 创建新规则 */}
      {isEditorOpen && (
        <div className="rounded-lg border bg-white p-6 shadow-sm">
          <h2 className="mb-4 text-lg font-semibold">创建新版本</h2>
          <div className="mb-4">
            <label className="mb-2 block text-sm font-medium text-gray-700">
              版本描述
            </label>
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
              placeholder="例如：添加新的SQL注入检测规则..."
            />
          </div>
          <div className="mb-4">
            <label className="mb-2 block text-sm font-medium text-gray-700">
              规则内容 (Suricata Rules 格式)
            </label>
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              className="h-64 w-full rounded-lg border border-gray-300 px-3 py-2 font-mono text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
              placeholder={`# Suricata Rules
# 例如：
alert http any any -> any any (msg:"SQL Injection Attempt"; content:"SELECT"; nocase; content:"FROM"; nocase; sid:1000001; rev:1;)
alert http any any -> any any (msg:"XSS Attempt"; content:"<script>"; nocase; sid:1000002; rev:1;)`}
            />
          </div>
          <div className="flex gap-3">
            <button
              onClick={handleCreate}
              disabled={createMutation.isPending || !content.trim()}
              className="rounded-lg bg-green-600 px-4 py-2 text-white hover:bg-green-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {createMutation.isPending ? '创建中...' : '创建新版本'}
            </button>
            <button
              onClick={() => {
                setIsEditorOpen(false)
                setContent('')
                setDescription('')
              }}
              className="rounded-lg border border-gray-300 px-4 py-2 text-gray-700 hover:bg-gray-50"
            >
              取消
            </button>
          </div>
          {createMutation.isError && (
            <div className="mt-3 text-sm text-red-600">
              创建失败: {(createMutation.error as Error).message}
            </div>
          )}
        </div>
      )}

      {/* 版本列表 */}
      <div className="rounded-lg border bg-white shadow-sm">
        <div className="border-b px-6 py-4">
          <h2 className="text-lg font-semibold">版本历史</h2>
        </div>
        
        {isLoading ? (
          <div className="p-6 text-gray-500">加载中...</div>
        ) : versions.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-sm font-medium text-gray-500">
                    版本
                  </th>
                  <th className="px-6 py-3 text-left text-sm font-medium text-gray-500">
                    描述
                  </th>
                  <th className="px-6 py-3 text-left text-sm font-medium text-gray-500">
                    状态
                  </th>
                  <th className="px-6 py-3 text-left text-sm font-medium text-gray-500">
                    创建时间
                  </th>
                  <th className="px-6 py-3 text-left text-sm font-medium text-gray-500">
                    校验和
                  </th>
                  <th className="px-6 py-3 text-left text-sm font-medium text-gray-500">
                    操作
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {versions.map((rule) => (
                  <tr key={rule.id} className="hover:bg-gray-50">
                    <td className="whitespace-nowrap px-6 py-4">
                      <span className="font-mono text-sm">{rule.version}</span>
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-sm text-gray-600">
                        {rule.description || '-'}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-6 py-4">
                      {rule.is_active ? (
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
                      {new Date(rule.created_at).toLocaleString('zh-CN')}
                    </td>
                    <td className="whitespace-nowrap px-6 py-4">
                      <span className="font-mono text-xs text-gray-400">
                        {rule.checksum?.slice(0, 20)}...
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-6 py-4">
                      <button
                        onClick={() => handleViewRule(rule.version)}
                        className="text-blue-600 hover:text-blue-800 hover:underline"
                      >
                        查看
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-6 text-center text-gray-500">
            暂无规则版本，请点击"创建新版本"添加规则
          </div>
        )}
      </div>

      {/* 规则内容查看弹窗 */}
      {selectedVersion && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
          <div className="max-h-[80vh] w-full max-w-4xl overflow-hidden rounded-lg bg-white shadow-xl">
            <div className="flex items-center justify-between border-b px-6 py-4">
              <h3 className="text-lg font-semibold">
                规则版本: {selectedVersion}
              </h3>
              <button
                onClick={() => {
                  setSelectedVersion(null)
                  setViewingContent(null)
                }}
                className="text-gray-400 hover:text-gray-600"
              >
                <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div className="max-h-[60vh] overflow-y-auto p-6">
              {contentLoading ? (
                <div className="text-gray-500">加载中...</div>
              ) : viewingContent ? (
                <pre className="whitespace-pre-wrap rounded-lg bg-gray-900 p-4 font-mono text-sm text-gray-100">
                  {viewingContent}
                </pre>
              ) : (
                <div className="text-gray-500">无法加载规则内容</div>
              )}
            </div>
            <div className="border-t px-6 py-4">
              <button
                onClick={() => {
                  setSelectedVersion(null)
                  setViewingContent(null)
                }}
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

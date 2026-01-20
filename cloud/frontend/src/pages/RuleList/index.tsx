import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { rulesApi } from '../../services/api'

// 类型定义
interface Rule {
  id: number
  sid: number
  gid: number
  rev: number
  action: string
  protocol: string | null
  msg: string | null
  classtype: string | null
  category: string | null
  severity: number
  enabled: boolean
  created_at: string
}

interface RuleDetail extends Rule {
  src_addr: string | null
  src_port: string | null
  direction: string
  dst_addr: string | null
  dst_port: string | null
  content: string | null
  mitre_attack: string | null
  metadata: Record<string, string> | null
  alert_count_24h: number
}

interface CategoryStats {
  category_type: string
  category_name: string
  rule_count: number
  enabled_count: number
}

interface Categories {
  classtype: CategoryStats[]
  msg_prefix: CategoryStats[]
  severity_stats: Record<number, number>
  protocol_stats: Record<string, number>
}

// 严重级别配置
const severityConfig: Record<number, { label: string; color: string; bgColor: string }> = {
  1: { label: '高', color: 'text-red-700', bgColor: 'bg-red-100' },
  2: { label: '中高', color: 'text-orange-700', bgColor: 'bg-orange-100' },
  3: { label: '中', color: 'text-yellow-700', bgColor: 'bg-yellow-100' },
  4: { label: '低', color: 'text-blue-700', bgColor: 'bg-blue-100' }
}

export default function RuleListPage() {
  // 筛选状态
  const [filters, setFilters] = useState({
    classtype: '',
    category: '',
    severity: '' as '' | number,
    protocol: '',
    enabled: '' as '' | boolean,
    search: ''
  })
  const [page, setPage] = useState(0)
  const [selectedRule, setSelectedRule] = useState<number | null>(null)
  const [showFilters, setShowFilters] = useState(false)
  const pageSize = 20

  const queryClient = useQueryClient()

  // 获取分类统计
  const { data: categories } = useQuery<Categories>({
    queryKey: ['rule-categories'],
    queryFn: () => rulesApi.getCategories()
  })

  // 构建查询参数
  const queryParams = {
    ...(filters.classtype && { classtype: filters.classtype }),
    ...(filters.category && { category: filters.category }),
    ...(filters.severity !== '' && { severity: filters.severity }),
    ...(filters.protocol && { protocol: filters.protocol }),
    ...(filters.enabled !== '' && { enabled: filters.enabled }),
    ...(filters.search && { search: filters.search }),
    limit: pageSize,
    offset: page * pageSize
  }

  // 获取规则列表
  const { data: rulesData, isLoading } = useQuery({
    queryKey: ['rules', queryParams],
    queryFn: () => rulesApi.list(queryParams)
  })

  // 获取规则详情
  const { data: ruleDetail, isLoading: detailLoading } = useQuery<RuleDetail>({
    queryKey: ['rule-detail', selectedRule],
    queryFn: () => rulesApi.getBySid(selectedRule!),
    enabled: selectedRule !== null
  })

  // 切换规则启用状态
  const toggleMutation = useMutation({
    mutationFn: ({ sid, enabled }: { sid: number; enabled: boolean }) =>
      rulesApi.toggle(sid, enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      if (selectedRule) {
        queryClient.invalidateQueries({ queryKey: ['rule-detail', selectedRule] })
      }
    }
  })

  const rules: Rule[] = rulesData?.rules || []
  const total = rulesData?.total || 0
  const totalPages = Math.ceil(total / pageSize)

  // 重置筛选
  const resetFilters = () => {
    setFilters({
      classtype: '',
      category: '',
      severity: '',
      protocol: '',
      enabled: '',
      search: ''
    })
    setPage(0)
  }

  // 应用筛选
  const applyFilters = () => {
    setPage(0)
  }

  // 获取活跃筛选数量
  const activeFilterCount = Object.values(filters).filter(v => v !== '').length

  return (
    <div className="space-y-6">
      {/* 页面标题 */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">规则管理</h1>
          <p className="mt-1 text-sm text-gray-500">
            共 {total.toLocaleString()} 条规则
          </p>
        </div>
        <button
          onClick={() => setShowFilters(!showFilters)}
          className={`flex items-center gap-2 rounded-lg border px-4 py-2 ${
            activeFilterCount > 0 ? 'border-blue-500 text-blue-600' : 'border-gray-300 text-gray-700'
          } hover:bg-gray-50`}
        >
          <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z" />
          </svg>
          筛选
          {activeFilterCount > 0 && (
            <span className="rounded-full bg-blue-100 px-2 py-0.5 text-xs">
              {activeFilterCount}
            </span>
          )}
        </button>
      </div>

      {/* 筛选面板 */}
      {showFilters && (
        <div className="rounded-lg border bg-white p-6 shadow-sm">
          <div className="grid grid-cols-2 gap-4 md:grid-cols-3 lg:grid-cols-6">
            {/* 搜索 */}
            <div className="col-span-2 md:col-span-1">
              <label className="mb-1 block text-sm font-medium text-gray-700">搜索</label>
              <input
                type="text"
                value={filters.search}
                onChange={(e) => setFilters({ ...filters, search: e.target.value })}
                onKeyDown={(e) => e.key === 'Enter' && applyFilters()}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                placeholder="SID 或消息内容"
              />
            </div>

            {/* classtype */}
            <div>
              <label className="mb-1 block text-sm font-medium text-gray-700">Classtype</label>
              <select
                value={filters.classtype}
                onChange={(e) => setFilters({ ...filters, classtype: e.target.value })}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
              >
                <option value="">全部</option>
                {categories?.classtype?.map((cat) => (
                  <option key={cat.category_name} value={cat.category_name}>
                    {cat.category_name} ({cat.rule_count})
                  </option>
                ))}
              </select>
            </div>

            {/* 分类 (msg前缀) */}
            <div>
              <label className="mb-1 block text-sm font-medium text-gray-700">分类</label>
              <select
                value={filters.category}
                onChange={(e) => setFilters({ ...filters, category: e.target.value })}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
              >
                <option value="">全部</option>
                {categories?.msg_prefix?.map((cat) => (
                  <option key={cat.category_name} value={cat.category_name}>
                    {cat.category_name} ({cat.rule_count})
                  </option>
                ))}
              </select>
            </div>

            {/* 严重级别 */}
            <div>
              <label className="mb-1 block text-sm font-medium text-gray-700">严重级别</label>
              <select
                value={filters.severity}
                onChange={(e) => setFilters({ ...filters, severity: e.target.value === '' ? '' : Number(e.target.value) })}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
              >
                <option value="">全部</option>
                {[1, 2, 3, 4].map((s) => (
                  <option key={s} value={s}>
                    {severityConfig[s].label} ({categories?.severity_stats?.[s] || 0})
                  </option>
                ))}
              </select>
            </div>

            {/* 协议 */}
            <div>
              <label className="mb-1 block text-sm font-medium text-gray-700">协议</label>
              <select
                value={filters.protocol}
                onChange={(e) => setFilters({ ...filters, protocol: e.target.value })}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
              >
                <option value="">全部</option>
                {Object.entries(categories?.protocol_stats || {}).map(([proto, count]) => (
                  <option key={proto} value={proto}>
                    {proto.toUpperCase()} ({count})
                  </option>
                ))}
              </select>
            </div>

            {/* 启用状态 */}
            <div>
              <label className="mb-1 block text-sm font-medium text-gray-700">状态</label>
              <select
                value={filters.enabled === '' ? '' : String(filters.enabled)}
                onChange={(e) => setFilters({ ...filters, enabled: e.target.value === '' ? '' : e.target.value === 'true' })}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
              >
                <option value="">全部</option>
                <option value="true">已启用</option>
                <option value="false">已禁用</option>
              </select>
            </div>
          </div>

          <div className="mt-4 flex gap-3">
            <button
              onClick={applyFilters}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700"
            >
              应用筛选
            </button>
            <button
              onClick={resetFilters}
              className="rounded-lg border border-gray-300 px-4 py-2 text-sm text-gray-700 hover:bg-gray-50"
            >
              重置
            </button>
          </div>
        </div>
      )}

      {/* 规则列表 */}
      <div className="rounded-lg border bg-white shadow-sm">
        {isLoading ? (
          <div className="p-6 text-center text-gray-500">加载中...</div>
        ) : rules.length > 0 ? (
          <>
            <div className="overflow-x-auto">
              <table className="min-w-full">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">SID</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">消息</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">分类</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">协议</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">级别</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">状态</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">操作</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {rules.map((rule) => (
                    <tr key={rule.id} className="hover:bg-gray-50">
                      <td className="whitespace-nowrap px-6 py-4">
                        <span className="font-mono text-sm">{rule.sid}</span>
                      </td>
                      <td className="px-6 py-4">
                        <div className="max-w-md truncate text-sm text-gray-700" title={rule.msg || ''}>
                          {rule.msg || '-'}
                        </div>
                        {rule.classtype && (
                          <div className="mt-1 text-xs text-gray-400">{rule.classtype}</div>
                        )}
                      </td>
                      <td className="whitespace-nowrap px-6 py-4">
                        {rule.category && (
                          <span className="inline-flex rounded-full bg-gray-100 px-2 py-0.5 text-xs text-gray-600">
                            {rule.category}
                          </span>
                        )}
                      </td>
                      <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-500">
                        {rule.protocol?.toUpperCase() || '-'}
                      </td>
                      <td className="whitespace-nowrap px-6 py-4">
                        <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${severityConfig[rule.severity]?.bgColor || 'bg-gray-100'} ${severityConfig[rule.severity]?.color || 'text-gray-600'}`}>
                          {severityConfig[rule.severity]?.label || rule.severity}
                        </span>
                      </td>
                      <td className="whitespace-nowrap px-6 py-4">
                        <button
                          onClick={() => toggleMutation.mutate({ sid: rule.sid, enabled: !rule.enabled })}
                          disabled={toggleMutation.isPending}
                          className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 ${
                            rule.enabled ? 'bg-blue-600' : 'bg-gray-200'
                          } disabled:cursor-not-allowed disabled:opacity-50`}
                        >
                          <span
                            className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                              rule.enabled ? 'translate-x-5' : 'translate-x-0'
                            }`}
                          />
                        </button>
                      </td>
                      <td className="whitespace-nowrap px-6 py-4">
                        <button
                          onClick={() => setSelectedRule(rule.sid)}
                          className="text-blue-600 hover:text-blue-800 hover:underline"
                        >
                          详情
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* 分页 */}
            <div className="flex items-center justify-between border-t px-6 py-3">
              <div className="text-sm text-gray-500">
                显示 {page * pageSize + 1} - {Math.min((page + 1) * pageSize, total)} 条，共 {total} 条
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => setPage(Math.max(0, page - 1))}
                  disabled={page === 0}
                  className="rounded-lg border border-gray-300 px-3 py-1 text-sm text-gray-700 hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  上一页
                </button>
                <span className="px-3 py-1 text-sm text-gray-500">
                  {page + 1} / {totalPages || 1}
                </span>
                <button
                  onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
                  disabled={page >= totalPages - 1}
                  className="rounded-lg border border-gray-300 px-3 py-1 text-sm text-gray-700 hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  下一页
                </button>
              </div>
            </div>
          </>
        ) : (
          <div className="p-6 text-center text-gray-500">
            {activeFilterCount > 0 ? '没有匹配的规则' : '暂无规则数据'}
          </div>
        )}
      </div>

      {/* 规则详情弹窗 */}
      {selectedRule !== null && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
          <div className="max-h-[85vh] w-full max-w-3xl overflow-hidden rounded-lg bg-white shadow-xl">
            <div className="flex items-center justify-between border-b px-6 py-4">
              <h3 className="text-lg font-semibold">
                规则详情 - SID: {selectedRule}
              </h3>
              <button
                onClick={() => setSelectedRule(null)}
                className="text-gray-400 hover:text-gray-600"
              >
                <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <div className="max-h-[calc(85vh-130px)] overflow-y-auto p-6">
              {detailLoading ? (
                <div className="text-center text-gray-500">加载中...</div>
              ) : ruleDetail ? (
                <div className="space-y-6">
                  {/* 基本信息 */}
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="text-sm font-medium text-gray-500">SID</label>
                      <div className="mt-1 font-mono">{ruleDetail.sid}</div>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-gray-500">GID</label>
                      <div className="mt-1 font-mono">{ruleDetail.gid}</div>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-gray-500">版本 (Rev)</label>
                      <div className="mt-1">{ruleDetail.rev}</div>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-gray-500">动作</label>
                      <div className="mt-1">{ruleDetail.action}</div>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-gray-500">协议</label>
                      <div className="mt-1">{ruleDetail.protocol?.toUpperCase() || '-'}</div>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-gray-500">严重级别</label>
                      <div className="mt-1">
                        <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${severityConfig[ruleDetail.severity]?.bgColor || 'bg-gray-100'} ${severityConfig[ruleDetail.severity]?.color || 'text-gray-600'}`}>
                          {severityConfig[ruleDetail.severity]?.label || ruleDetail.severity}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* 消息 */}
                  <div>
                    <label className="text-sm font-medium text-gray-500">消息</label>
                    <div className="mt-1 text-gray-700">{ruleDetail.msg || '-'}</div>
                  </div>

                  {/* 分类信息 */}
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="text-sm font-medium text-gray-500">Classtype</label>
                      <div className="mt-1">{ruleDetail.classtype || '-'}</div>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-gray-500">分类</label>
                      <div className="mt-1">{ruleDetail.category || '-'}</div>
                    </div>
                  </div>

                  {/* 网络信息 */}
                  <div>
                    <label className="text-sm font-medium text-gray-500">网络</label>
                    <div className="mt-1 font-mono text-sm">
                      {ruleDetail.src_addr || 'any'}:{ruleDetail.src_port || 'any'}{' '}
                      {ruleDetail.direction}{' '}
                      {ruleDetail.dst_addr || 'any'}:{ruleDetail.dst_port || 'any'}
                    </div>
                  </div>

                  {/* MITRE ATT&CK */}
                  {ruleDetail.mitre_attack && (
                    <div>
                      <label className="text-sm font-medium text-gray-500">MITRE ATT&CK</label>
                      <div className="mt-1">
                        <span className="inline-flex rounded-full bg-purple-100 px-2 py-0.5 text-xs text-purple-700">
                          {ruleDetail.mitre_attack}
                        </span>
                      </div>
                    </div>
                  )}

                  {/* 24小时告警数 */}
                  <div>
                    <label className="text-sm font-medium text-gray-500">24小时告警数</label>
                    <div className="mt-1">
                      <span className={`text-lg font-semibold ${ruleDetail.alert_count_24h > 0 ? 'text-red-600' : 'text-gray-500'}`}>
                        {ruleDetail.alert_count_24h}
                      </span>
                    </div>
                  </div>

                  {/* 规则内容 */}
                  {ruleDetail.content && (
                    <div>
                      <label className="text-sm font-medium text-gray-500">规则内容</label>
                      <pre className="mt-1 overflow-x-auto whitespace-pre-wrap rounded-lg bg-gray-900 p-4 font-mono text-sm text-gray-100">
                        {ruleDetail.content}
                      </pre>
                    </div>
                  )}

                  {/* 元数据 */}
                  {ruleDetail.metadata && Object.keys(ruleDetail.metadata).length > 0 && (
                    <div>
                      <label className="text-sm font-medium text-gray-500">元数据</label>
                      <div className="mt-1 flex flex-wrap gap-2">
                        {Object.entries(ruleDetail.metadata).map(([key, value]) => (
                          <span key={key} className="inline-flex rounded bg-gray-100 px-2 py-1 text-xs">
                            <span className="font-medium">{key}:</span>
                            <span className="ml-1 text-gray-600">{value}</span>
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* 状态切换 */}
                  <div className="flex items-center justify-between rounded-lg bg-gray-50 p-4">
                    <div>
                      <div className="font-medium">规则状态</div>
                      <div className="text-sm text-gray-500">
                        {ruleDetail.enabled ? '规则已启用' : '规则已禁用'}
                      </div>
                    </div>
                    <button
                      onClick={() => toggleMutation.mutate({ sid: ruleDetail.sid, enabled: !ruleDetail.enabled })}
                      disabled={toggleMutation.isPending}
                      className={`rounded-lg px-4 py-2 text-sm font-medium ${
                        ruleDetail.enabled
                          ? 'bg-red-100 text-red-700 hover:bg-red-200'
                          : 'bg-green-100 text-green-700 hover:bg-green-200'
                      } disabled:cursor-not-allowed disabled:opacity-50`}
                    >
                      {ruleDetail.enabled ? '禁用规则' : '启用规则'}
                    </button>
                  </div>
                </div>
              ) : (
                <div className="text-center text-gray-500">无法加载规则详情</div>
              )}
            </div>

            <div className="border-t px-6 py-4">
              <button
                onClick={() => setSelectedRule(null)}
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

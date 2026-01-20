import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { attacksApi, rulesApi, probesApi } from '../../services/api'

// 类型定义
interface AttackTest {
  id: number
  test_id: string
  name: string | null
  test_type: string
  status: string
  total_rules: number
  success_count: number
  failed_count: number
  progress_percent: number
  probe_id: string | null
  started_at: string | null
  completed_at: string | null
  created_at: string | null
}

interface TestItem {
  id: number
  sid: number
  status: string
  attack_type: string | null
  response_time_ms: number | null
  error_message: string | null
  matched_log_id: string | null
  executed_at: string | null
}

interface Probe {
  node_id: string
  name: string
  status: string
}

interface Rule {
  id: number
  sid: number
  msg: string | null
  classtype: string | null
  severity: number
}

// 状态配置
const statusConfig: Record<string, { label: string; color: string; bgColor: string }> = {
  pending: { label: '待执行', color: 'text-gray-700', bgColor: 'bg-gray-100' },
  running: { label: '执行中', color: 'text-blue-700', bgColor: 'bg-blue-100' },
  completed: { label: '已完成', color: 'text-green-700', bgColor: 'bg-green-100' },
  failed: { label: '失败', color: 'text-red-700', bgColor: 'bg-red-100' },
  cancelled: { label: '已取消', color: 'text-gray-700', bgColor: 'bg-gray-100' },
  success: { label: '成功', color: 'text-green-700', bgColor: 'bg-green-100' },
  timeout: { label: '超时', color: 'text-orange-700', bgColor: 'bg-orange-100' },
}

export default function AttackTestPage() {
  const [activeTab, setActiveTab] = useState<'list' | 'create'>('list')
  const [selectedTest, setSelectedTest] = useState<string | null>(null)
  const [selectedRules, setSelectedRules] = useState<number[]>([])
  const [selectedProbe, setSelectedProbe] = useState<string>('')
  const [testName, setTestName] = useState('')
  const [ruleSearch, setRuleSearch] = useState('')
  const [page, setPage] = useState(0)

  const queryClient = useQueryClient()

  // 获取测试列表
  const { data: testsData, isLoading: testsLoading } = useQuery({
    queryKey: ['attack-tests', page],
    queryFn: () => attacksApi.listTests({ limit: 20, offset: page * 20 }),
    refetchInterval: selectedTest ? 3000 : false  // 选中测试时自动刷新
  })

  // 获取测试详情
  const { data: testDetail, isLoading: detailLoading } = useQuery({
    queryKey: ['attack-test', selectedTest],
    queryFn: () => attacksApi.getTest(selectedTest!),
    enabled: !!selectedTest,
    refetchInterval: 3000  // 自动刷新进度
  })

  // 获取探针列表
  const { data: probesData } = useQuery({
    queryKey: ['probes'],
    queryFn: () => probesApi.list()
  })

  // 获取规则列表 (用于选择)
  const { data: rulesData, isLoading: rulesLoading } = useQuery({
    queryKey: ['rules-for-test', ruleSearch],
    queryFn: () => rulesApi.list({ search: ruleSearch, limit: 50, enabled: true }),
    enabled: activeTab === 'create'
  })

  // 创建测试
  const createMutation = useMutation({
    mutationFn: (data: { name?: string; rule_sids: number[]; probe_id: string }) =>
      attacksApi.createTest(data),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['attack-tests'] })
      setSelectedTest(data.test_id)
      setActiveTab('list')
      setSelectedRules([])
      setTestName('')
    }
  })

  // 启动测试
  const startMutation = useMutation({
    mutationFn: (testId: string) => attacksApi.startTest(testId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['attack-tests'] })
      queryClient.invalidateQueries({ queryKey: ['attack-test', selectedTest] })
    }
  })

  // 取消测试
  const cancelMutation = useMutation({
    mutationFn: (testId: string) => attacksApi.cancelTest(testId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['attack-tests'] })
      queryClient.invalidateQueries({ queryKey: ['attack-test', selectedTest] })
    }
  })

  const tests: AttackTest[] = testsData?.tests || []
  const probes: Probe[] = probesData?.probes || []
  const rules: Rule[] = rulesData?.rules || []
  const total = testsData?.total || 0

  // 处理规则选择
  const toggleRuleSelection = (sid: number) => {
    setSelectedRules(prev =>
      prev.includes(sid)
        ? prev.filter(s => s !== sid)
        : [...prev, sid]
    )
  }

  const handleCreateTest = () => {
    if (selectedRules.length === 0 || !selectedProbe) return
    createMutation.mutate({
      name: testName || undefined,
      rule_sids: selectedRules,
      probe_id: selectedProbe
    })
  }

  return (
    <div className="space-y-6">
      {/* 页面标题 */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">攻击测试</h1>
        <button
          onClick={() => setActiveTab(activeTab === 'list' ? 'create' : 'list')}
          className="rounded-lg bg-blue-600 px-4 py-2 text-white hover:bg-blue-700"
        >
          {activeTab === 'list' ? '创建测试' : '返回列表'}
        </button>
      </div>

      {/* 创建测试 */}
      {activeTab === 'create' && (
        <div className="space-y-6">
          {/* 基本信息 */}
          <div className="rounded-lg border bg-white p-6 shadow-sm">
            <h2 className="mb-4 text-lg font-semibold">测试配置</h2>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="mb-1 block text-sm font-medium text-gray-700">
                  测试名称 (可选)
                </label>
                <input
                  type="text"
                  value={testName}
                  onChange={(e) => setTestName(e.target.value)}
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                  placeholder="例如：SQL注入规则测试"
                />
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-gray-700">
                  执行探针 <span className="text-red-500">*</span>
                </label>
                <select
                  value={selectedProbe}
                  onChange={(e) => setSelectedProbe(e.target.value)}
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                >
                  <option value="">选择探针</option>
                  {probes.map((probe) => (
                    <option key={probe.node_id} value={probe.node_id}>
                      {probe.name} ({probe.node_id})
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </div>

          {/* 规则选择 */}
          <div className="rounded-lg border bg-white shadow-sm">
            <div className="flex items-center justify-between border-b px-6 py-4">
              <h2 className="font-semibold">
                选择规则
                {selectedRules.length > 0 && (
                  <span className="ml-2 text-sm text-blue-600">
                    已选 {selectedRules.length} 条
                  </span>
                )}
              </h2>
              <input
                type="text"
                value={ruleSearch}
                onChange={(e) => setRuleSearch(e.target.value)}
                className="w-64 rounded-lg border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                placeholder="搜索 SID 或消息"
              />
            </div>

            <div className="max-h-80 overflow-y-auto">
              {rulesLoading ? (
                <div className="p-6 text-center text-gray-500">加载中...</div>
              ) : rules.length > 0 ? (
                <table className="min-w-full">
                  <thead className="bg-gray-50 sticky top-0">
                    <tr>
                      <th className="w-12 px-6 py-3 text-left text-xs font-medium text-gray-500">
                        <input
                          type="checkbox"
                          checked={rules.length > 0 && rules.every(r => selectedRules.includes(r.sid))}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setSelectedRules([...new Set([...selectedRules, ...rules.map(r => r.sid)])])
                            } else {
                              setSelectedRules(selectedRules.filter(s => !rules.some(r => r.sid === s)))
                            }
                          }}
                          className="h-4 w-4 rounded border-gray-300"
                        />
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">SID</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">消息</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">分类</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-200">
                    {rules.map((rule) => (
                      <tr
                        key={rule.sid}
                        className={`cursor-pointer hover:bg-gray-50 ${selectedRules.includes(rule.sid) ? 'bg-blue-50' : ''}`}
                        onClick={() => toggleRuleSelection(rule.sid)}
                      >
                        <td className="px-6 py-3">
                          <input
                            type="checkbox"
                            checked={selectedRules.includes(rule.sid)}
                            onChange={() => toggleRuleSelection(rule.sid)}
                            onClick={(e) => e.stopPropagation()}
                            className="h-4 w-4 rounded border-gray-300"
                          />
                        </td>
                        <td className="whitespace-nowrap px-6 py-3 font-mono text-sm">{rule.sid}</td>
                        <td className="px-6 py-3 text-sm text-gray-600 truncate max-w-md">{rule.msg || '-'}</td>
                        <td className="whitespace-nowrap px-6 py-3 text-sm text-gray-500">{rule.classtype || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="p-6 text-center text-gray-500">没有找到规则</div>
              )}
            </div>

            <div className="border-t px-6 py-4">
              <button
                onClick={handleCreateTest}
                disabled={selectedRules.length === 0 || !selectedProbe || createMutation.isPending}
                className="rounded-lg bg-green-600 px-4 py-2 text-white hover:bg-green-700 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {createMutation.isPending ? '创建中...' : `创建测试 (${selectedRules.length} 条规则)`}
              </button>
              {createMutation.isError && (
                <span className="ml-4 text-sm text-red-600">
                  创建失败: {(createMutation.error as Error).message}
                </span>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 测试列表 */}
      {activeTab === 'list' && !selectedTest && (
        <div className="rounded-lg border bg-white shadow-sm">
          <div className="border-b px-6 py-4">
            <h2 className="text-lg font-semibold">测试列表</h2>
          </div>

          {testsLoading ? (
            <div className="p-6 text-center text-gray-500">加载中...</div>
          ) : tests.length > 0 ? (
            <>
              <div className="overflow-x-auto">
                <table className="min-w-full">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">测试ID</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">名称</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">状态</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">进度</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">探针</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">创建时间</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">操作</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-200">
                    {tests.map((test) => (
                      <tr key={test.id} className="hover:bg-gray-50">
                        <td className="whitespace-nowrap px-6 py-4">
                          <span className="font-mono text-sm">{test.test_id.slice(-12)}</span>
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-600">
                          {test.name || '-'}
                        </td>
                        <td className="whitespace-nowrap px-6 py-4">
                          <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${statusConfig[test.status]?.bgColor || 'bg-gray-100'} ${statusConfig[test.status]?.color || 'text-gray-600'}`}>
                            {statusConfig[test.status]?.label || test.status}
                          </span>
                        </td>
                        <td className="whitespace-nowrap px-6 py-4">
                          <div className="flex items-center gap-2">
                            <div className="h-2 w-24 rounded-full bg-gray-200">
                              <div
                                className={`h-2 rounded-full ${test.status === 'completed' ? 'bg-green-500' : 'bg-blue-500'}`}
                                style={{ width: `${test.progress_percent}%` }}
                              ></div>
                            </div>
                            <span className="text-xs text-gray-500">
                              {test.success_count}/{test.total_rules}
                            </span>
                          </div>
                        </td>
                        <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-500">
                          {test.probe_id || '-'}
                        </td>
                        <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-500">
                          {test.created_at ? new Date(test.created_at).toLocaleString('zh-CN') : '-'}
                        </td>
                        <td className="whitespace-nowrap px-6 py-4">
                          <button
                            onClick={() => setSelectedTest(test.test_id)}
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
                  共 {total} 个测试
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => setPage(Math.max(0, page - 1))}
                    disabled={page === 0}
                    className="rounded-lg border border-gray-300 px-3 py-1 text-sm text-gray-700 hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    上一页
                  </button>
                  <button
                    onClick={() => setPage(page + 1)}
                    disabled={tests.length < 20}
                    className="rounded-lg border border-gray-300 px-3 py-1 text-sm text-gray-700 hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    下一页
                  </button>
                </div>
              </div>
            </>
          ) : (
            <div className="p-6 text-center text-gray-500">
              暂无测试，点击"创建测试"开始
            </div>
          )}
        </div>
      )}

      {/* 测试详情 */}
      {activeTab === 'list' && selectedTest && (
        <div className="space-y-6">
          {/* 返回按钮 */}
          <button
            onClick={() => setSelectedTest(null)}
            className="flex items-center gap-1 text-sm text-gray-600 hover:text-gray-800"
          >
            <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
            返回列表
          </button>

          {detailLoading ? (
            <div className="rounded-lg border bg-white p-6 shadow-sm text-center text-gray-500">
              加载中...
            </div>
          ) : testDetail ? (
            <>
              {/* 测试概况 */}
              <div className="rounded-lg border bg-white p-6 shadow-sm">
                <div className="flex items-center justify-between mb-6">
                  <div>
                    <h2 className="text-lg font-semibold">{testDetail.name || testDetail.test_id}</h2>
                    <p className="text-sm text-gray-500 mt-1">
                      探针: {testDetail.probe_id} | 创建: {testDetail.created_at ? new Date(testDetail.created_at).toLocaleString('zh-CN') : '-'}
                    </p>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className={`inline-flex rounded-full px-3 py-1 text-sm font-medium ${statusConfig[testDetail.status]?.bgColor || 'bg-gray-100'} ${statusConfig[testDetail.status]?.color || 'text-gray-600'}`}>
                      {statusConfig[testDetail.status]?.label || testDetail.status}
                    </span>
                    {testDetail.status === 'pending' && (
                      <button
                        onClick={() => startMutation.mutate(testDetail.test_id)}
                        disabled={startMutation.isPending}
                        className="rounded-lg bg-green-600 px-4 py-2 text-white hover:bg-green-700 disabled:opacity-50"
                      >
                        {startMutation.isPending ? '启动中...' : '启动测试'}
                      </button>
                    )}
                    {(testDetail.status === 'pending' || testDetail.status === 'running') && (
                      <button
                        onClick={() => cancelMutation.mutate(testDetail.test_id)}
                        disabled={cancelMutation.isPending}
                        className="rounded-lg border border-red-300 px-4 py-2 text-red-600 hover:bg-red-50 disabled:opacity-50"
                      >
                        取消
                      </button>
                    )}
                  </div>
                </div>

                {/* 统计卡片 */}
                <div className="grid grid-cols-4 gap-4">
                  <div className="rounded-lg bg-gray-50 p-4">
                    <div className="text-sm text-gray-500">总规则数</div>
                    <div className="mt-1 text-2xl font-semibold">{testDetail.total_rules}</div>
                  </div>
                  <div className="rounded-lg bg-green-50 p-4">
                    <div className="text-sm text-green-600">成功</div>
                    <div className="mt-1 text-2xl font-semibold text-green-700">{testDetail.success_count}</div>
                  </div>
                  <div className="rounded-lg bg-red-50 p-4">
                    <div className="text-sm text-red-600">失败</div>
                    <div className="mt-1 text-2xl font-semibold text-red-700">{testDetail.failed_count}</div>
                  </div>
                  <div className="rounded-lg bg-blue-50 p-4">
                    <div className="text-sm text-blue-600">进度</div>
                    <div className="mt-1 text-2xl font-semibold text-blue-700">{testDetail.progress_percent.toFixed(1)}%</div>
                  </div>
                </div>

                {/* 进度条 */}
                {testDetail.status === 'running' && (
                  <div className="mt-4">
                    <div className="h-3 w-full rounded-full bg-gray-200">
                      <div
                        className="h-3 rounded-full bg-blue-600 transition-all duration-300"
                        style={{ width: `${testDetail.progress_percent}%` }}
                      ></div>
                    </div>
                  </div>
                )}
              </div>

              {/* 测试项列表 */}
              <div className="rounded-lg border bg-white shadow-sm">
                <div className="border-b px-6 py-4">
                  <h3 className="font-semibold">测试项详情</h3>
                </div>
                <div className="max-h-96 overflow-y-auto">
                  <table className="min-w-full">
                    <thead className="bg-gray-50 sticky top-0">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">SID</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">状态</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">攻击类型</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">响应时间</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">关联日志</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">执行时间</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500">错误信息</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-200">
                      {(testDetail.items || []).map((item: TestItem) => (
                        <tr key={item.id} className="hover:bg-gray-50">
                          <td className="whitespace-nowrap px-6 py-3 font-mono text-sm">{item.sid}</td>
                          <td className="whitespace-nowrap px-6 py-3">
                            <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${statusConfig[item.status]?.bgColor || 'bg-gray-100'} ${statusConfig[item.status]?.color || 'text-gray-600'}`}>
                              {statusConfig[item.status]?.label || item.status}
                            </span>
                          </td>
                          <td className="whitespace-nowrap px-6 py-3 text-sm text-gray-500">
                            {item.attack_type || '-'}
                          </td>
                          <td className="whitespace-nowrap px-6 py-3 text-sm text-gray-500">
                            {item.response_time_ms ? `${item.response_time_ms}ms` : '-'}
                          </td>
                          <td className="whitespace-nowrap px-6 py-3 text-sm">
                            {item.matched_log_id ? (
                              <span className="text-blue-600 font-mono text-xs" title={item.matched_log_id}>
                                {item.matched_log_id.slice(0, 8)}...
                              </span>
                            ) : (
                              <span className="text-gray-400">-</span>
                            )}
                          </td>
                          <td className="whitespace-nowrap px-6 py-3 text-sm text-gray-500">
                            {item.executed_at ? new Date(item.executed_at).toLocaleString('zh-CN') : '-'}
                          </td>
                          <td className="px-6 py-3 text-sm text-red-500 truncate max-w-xs" title={item.error_message || ''}>
                            {item.error_message || '-'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          ) : (
            <div className="rounded-lg border bg-white p-6 shadow-sm text-center text-gray-500">
              测试不存在
            </div>
          )}
        </div>
      )}
    </div>
  )
}

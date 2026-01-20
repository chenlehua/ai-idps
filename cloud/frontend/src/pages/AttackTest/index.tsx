import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { attacksApi, rulesApi, probesApi } from '../../services/api'
import { Card, Button, Badge, Input, Select, Pagination, ProgressBar } from '../../components/common'

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
const statusConfig: Record<string, { label: string; variant: 'gray' | 'info' | 'success' | 'error' | 'warning' }> = {
  pending: { label: '待执行', variant: 'gray' },
  running: { label: '执行中', variant: 'info' },
  completed: { label: '已完成', variant: 'success' },
  failed: { label: '失败', variant: 'error' },
  cancelled: { label: '已取消', variant: 'gray' },
  success: { label: '成功', variant: 'success' },
  timeout: { label: '超时', variant: 'warning' },
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
    refetchInterval: selectedTest ? 3000 : false
  })

  // 获取测试详情
  const { data: testDetail, isLoading: detailLoading } = useQuery({
    queryKey: ['attack-test', selectedTest],
    queryFn: () => attacksApi.getTest(selectedTest!),
    enabled: !!selectedTest,
    refetchInterval: 3000
  })

  // 获取探针列表
  const { data: probesData } = useQuery({
    queryKey: ['probes'],
    queryFn: () => probesApi.list()
  })

  // 获取规则列表
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

  const toggleRuleSelection = (sid: number) => {
    setSelectedRules(prev =>
      prev.includes(sid) ? prev.filter(s => s !== sid) : [...prev, sid]
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
    <div className="space-y-6 animate-fade-in">
      {/* 页面标题 */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">攻击测试</h1>
          <p className="mt-1 text-sm text-slate-500">验证规则有效性的自动化测试</p>
        </div>
        <Button
          variant={activeTab === 'list' ? 'primary' : 'secondary'}
          onClick={() => setActiveTab(activeTab === 'list' ? 'create' : 'list')}
          icon={
            activeTab === 'list' ? (
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
            ) : (
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
            )
          }
        >
          {activeTab === 'list' ? '创建测试' : '返回列表'}
        </Button>
      </div>

      {/* 创建测试 */}
      {activeTab === 'create' && (
        <div className="space-y-6">
          {/* 基本信息 */}
          <Card>
            <Card.Header>测试配置</Card.Header>
            <Card.Body>
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                <Input
                  label="测试名称 (可选)"
                  value={testName}
                  onChange={(e) => setTestName(e.target.value)}
                  placeholder="例如：SQL注入规则测试"
                />
                <Select
                  label="执行探针"
                  value={selectedProbe}
                  onChange={(e) => setSelectedProbe(e.target.value)}
                  placeholder="选择探针"
                  options={probes.map((probe) => ({
                    value: probe.node_id,
                    label: `${probe.name} (${probe.node_id})`
                  }))}
                />
              </div>
            </Card.Body>
          </Card>

          {/* 规则选择 */}
          <Card>
            <Card.Header
              action={
                <Input
                  value={ruleSearch}
                  onChange={(e) => setRuleSearch(e.target.value)}
                  placeholder="搜索 SID 或消息"
                  className="w-64"
                />
              }
            >
              选择规则
              {selectedRules.length > 0 && (
                <Badge variant="primary" className="ml-2">已选 {selectedRules.length} 条</Badge>
              )}
            </Card.Header>

            <div className="max-h-80 overflow-y-auto">
              {rulesLoading ? (
                <div className="flex items-center justify-center py-12 text-slate-400">
                  <svg className="animate-spin h-6 w-6 mr-2" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  加载中...
                </div>
              ) : rules.length > 0 ? (
                <table className="min-w-full">
                  <thead className="bg-slate-50 sticky top-0">
                    <tr>
                      <th className="w-12 px-6 py-3 text-left">
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
                          className="h-4 w-4 rounded border-slate-300 text-stripe-primary focus:ring-stripe-primary"
                        />
                      </th>
                      <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">SID</th>
                      <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">消息</th>
                      <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">分类</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {rules.map((rule) => (
                      <tr
                        key={rule.sid}
                        className={`cursor-pointer transition-colors ${selectedRules.includes(rule.sid) ? 'bg-stripe-primary/5' : 'hover:bg-slate-50'}`}
                        onClick={() => toggleRuleSelection(rule.sid)}
                      >
                        <td className="px-6 py-3">
                          <input
                            type="checkbox"
                            checked={selectedRules.includes(rule.sid)}
                            onChange={() => toggleRuleSelection(rule.sid)}
                            onClick={(e) => e.stopPropagation()}
                            className="h-4 w-4 rounded border-slate-300 text-stripe-primary focus:ring-stripe-primary"
                          />
                        </td>
                        <td className="whitespace-nowrap px-6 py-3 font-mono text-sm text-slate-700">{rule.sid}</td>
                        <td className="px-6 py-3 text-sm text-slate-600 truncate max-w-md">{rule.msg || '-'}</td>
                        <td className="whitespace-nowrap px-6 py-3 text-sm text-slate-500">{rule.classtype || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="flex items-center justify-center py-12 text-slate-400">没有找到规则</div>
              )}
            </div>

            <Card.Footer>
              <Button
                variant="success"
                onClick={handleCreateTest}
                disabled={selectedRules.length === 0 || !selectedProbe}
                loading={createMutation.isPending}
              >
                创建测试 ({selectedRules.length} 条规则)
              </Button>
              {createMutation.isError && (
                <span className="ml-4 text-sm text-error">
                  创建失败: {(createMutation.error as Error).message}
                </span>
              )}
            </Card.Footer>
          </Card>
        </div>
      )}

      {/* 测试列表 */}
      {activeTab === 'list' && !selectedTest && (
        <Card>
          <Card.Header>测试列表</Card.Header>

          {testsLoading ? (
            <Card.Body className="flex items-center justify-center py-12 text-slate-400">
              <svg className="animate-spin h-6 w-6 mr-2" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              加载中...
            </Card.Body>
          ) : tests.length > 0 ? (
            <>
              <div className="overflow-x-auto">
                <table className="min-w-full">
                  <thead className="bg-slate-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">测试ID</th>
                      <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">名称</th>
                      <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">状态</th>
                      <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">进度</th>
                      <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">探针</th>
                      <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">创建时间</th>
                      <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">操作</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {tests.map((test) => (
                      <tr key={test.id} className="hover:bg-slate-50 transition-colors">
                        <td className="whitespace-nowrap px-6 py-4">
                          <span className="font-mono text-sm text-slate-700">{test.test_id.slice(-12)}</span>
                        </td>
                        <td className="px-6 py-4 text-sm text-slate-600">{test.name || '-'}</td>
                        <td className="whitespace-nowrap px-6 py-4">
                          <Badge variant={statusConfig[test.status]?.variant || 'gray'}>
                            {statusConfig[test.status]?.label || test.status}
                          </Badge>
                        </td>
                        <td className="whitespace-nowrap px-6 py-4">
                          <div className="flex items-center gap-3">
                            <ProgressBar
                              value={test.progress_percent}
                              variant={test.status === 'completed' ? 'success' : 'primary'}
                              className="w-24"
                            />
                            <span className="text-xs text-slate-500">
                              {test.success_count}/{test.total_rules}
                            </span>
                          </div>
                        </td>
                        <td className="whitespace-nowrap px-6 py-4 text-sm text-slate-500">
                          {test.probe_id || '-'}
                        </td>
                        <td className="whitespace-nowrap px-6 py-4 text-sm text-slate-500">
                          {test.created_at ? new Date(test.created_at).toLocaleString('zh-CN') : '-'}
                        </td>
                        <td className="whitespace-nowrap px-6 py-4">
                          <Button variant="text" size="sm" onClick={() => setSelectedTest(test.test_id)}>
                            详情
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="border-t border-slate-100 px-6 py-4">
                <Pagination
                  current={page}
                  total={total}
                  pageSize={20}
                  onChange={setPage}
                />
              </div>
            </>
          ) : (
            <Card.Body className="flex flex-col items-center justify-center py-12 text-slate-400">
              <svg className="w-12 h-12 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
              暂无测试，点击"创建测试"开始
            </Card.Body>
          )}
        </Card>
      )}

      {/* 测试详情 */}
      {activeTab === 'list' && selectedTest && (
        <div className="space-y-6">
          <Button
            variant="text"
            onClick={() => setSelectedTest(null)}
            icon={
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
            }
          >
            返回列表
          </Button>

          {detailLoading ? (
            <Card>
              <Card.Body className="flex items-center justify-center py-12 text-slate-400">
                <svg className="animate-spin h-6 w-6 mr-2" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                加载中...
              </Card.Body>
            </Card>
          ) : testDetail ? (
            <>
              {/* 测试概况 */}
              <Card>
                <Card.Body>
                  <div className="flex items-center justify-between mb-6">
                    <div>
                      <h2 className="text-lg font-semibold text-slate-900">{testDetail.name || testDetail.test_id}</h2>
                      <p className="text-sm text-slate-500 mt-1">
                        探针: {testDetail.probe_id} | 创建: {testDetail.created_at ? new Date(testDetail.created_at).toLocaleString('zh-CN') : '-'}
                      </p>
                    </div>
                    <div className="flex items-center gap-3">
                      <Badge variant={statusConfig[testDetail.status]?.variant || 'gray'} size="md">
                        {statusConfig[testDetail.status]?.label || testDetail.status}
                      </Badge>
                      {testDetail.status === 'pending' && (
                        <Button
                          variant="success"
                          size="sm"
                          onClick={() => startMutation.mutate(testDetail.test_id)}
                          loading={startMutation.isPending}
                        >
                          启动测试
                        </Button>
                      )}
                      {(testDetail.status === 'pending' || testDetail.status === 'running') && (
                        <Button
                          variant="danger"
                          size="sm"
                          onClick={() => cancelMutation.mutate(testDetail.test_id)}
                          loading={cancelMutation.isPending}
                        >
                          取消
                        </Button>
                      )}
                    </div>
                  </div>

                  {/* 统计卡片 */}
                  <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
                    <div className="rounded-lg bg-slate-50 p-4">
                      <div className="text-sm text-slate-500">总规则数</div>
                      <div className="mt-1 text-2xl font-semibold text-slate-900">{testDetail.total_rules}</div>
                    </div>
                    <div className="rounded-lg bg-success-light p-4">
                      <div className="text-sm text-success-dark">成功</div>
                      <div className="mt-1 text-2xl font-semibold text-success-dark">{testDetail.success_count}</div>
                    </div>
                    <div className="rounded-lg bg-error-light p-4">
                      <div className="text-sm text-error-dark">失败</div>
                      <div className="mt-1 text-2xl font-semibold text-error-dark">{testDetail.failed_count}</div>
                    </div>
                    <div className="rounded-lg bg-info-light p-4">
                      <div className="text-sm text-info-dark">进度</div>
                      <div className="mt-1 text-2xl font-semibold text-info-dark">{testDetail.progress_percent.toFixed(1)}%</div>
                    </div>
                  </div>

                  {testDetail.status === 'running' && (
                    <div className="mt-4">
                      <ProgressBar value={testDetail.progress_percent} variant="primary" size="lg" />
                    </div>
                  )}
                </Card.Body>
              </Card>

              {/* 测试项列表 */}
              <Card>
                <Card.Header>测试项详情</Card.Header>
                <div className="max-h-96 overflow-y-auto">
                  <table className="min-w-full">
                    <thead className="bg-slate-50 sticky top-0">
                      <tr>
                        <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">SID</th>
                        <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">状态</th>
                        <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">攻击类型</th>
                        <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">响应时间</th>
                        <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">关联日志</th>
                        <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">执行时间</th>
                        <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">错误信息</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {(testDetail.items || []).map((item: TestItem) => (
                        <tr key={item.id} className="hover:bg-slate-50">
                          <td className="whitespace-nowrap px-6 py-3 font-mono text-sm">{item.sid}</td>
                          <td className="whitespace-nowrap px-6 py-3">
                            <Badge variant={statusConfig[item.status]?.variant || 'gray'}>
                              {statusConfig[item.status]?.label || item.status}
                            </Badge>
                          </td>
                          <td className="whitespace-nowrap px-6 py-3 text-sm text-slate-500">{item.attack_type || '-'}</td>
                          <td className="whitespace-nowrap px-6 py-3 text-sm text-slate-500">
                            {item.response_time_ms ? `${item.response_time_ms}ms` : '-'}
                          </td>
                          <td className="whitespace-nowrap px-6 py-3">
                            {item.matched_log_id ? (
                              <span className="text-stripe-primary font-mono text-xs" title={item.matched_log_id}>
                                {item.matched_log_id.slice(0, 8)}...
                              </span>
                            ) : (
                              <span className="text-slate-400">-</span>
                            )}
                          </td>
                          <td className="whitespace-nowrap px-6 py-3 text-sm text-slate-500">
                            {item.executed_at ? new Date(item.executed_at).toLocaleString('zh-CN') : '-'}
                          </td>
                          <td className="px-6 py-3 text-sm text-error truncate max-w-xs" title={item.error_message || ''}>
                            {item.error_message || '-'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Card>
            </>
          ) : (
            <Card>
              <Card.Body className="text-center py-12 text-slate-400">测试不存在</Card.Body>
            </Card>
          )}
        </div>
      )}
    </div>
  )
}

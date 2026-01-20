import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { rulesApi } from '../../services/api'
import { Card, Button, Badge, Input, Select, Modal, Toggle, Pagination } from '../../components/common'

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
const severityConfig: Record<number, { label: string; variant: 'error' | 'warning' | 'info' | 'gray' }> = {
  1: { label: '高', variant: 'error' },
  2: { label: '中高', variant: 'warning' },
  3: { label: '中', variant: 'info' },
  4: { label: '低', variant: 'gray' }
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

  // 获取活跃筛选数量
  const activeFilterCount = Object.values(filters).filter(v => v !== '').length

  return (
    <div className="space-y-6 animate-fade-in">
      {/* 页面标题 */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">规则管理</h1>
          <p className="mt-1 text-sm text-slate-500">
            共 {total.toLocaleString()} 条规则
          </p>
        </div>
        <Button
          variant={activeFilterCount > 0 ? 'primary' : 'secondary'}
          onClick={() => setShowFilters(!showFilters)}
          icon={
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z" />
            </svg>
          }
        >
          筛选 {activeFilterCount > 0 && `(${activeFilterCount})`}
        </Button>
      </div>

      {/* 筛选面板 */}
      {showFilters && (
        <Card className="animate-fade-in">
          <Card.Body>
            <div className="grid grid-cols-2 gap-4 md:grid-cols-3 lg:grid-cols-6">
              {/* 搜索 */}
              <div className="col-span-2 md:col-span-1">
                <Input
                  label="搜索"
                  value={filters.search}
                  onChange={(e) => setFilters({ ...filters, search: e.target.value })}
                  onKeyDown={(e) => e.key === 'Enter' && setPage(0)}
                  placeholder="SID 或消息内容"
                />
              </div>

              {/* classtype */}
              <div>
                <Select
                  label="Classtype"
                  value={filters.classtype}
                  onChange={(e) => setFilters({ ...filters, classtype: e.target.value })}
                  placeholder="全部"
                  options={categories?.classtype?.map((cat) => ({
                    value: cat.category_name,
                    label: `${cat.category_name} (${cat.rule_count})`
                  })) || []}
                />
              </div>

              {/* 分类 */}
              <div>
                <Select
                  label="分类"
                  value={filters.category}
                  onChange={(e) => setFilters({ ...filters, category: e.target.value })}
                  placeholder="全部"
                  options={categories?.msg_prefix?.map((cat) => ({
                    value: cat.category_name,
                    label: `${cat.category_name} (${cat.rule_count})`
                  })) || []}
                />
              </div>

              {/* 严重级别 */}
              <div>
                <Select
                  label="严重级别"
                  value={filters.severity === '' ? '' : String(filters.severity)}
                  onChange={(e) => setFilters({ ...filters, severity: e.target.value === '' ? '' : Number(e.target.value) })}
                  placeholder="全部"
                  options={[1, 2, 3, 4].map((s) => ({
                    value: String(s),
                    label: `${severityConfig[s].label} (${categories?.severity_stats?.[s] || 0})`
                  }))}
                />
              </div>

              {/* 协议 */}
              <div>
                <Select
                  label="协议"
                  value={filters.protocol}
                  onChange={(e) => setFilters({ ...filters, protocol: e.target.value })}
                  placeholder="全部"
                  options={Object.entries(categories?.protocol_stats || {}).map(([proto, count]) => ({
                    value: proto,
                    label: `${proto.toUpperCase()} (${count})`
                  }))}
                />
              </div>

              {/* 状态 */}
              <div>
                <Select
                  label="状态"
                  value={filters.enabled === '' ? '' : String(filters.enabled)}
                  onChange={(e) => setFilters({ ...filters, enabled: e.target.value === '' ? '' : e.target.value === 'true' })}
                  placeholder="全部"
                  options={[
                    { value: 'true', label: '已启用' },
                    { value: 'false', label: '已禁用' }
                  ]}
                />
              </div>
            </div>

            <div className="mt-4 flex gap-3">
              <Button onClick={() => setPage(0)}>应用筛选</Button>
              <Button variant="secondary" onClick={resetFilters}>重置</Button>
            </div>
          </Card.Body>
        </Card>
      )}

      {/* 规则列表 */}
      <Card>
        {isLoading ? (
          <div className="flex items-center justify-center py-12 text-slate-400">
            <svg className="animate-spin h-6 w-6 mr-2" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            加载中...
          </div>
        ) : rules.length > 0 ? (
          <>
            <div className="overflow-x-auto">
              <table className="min-w-full">
                <thead className="bg-slate-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">SID</th>
                    <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">消息</th>
                    <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">分类</th>
                    <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">协议</th>
                    <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">级别</th>
                    <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">状态</th>
                    <th className="px-6 py-3 text-left text-sm font-semibold text-slate-700">操作</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {rules.map((rule) => (
                    <tr key={rule.id} className="hover:bg-slate-50 transition-colors">
                      <td className="whitespace-nowrap px-6 py-4">
                        <span className="font-mono text-sm text-slate-700">{rule.sid}</span>
                      </td>
                      <td className="px-6 py-4">
                        <div className="max-w-md truncate text-sm text-slate-700" title={rule.msg || ''}>
                          {rule.msg || '-'}
                        </div>
                        {rule.classtype && (
                          <div className="mt-1 text-xs text-slate-400">{rule.classtype}</div>
                        )}
                      </td>
                      <td className="whitespace-nowrap px-6 py-4">
                        {rule.category && (
                          <Badge variant="gray">{rule.category}</Badge>
                        )}
                      </td>
                      <td className="whitespace-nowrap px-6 py-4 text-sm text-slate-500">
                        {rule.protocol?.toUpperCase() || '-'}
                      </td>
                      <td className="whitespace-nowrap px-6 py-4">
                        <Badge variant={severityConfig[rule.severity]?.variant || 'gray'}>
                          {severityConfig[rule.severity]?.label || rule.severity}
                        </Badge>
                      </td>
                      <td className="whitespace-nowrap px-6 py-4">
                        <Toggle
                          checked={rule.enabled}
                          onChange={() => toggleMutation.mutate({ sid: rule.sid, enabled: !rule.enabled })}
                          disabled={toggleMutation.isPending}
                          size="sm"
                        />
                      </td>
                      <td className="whitespace-nowrap px-6 py-4">
                        <Button
                          variant="text"
                          size="sm"
                          onClick={() => setSelectedRule(rule.sid)}
                        >
                          详情
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* 分页 */}
            <div className="border-t border-slate-100 px-6 py-4">
              <Pagination
                current={page}
                total={total}
                pageSize={pageSize}
                onChange={setPage}
              />
            </div>
          </>
        ) : (
          <div className="flex flex-col items-center justify-center py-12 text-slate-400">
            <svg className="w-12 h-12 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
            </svg>
            {activeFilterCount > 0 ? '没有匹配的规则' : '暂无规则数据'}
          </div>
        )}
      </Card>

      {/* 规则详情弹窗 */}
      <Modal
        isOpen={selectedRule !== null}
        onClose={() => setSelectedRule(null)}
        title={`规则详情 - SID: ${selectedRule}`}
        size="lg"
        footer={
          <div className="flex justify-between">
            <Button variant="secondary" onClick={() => setSelectedRule(null)}>关闭</Button>
            {ruleDetail && (
              <Button
                variant={ruleDetail.enabled ? 'danger' : 'success'}
                onClick={() => toggleMutation.mutate({ sid: ruleDetail.sid, enabled: !ruleDetail.enabled })}
                loading={toggleMutation.isPending}
              >
                {ruleDetail.enabled ? '禁用规则' : '启用规则'}
              </Button>
            )}
          </div>
        }
      >
        {detailLoading ? (
          <div className="flex items-center justify-center py-8 text-slate-400">
            <svg className="animate-spin h-6 w-6 mr-2" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            加载中...
          </div>
        ) : ruleDetail ? (
          <div className="space-y-6">
            {/* 基本信息 */}
            <div className="grid grid-cols-2 gap-4 md:grid-cols-3">
              <div>
                <label className="text-sm font-medium text-slate-500">SID</label>
                <div className="mt-1 font-mono text-slate-900">{ruleDetail.sid}</div>
              </div>
              <div>
                <label className="text-sm font-medium text-slate-500">GID</label>
                <div className="mt-1 font-mono text-slate-900">{ruleDetail.gid}</div>
              </div>
              <div>
                <label className="text-sm font-medium text-slate-500">版本 (Rev)</label>
                <div className="mt-1 text-slate-900">{ruleDetail.rev}</div>
              </div>
              <div>
                <label className="text-sm font-medium text-slate-500">动作</label>
                <div className="mt-1 text-slate-900">{ruleDetail.action}</div>
              </div>
              <div>
                <label className="text-sm font-medium text-slate-500">协议</label>
                <div className="mt-1 text-slate-900">{ruleDetail.protocol?.toUpperCase() || '-'}</div>
              </div>
              <div>
                <label className="text-sm font-medium text-slate-500">严重级别</label>
                <div className="mt-1">
                  <Badge variant={severityConfig[ruleDetail.severity]?.variant || 'gray'}>
                    {severityConfig[ruleDetail.severity]?.label || ruleDetail.severity}
                  </Badge>
                </div>
              </div>
            </div>

            {/* 消息 */}
            <div>
              <label className="text-sm font-medium text-slate-500">消息</label>
              <div className="mt-1 text-slate-700">{ruleDetail.msg || '-'}</div>
            </div>

            {/* 网络信息 */}
            <div>
              <label className="text-sm font-medium text-slate-500">网络</label>
              <div className="mt-1 font-mono text-sm text-slate-700 p-3 bg-slate-50 rounded-lg">
                {ruleDetail.src_addr || 'any'}:{ruleDetail.src_port || 'any'}{' '}
                {ruleDetail.direction}{' '}
                {ruleDetail.dst_addr || 'any'}:{ruleDetail.dst_port || 'any'}
              </div>
            </div>

            {/* MITRE ATT&CK */}
            {ruleDetail.mitre_attack && (
              <div>
                <label className="text-sm font-medium text-slate-500">MITRE ATT&CK</label>
                <div className="mt-1">
                  <Badge variant="primary">{ruleDetail.mitre_attack}</Badge>
                </div>
              </div>
            )}

            {/* 24小时告警数 */}
            <div>
              <label className="text-sm font-medium text-slate-500">24小时告警数</label>
              <div className={`mt-1 text-lg font-semibold ${ruleDetail.alert_count_24h > 0 ? 'text-error' : 'text-slate-400'}`}>
                {ruleDetail.alert_count_24h}
              </div>
            </div>

            {/* 规则内容 */}
            {ruleDetail.content && (
              <div>
                <label className="text-sm font-medium text-slate-500">规则内容</label>
                <pre className="mt-1 p-4 overflow-x-auto whitespace-pre-wrap rounded-lg bg-slate-900 font-mono text-sm text-slate-100">
                  {ruleDetail.content}
                </pre>
              </div>
            )}

            {/* 元数据 */}
            {ruleDetail.metadata && Object.keys(ruleDetail.metadata).length > 0 && (
              <div>
                <label className="text-sm font-medium text-slate-500">元数据</label>
                <div className="mt-1 flex flex-wrap gap-2">
                  {Object.entries(ruleDetail.metadata).map(([key, value]) => (
                    <span key={key} className="inline-flex rounded-md bg-slate-100 px-2 py-1 text-xs text-slate-600">
                      <span className="font-medium">{key}:</span>
                      <span className="ml-1">{value}</span>
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="text-center text-slate-400 py-8">无法加载规则详情</div>
        )}
      </Modal>
    </div>
  )
}

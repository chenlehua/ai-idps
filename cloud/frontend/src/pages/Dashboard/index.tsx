import { useQuery } from '@tanstack/react-query'
import { probesApi, logsApi } from '../../services/api'
import { Card, StatCard, Badge, StatusDot } from '../../components/common'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend
} from 'recharts'

const SEVERITY_COLORS = {
  1: '#DF1B41', // 严重 - 红色
  2: '#F5A623', // 高 - 橙色
  3: '#FBBF24', // 中 - 黄色
  4: '#33C27F'  // 低 - 绿色
}

const SEVERITY_LABELS: Record<number, string> = {
  1: '严重',
  2: '高',
  3: '中',
  4: '低'
}

export default function DashboardPage() {
  // 获取探针数据
  const { data: probesData, isLoading: probesLoading } = useQuery({
    queryKey: ['probes'],
    queryFn: () => probesApi.list(),
    refetchInterval: 30000
  })

  // 获取日志统计
  const { data: statsData, isLoading: statsLoading } = useQuery({
    queryKey: ['logs-stats'],
    queryFn: () => logsApi.stats(24),
    refetchInterval: 60000
  })

  // 计算统计信息
  const probes = probesData?.probes || []
  const onlineProbes = probes.filter((p: any) => p.status === 'online').length
  const offlineProbes = probes.filter((p: any) => p.status === 'offline').length

  // 处理图表数据
  const hourlyData = statsData?.stats || []
  
  // 按小时聚合数据
  const hourlyChartData = hourlyData.reduce((acc: any[], item: any) => {
    const hour = item[0] || item.hour
    const severity = item[1] || item.severity
    const count = item[2] || item.count
    
    let existing = acc.find(d => d.hour === hour)
    if (!existing) {
      existing = { hour, total: 0 }
      acc.push(existing)
    }
    existing.total += count
    existing[`severity_${severity}`] = count
    
    return acc
  }, []).slice(-24)

  // 按严重级别统计
  const severityData = hourlyData.reduce((acc: any, item: any) => {
    const severity = item[1] || item.severity
    const count = item[2] || item.count
    if (!acc[severity]) {
      acc[severity] = { name: SEVERITY_LABELS[severity] || `级别${severity}`, value: 0, severity }
    }
    acc[severity].value += count
    return acc
  }, {} as Record<number, any>)

  const pieData = Object.values(severityData)
  const totalAlerts = pieData.reduce((sum: number, item: any) => sum + item.value, 0)

  const isLoading = probesLoading || statsLoading

  return (
    <div className="space-y-8 animate-fade-in">
      {/* 页面标题 */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">仪表盘</h1>
          <p className="mt-1 text-sm text-slate-500">系统概览与实时监控</p>
        </div>
        <div className="flex items-center gap-2 text-sm text-slate-500">
          <StatusDot status="online" pulse />
          数据每30秒自动刷新
        </div>
      </div>

      {/* 统计卡片 */}
      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="在线探针"
          value={isLoading ? '-' : onlineProbes}
          subtitle={`共 ${probes.length} 个探针`}
          variant="success"
          icon={
            <svg className="w-6 h-6 text-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
            </svg>
          }
        />
        <StatCard
          title="离线探针"
          value={isLoading ? '-' : offlineProbes}
          subtitle="需要关注"
          variant={offlineProbes > 0 ? 'error' : 'default'}
          icon={
            <svg className="w-6 h-6 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 5.636a9 9 0 010 12.728m0 0l-2.829-2.829m2.829 2.829L21 21M15.536 8.464a5 5 0 010 7.072m0 0l-2.829-2.829m-4.243 2.829a4.978 4.978 0 01-1.414-2.83m-1.414 5.658a9 9 0 01-2.167-9.238m7.824 2.167a1 1 0 111.414 1.414m-1.414-1.414L3 3m8.293 8.293l1.414 1.414" />
            </svg>
          }
        />
        <StatCard
          title="24小时告警"
          value={isLoading ? '-' : totalAlerts.toLocaleString()}
          subtitle="告警总数"
          variant="info"
          icon={
            <svg className="w-6 h-6 text-info" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
            </svg>
          }
        />
        <StatCard
          title="高危告警"
          value={isLoading ? '-' : (severityData[1]?.value || 0) + (severityData[2]?.value || 0)}
          subtitle="严重 + 高级别"
          variant={(severityData[1]?.value || 0) > 0 ? 'error' : 'warning'}
          icon={
            <svg className="w-6 h-6 text-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          }
        />
      </div>

      {/* 图表区域 */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* 24小时告警趋势 */}
        <Card>
          <Card.Header>24小时告警趋势</Card.Header>
          <Card.Body className="pt-4">
            {isLoading ? (
              <div className="flex h-72 items-center justify-center text-slate-400">
                <svg className="animate-spin h-6 w-6 mr-2" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                加载中...
              </div>
            ) : hourlyChartData.length > 0 ? (
              <ResponsiveContainer width="100%" height={280}>
                <LineChart data={hourlyChartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#E3E8EF" />
                  <XAxis 
                    dataKey="hour" 
                    tick={{ fontSize: 12, fill: '#5B7083' }}
                    tickFormatter={(value) => {
                      const date = new Date(value)
                      return `${date.getHours()}:00`
                    }}
                    axisLine={{ stroke: '#E3E8EF' }}
                    tickLine={{ stroke: '#E3E8EF' }}
                  />
                  <YAxis 
                    tick={{ fontSize: 12, fill: '#5B7083' }}
                    axisLine={{ stroke: '#E3E8EF' }}
                    tickLine={{ stroke: '#E3E8EF' }}
                  />
                  <Tooltip 
                    labelFormatter={(value) => {
                      const date = new Date(value)
                      return date.toLocaleString('zh-CN')
                    }}
                    contentStyle={{
                      backgroundColor: 'white',
                      border: '1px solid #E3E8EF',
                      borderRadius: '8px',
                      boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.08)',
                    }}
                  />
                  <Legend />
                  <Line 
                    type="monotone" 
                    dataKey="total" 
                    stroke="#635BFF" 
                    strokeWidth={2}
                    name="告警数"
                    dot={false}
                    activeDot={{ r: 6, fill: '#635BFF' }}
                  />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-72 flex-col items-center justify-center text-slate-400">
                <svg className="w-12 h-12 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                暂无告警数据
              </div>
            )}
          </Card.Body>
        </Card>

        {/* 告警级别分布 */}
        <Card>
          <Card.Header>告警级别分布</Card.Header>
          <Card.Body className="pt-4">
            {isLoading ? (
              <div className="flex h-72 items-center justify-center text-slate-400">
                <svg className="animate-spin h-6 w-6 mr-2" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                加载中...
              </div>
            ) : pieData.length > 0 ? (
              <ResponsiveContainer width="100%" height={280}>
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    outerRadius={100}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {pieData.map((entry: any, index: number) => (
                      <Cell 
                        key={`cell-${index}`} 
                        fill={SEVERITY_COLORS[entry.severity as keyof typeof SEVERITY_COLORS] || '#5B7083'} 
                      />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{
                      backgroundColor: 'white',
                      border: '1px solid #E3E8EF',
                      borderRadius: '8px',
                      boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.08)',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-72 flex-col items-center justify-center text-slate-400">
                <svg className="w-12 h-12 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M11 3.055A9.001 9.001 0 1020.945 13H11V3.055z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M20.488 9H15V3.512A9.025 9.025 0 0120.488 9z" />
                </svg>
                暂无告警数据
              </div>
            )}
          </Card.Body>
        </Card>
      </div>

      {/* 探针状态列表 */}
      <Card>
        <Card.Header>探针状态概览</Card.Header>
        <Card.Body>
          {isLoading ? (
            <div className="flex items-center justify-center py-8 text-slate-400">
              <svg className="animate-spin h-6 w-6 mr-2" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              加载中...
            </div>
          ) : probes.length > 0 ? (
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
              {probes.slice(0, 6).map((probe: any) => (
                <div 
                  key={probe.node_id} 
                  className="flex items-center justify-between p-4 rounded-lg border border-slate-100 bg-slate-50/50 hover:bg-slate-100/50 transition-colors"
                >
                  <div>
                    <div className="font-medium text-slate-900">{probe.name}</div>
                    <div className="text-sm text-slate-500 font-mono">{probe.ip_address}</div>
                  </div>
                  <Badge 
                    variant={probe.status === 'online' ? 'success' : probe.status === 'offline' ? 'error' : 'gray'}
                    dot
                  >
                    {probe.status === 'online' ? '在线' : probe.status === 'offline' ? '离线' : '未知'}
                  </Badge>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-12 text-slate-400">
              <svg className="w-12 h-12 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
              </svg>
              暂无探针数据
            </div>
          )}
        </Card.Body>
      </Card>
    </div>
  )
}

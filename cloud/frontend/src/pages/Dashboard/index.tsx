import { useQuery } from '@tanstack/react-query'
import { dashboardApi, logsApi, probesApi } from '../../services/api'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  Legend
} from 'recharts'

const SEVERITY_COLORS = {
  1: '#ef4444', // 红色 - 严重
  2: '#f97316', // 橙色 - 高
  3: '#eab308', // 黄色 - 中
  4: '#22c55e'  // 绿色 - 低
}

const SEVERITY_LABELS: Record<number, string> = {
  1: '严重',
  2: '高',
  3: '中',
  4: '低'
}

interface StatCardProps {
  title: string
  value: string | number
  subtitle?: string
  color?: string
}

function StatCard({ title, value, subtitle, color = 'blue' }: StatCardProps) {
  const colorClasses: Record<string, string> = {
    blue: 'bg-blue-50 border-blue-200 text-blue-700',
    green: 'bg-green-50 border-green-200 text-green-700',
    yellow: 'bg-yellow-50 border-yellow-200 text-yellow-700',
    red: 'bg-red-50 border-red-200 text-red-700'
  }

  return (
    <div className={`rounded-lg border p-6 ${colorClasses[color]}`}>
      <div className="text-sm font-medium opacity-80">{title}</div>
      <div className="mt-2 text-3xl font-bold">{value}</div>
      {subtitle && <div className="mt-1 text-xs opacity-70">{subtitle}</div>}
    </div>
  )
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
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">仪表盘</h1>
        <div className="text-sm text-gray-500">
          数据每30秒自动刷新
        </div>
      </div>

      {/* 统计卡片 */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="在线探针"
          value={isLoading ? '-' : onlineProbes}
          subtitle={`共 ${probes.length} 个探针`}
          color="green"
        />
        <StatCard
          title="离线探针"
          value={isLoading ? '-' : offlineProbes}
          subtitle="需要关注"
          color={offlineProbes > 0 ? 'red' : 'green'}
        />
        <StatCard
          title="24小时告警"
          value={isLoading ? '-' : totalAlerts}
          subtitle="告警总数"
          color="blue"
        />
        <StatCard
          title="高危告警"
          value={isLoading ? '-' : (severityData[1]?.value || 0) + (severityData[2]?.value || 0)}
          subtitle="严重+高级别"
          color={(severityData[1]?.value || 0) > 0 ? 'red' : 'yellow'}
        />
      </div>

      {/* 图表区域 */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* 24小时告警趋势 */}
        <div className="rounded-lg border bg-white p-6 shadow-sm">
          <h2 className="mb-4 text-lg font-semibold">24小时告警趋势</h2>
          {isLoading ? (
            <div className="flex h-64 items-center justify-center text-gray-500">
              加载中...
            </div>
          ) : hourlyChartData.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <LineChart data={hourlyChartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis 
                  dataKey="hour" 
                  tick={{ fontSize: 12 }}
                  tickFormatter={(value) => {
                    const date = new Date(value)
                    return `${date.getHours()}:00`
                  }}
                />
                <YAxis tick={{ fontSize: 12 }} />
                <Tooltip 
                  labelFormatter={(value) => {
                    const date = new Date(value)
                    return date.toLocaleString('zh-CN')
                  }}
                />
                <Legend />
                <Line 
                  type="monotone" 
                  dataKey="total" 
                  stroke="#3b82f6" 
                  strokeWidth={2}
                  name="告警数"
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-64 items-center justify-center text-gray-500">
              暂无告警数据
            </div>
          )}
        </div>

        {/* 告警级别分布 */}
        <div className="rounded-lg border bg-white p-6 shadow-sm">
          <h2 className="mb-4 text-lg font-semibold">告警级别分布</h2>
          {isLoading ? (
            <div className="flex h-64 items-center justify-center text-gray-500">
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
                      fill={SEVERITY_COLORS[entry.severity as keyof typeof SEVERITY_COLORS] || '#6b7280'} 
                    />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-64 items-center justify-center text-gray-500">
              暂无告警数据
            </div>
          )}
        </div>
      </div>

      {/* 探针状态列表 */}
      <div className="rounded-lg border bg-white p-6 shadow-sm">
        <h2 className="mb-4 text-lg font-semibold">探针状态概览</h2>
        {isLoading ? (
          <div className="text-gray-500">加载中...</div>
        ) : probes.length > 0 ? (
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
            {probes.slice(0, 6).map((probe: any) => (
              <div 
                key={probe.node_id} 
                className="flex items-center justify-between rounded-lg border p-4"
              >
                <div>
                  <div className="font-medium">{probe.name}</div>
                  <div className="text-sm text-gray-500">{probe.ip_address}</div>
                </div>
                <div className="flex items-center gap-2">
                  <span 
                    className={`h-3 w-3 rounded-full ${
                      probe.status === 'online' ? 'bg-green-500' : 
                      probe.status === 'offline' ? 'bg-red-500' : 'bg-gray-400'
                    }`} 
                  />
                  <span className="text-sm text-gray-600">
                    {probe.status === 'online' ? '在线' : 
                     probe.status === 'offline' ? '离线' : '未知'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-gray-500">暂无探针数据</div>
        )}
      </div>
    </div>
  )
}

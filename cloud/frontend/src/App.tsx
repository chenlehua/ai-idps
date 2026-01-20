import { NavLink, Route, Routes } from 'react-router-dom'
import DashboardPage from './pages/Dashboard'
import RuleUpdatePage from './pages/RuleUpdate'
import RuleListPage from './pages/RuleList'
import AttackTestPage from './pages/AttackTest'
import LogsPage from './pages/Logs'
import ProbesPage from './pages/Probes'

const navItems = [
  { path: '/', label: '仪表盘', icon: DashboardIcon },
  { path: '/rules', label: '规则列表', icon: RulesIcon },
  { path: '/rules/update', label: '规则更新', icon: UpdateIcon },
  { path: '/attacks', label: '攻击测试', icon: AttackIcon },
  { path: '/logs', label: '日志展示', icon: LogsIcon },
  { path: '/probes', label: '探针管理', icon: ProbesIcon }
]

// 图标组件
function DashboardIcon() {
  return (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 5a1 1 0 011-1h14a1 1 0 011 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM4 13a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1v-6zM16 13a1 1 0 011-1h2a1 1 0 011 1v6a1 1 0 01-1 1h-2a1 1 0 01-1-1v-6z" />
    </svg>
  )
}

function RulesIcon() {
  return (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
    </svg>
  )
}

function UpdateIcon() {
  return (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
    </svg>
  )
}

function AttackIcon() {
  return (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
    </svg>
  )
}

function LogsIcon() {
  return (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
    </svg>
  )
}

function ProbesIcon() {
  return (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
    </svg>
  )
}

export default function App() {
  return (
    <div className="min-h-screen bg-slate-50">
      {/* 顶部导航栏 - Stripe 风格 */}
      <header className="fixed top-0 left-0 right-0 z-50 h-16 bg-white/95 backdrop-blur-md border-b border-slate-100 shadow-xs">
        <div className="mx-auto flex h-full max-w-7xl items-center justify-between px-6">
          {/* Logo */}
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-gradient-to-br from-stripe-primary to-stripe-primary-light">
              <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <span className="text-lg font-semibold text-slate-900 tracking-tight">AI-IDPS</span>
          </div>

          {/* 导航菜单 */}
          <nav className="flex items-center gap-1">
            {navItems.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                end={item.path === '/'}
                className={({ isActive }) =>
                  `flex items-center gap-2 px-3.5 py-2 text-sm font-medium rounded-md transition-all duration-150 ${
                    isActive
                      ? 'text-stripe-primary bg-stripe-primary/10'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                  }`
                }
              >
                <item.icon />
                {item.label}
              </NavLink>
            ))}
          </nav>

          {/* 右侧区域 - 可放置用户信息等 */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 px-3 py-1.5 text-sm text-slate-500 bg-slate-100 rounded-full">
              <span className="h-2 w-2 rounded-full bg-success animate-pulse" />
              系统运行中
            </div>
          </div>
        </div>
      </header>

      {/* 主内容区域 */}
      <main className="pt-16">
        <div className="mx-auto max-w-7xl px-6 py-8">
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/rules" element={<RuleListPage />} />
            <Route path="/rules/update" element={<RuleUpdatePage />} />
            <Route path="/attacks" element={<AttackTestPage />} />
            <Route path="/logs" element={<LogsPage />} />
            <Route path="/probes" element={<ProbesPage />} />
          </Routes>
        </div>
      </main>

      {/* 页脚 */}
      <footer className="border-t border-slate-100 bg-white py-6">
        <div className="mx-auto max-w-7xl px-6 text-center text-sm text-slate-400">
          AI-IDPS 入侵检测与防御系统 • 基于 Suricata 构建
        </div>
      </footer>
    </div>
  )
}

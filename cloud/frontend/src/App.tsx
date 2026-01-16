import { NavLink, Route, Routes } from 'react-router-dom'
import DashboardPage from './pages/Dashboard'
import RulesPage from './pages/Rules'
import LogsPage from './pages/Logs'
import ProbesPage from './pages/Probes'

const navItems = [
  { path: '/', label: '仪表盘' },
  { path: '/rules', label: '规则管理' },
  { path: '/logs', label: '日志展示' },
  { path: '/probes', label: '探针管理' }
]

export default function App() {
  return (
    <div className="min-h-screen bg-gray-50 text-gray-900">
      <header className="border-b bg-white">
        <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-6">
          <div className="text-lg font-semibold">AI-IDPS 控制台</div>
          <nav className="flex gap-4 text-sm">
            {navItems.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `rounded px-3 py-1 ${isActive ? 'bg-blue-50 text-blue-700' : 'text-gray-600'}`
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-6">
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/rules" element={<RulesPage />} />
          <Route path="/logs" element={<LogsPage />} />
          <Route path="/probes" element={<ProbesPage />} />
        </Routes>
      </main>
    </div>
  )
}

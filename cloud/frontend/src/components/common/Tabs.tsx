import React from 'react'

interface Tab {
  key: string
  label: string
  badge?: number | string
}

interface TabsProps {
  tabs: Tab[]
  activeKey: string
  onChange: (key: string) => void
  className?: string
}

export const Tabs: React.FC<TabsProps> = ({
  tabs,
  activeKey,
  onChange,
  className = '',
}) => {
  return (
    <div className={`border-b border-slate-200 ${className}`}>
      <nav className="-mb-px flex space-x-8">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => onChange(tab.key)}
            className={`
              py-4 px-1 text-sm font-medium border-b-2 transition-colors duration-150
              ${
                activeKey === tab.key
                  ? 'border-stripe-primary text-stripe-primary'
                  : 'border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300'
              }
            `}
          >
            {tab.label}
            {tab.badge !== undefined && (
              <span
                className={`
                  ml-2 rounded-full px-2 py-0.5 text-xs
                  ${activeKey === tab.key ? 'bg-stripe-primary/10 text-stripe-primary' : 'bg-slate-100 text-slate-600'}
                `}
              >
                {tab.badge}
              </span>
            )}
          </button>
        ))}
      </nav>
    </div>
  )
}

export default Tabs

import React from 'react'

interface StatCardProps {
  title: string
  value: string | number
  subtitle?: string
  icon?: React.ReactNode
  trend?: {
    value: number
    label?: string
  }
  variant?: 'default' | 'success' | 'warning' | 'error' | 'info'
  onClick?: () => void
  className?: string
}

const variantClasses = {
  default: 'bg-white border-slate-100',
  success: 'bg-success-light border-success/20',
  warning: 'bg-warning-light border-warning/20',
  error: 'bg-error-light border-error/20',
  info: 'bg-info-light border-info/20',
}

const valueColors = {
  default: 'text-slate-900',
  success: 'text-success-dark',
  warning: 'text-warning-dark',
  error: 'text-error-dark',
  info: 'text-info-dark',
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon,
  trend,
  variant = 'default',
  onClick,
  className = '',
}) => {
  return (
    <div
      className={`
        p-5 rounded-lg border transition-all duration-200
        ${variantClasses[variant]}
        ${onClick ? 'cursor-pointer hover:shadow-md hover:-translate-y-0.5' : ''}
        ${className}
      `}
      onClick={onClick}
    >
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-sm font-medium text-slate-500">{title}</p>
          <p className={`mt-2 text-3xl font-bold ${valueColors[variant]}`}>{value}</p>
          {subtitle && <p className="mt-1 text-sm text-slate-400">{subtitle}</p>}
          {trend && (
            <p className={`mt-2 text-sm font-medium ${trend.value >= 0 ? 'text-success' : 'text-error'}`}>
              {trend.value >= 0 ? '↑' : '↓'} {Math.abs(trend.value)}%
              {trend.label && <span className="text-slate-400 ml-1">{trend.label}</span>}
            </p>
          )}
        </div>
        {icon && (
          <div className="flex-shrink-0 p-2 rounded-lg bg-white/50">{icon}</div>
        )}
      </div>
    </div>
  )
}

export default StatCard

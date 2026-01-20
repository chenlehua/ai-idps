import React from 'react'

interface ProgressBarProps {
  value: number
  max?: number
  variant?: 'primary' | 'success' | 'warning' | 'error'
  size?: 'sm' | 'md' | 'lg'
  showLabel?: boolean
  className?: string
}

const variantClasses = {
  primary: 'bg-stripe-primary',
  success: 'bg-success',
  warning: 'bg-warning',
  error: 'bg-error',
}

const sizeClasses = {
  sm: 'h-1.5',
  md: 'h-2',
  lg: 'h-3',
}

export const ProgressBar: React.FC<ProgressBarProps> = ({
  value,
  max = 100,
  variant = 'primary',
  size = 'md',
  showLabel = false,
  className = '',
}) => {
  const percentage = Math.min(Math.max((value / max) * 100, 0), 100)

  return (
    <div className={className}>
      <div className={`w-full rounded-full bg-slate-200 overflow-hidden ${sizeClasses[size]}`}>
        <div
          className={`rounded-full transition-all duration-300 ease-out ${sizeClasses[size]} ${variantClasses[variant]}`}
          style={{ width: `${percentage}%` }}
        />
      </div>
      {showLabel && (
        <div className="mt-1 text-xs text-slate-500 text-right">
          {percentage.toFixed(1)}%
        </div>
      )}
    </div>
  )
}

export default ProgressBar

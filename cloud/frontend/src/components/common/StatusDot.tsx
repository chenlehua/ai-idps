import React from 'react'

interface StatusDotProps {
  status: 'online' | 'offline' | 'warning' | 'running' | 'stopped' | 'error' | 'pending' | 'success'
  size?: 'sm' | 'md' | 'lg'
  pulse?: boolean
  className?: string
}

const statusColors = {
  online: 'bg-success',
  offline: 'bg-error',
  warning: 'bg-warning',
  running: 'bg-success',
  stopped: 'bg-slate-400',
  error: 'bg-error',
  pending: 'bg-slate-400',
  success: 'bg-success',
}

const sizeClasses = {
  sm: 'h-1.5 w-1.5',
  md: 'h-2 w-2',
  lg: 'h-3 w-3',
}

export const StatusDot: React.FC<StatusDotProps> = ({
  status,
  size = 'md',
  pulse = false,
  className = '',
}) => {
  return (
    <span
      className={`
        inline-block rounded-full
        ${statusColors[status] || 'bg-slate-400'}
        ${sizeClasses[size]}
        ${pulse ? 'animate-pulse' : ''}
        ${className}
      `}
    />
  )
}

export default StatusDot

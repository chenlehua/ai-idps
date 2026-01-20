import React from 'react'

interface BadgeProps {
  children: React.ReactNode
  variant?: 'primary' | 'success' | 'warning' | 'error' | 'info' | 'gray'
  size?: 'sm' | 'md'
  dot?: boolean
  className?: string
}

const variantClasses = {
  primary: 'text-stripe-primary bg-stripe-primary/10',
  success: 'text-success-dark bg-success-light',
  warning: 'text-warning-dark bg-warning-light',
  error: 'text-error-dark bg-error-light',
  info: 'text-info-dark bg-info-light',
  gray: 'text-slate-600 bg-slate-100',
}

const dotColors = {
  primary: 'bg-stripe-primary',
  success: 'bg-success',
  warning: 'bg-warning',
  error: 'bg-error',
  info: 'bg-info',
  gray: 'bg-slate-400',
}

const sizeClasses = {
  sm: 'px-2 py-0.5 text-xs',
  md: 'px-2.5 py-1 text-sm',
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'gray',
  size = 'sm',
  dot = false,
  className = '',
}) => {
  return (
    <span
      className={`
        inline-flex items-center gap-1.5 font-medium rounded-full
        ${variantClasses[variant]}
        ${sizeClasses[size]}
        ${className}
      `}
    >
      {dot && <span className={`h-1.5 w-1.5 rounded-full ${dotColors[variant]}`} />}
      {children}
    </span>
  )
}

export default Badge

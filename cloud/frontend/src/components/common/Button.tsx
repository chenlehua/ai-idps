import React from 'react'

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'text' | 'danger' | 'success'
  size?: 'sm' | 'md' | 'lg'
  loading?: boolean
  icon?: React.ReactNode
  children: React.ReactNode
}

const variantClasses = {
  primary: `inline-flex items-center justify-center font-medium text-white 
    bg-stripe-primary border-none rounded-md cursor-pointer
    transition-all duration-150 ease-out
    shadow-button hover:bg-stripe-primary-light hover:shadow-button-hover hover:-translate-y-0.5
    active:bg-stripe-primary-dark active:translate-y-0 active:shadow-sm
    focus:outline-none focus-visible:ring-2 focus-visible:ring-stripe-primary focus-visible:ring-offset-2
    disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none disabled:shadow-none`,
  secondary: `inline-flex items-center justify-center font-medium text-slate-900
    bg-white border border-slate-200 rounded-md cursor-pointer
    transition-all duration-150 ease-out
    hover:bg-slate-50 hover:border-slate-300
    active:bg-slate-100
    focus:outline-none focus-visible:ring-2 focus-visible:ring-stripe-primary focus-visible:ring-offset-2
    disabled:opacity-50 disabled:cursor-not-allowed`,
  text: `inline-flex items-center justify-center font-medium text-stripe-primary
    bg-transparent border-none rounded-md cursor-pointer
    transition-all duration-150 ease-out
    hover:bg-stripe-primary/10
    focus:outline-none focus-visible:ring-2 focus-visible:ring-stripe-primary focus-visible:ring-offset-2
    disabled:opacity-50 disabled:cursor-not-allowed`,
  danger: `inline-flex items-center justify-center font-medium text-white
    bg-error border-none rounded-md cursor-pointer
    transition-all duration-150 ease-out
    shadow-sm hover:bg-error-dark hover:shadow-md
    active:shadow-sm
    focus:outline-none focus-visible:ring-2 focus-visible:ring-error focus-visible:ring-offset-2
    disabled:opacity-50 disabled:cursor-not-allowed`,
  success: `inline-flex items-center justify-center font-medium text-white
    bg-success border-none rounded-md cursor-pointer
    transition-all duration-150 ease-out
    shadow-sm hover:bg-success-dark hover:shadow-md
    active:shadow-sm
    focus:outline-none focus-visible:ring-2 focus-visible:ring-success focus-visible:ring-offset-2
    disabled:opacity-50 disabled:cursor-not-allowed`,
}

const sizeClasses = {
  sm: 'px-3.5 py-2 text-sm gap-1.5',
  md: 'px-5 py-2.5 text-base gap-2',
  lg: 'px-7 py-3.5 text-lg gap-2.5',
}

export const Button: React.FC<ButtonProps> = ({
  variant = 'primary',
  size = 'md',
  loading = false,
  icon,
  children,
  className = '',
  disabled,
  ...props
}) => {
  return (
    <button
      className={`${variantClasses[variant]} ${sizeClasses[size]} ${className}`}
      disabled={disabled || loading}
      {...props}
    >
      {loading ? (
        <svg className="animate-spin h-4 w-4 mr-2" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
      ) : icon ? (
        <span className="flex-shrink-0">{icon}</span>
      ) : null}
      {children}
    </button>
  )
}

export default Button

import React from 'react'

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string
  error?: string
  helperText?: string
}

export const Input: React.FC<InputProps> = ({
  label,
  error,
  helperText,
  className = '',
  id,
  ...props
}) => {
  const inputId = id || label?.toLowerCase().replace(/\s+/g, '-')

  return (
    <div className="w-full">
      {label && (
        <label htmlFor={inputId} className="block mb-1.5 text-sm font-medium text-slate-700">
          {label}
        </label>
      )}
      <input
        id={inputId}
        className={`
          w-full px-3.5 py-2.5 text-base text-slate-900 bg-white
          border rounded transition-all duration-150 ease-out
          placeholder:text-slate-400
          hover:border-slate-300
          focus:outline-none focus:border-stripe-primary focus:shadow-focus
          disabled:bg-slate-50 disabled:text-slate-400 disabled:cursor-not-allowed
          ${error ? 'border-error focus:border-error focus:shadow-focus-error' : 'border-slate-200'}
          ${className}
        `}
        {...props}
      />
      {error && <p className="mt-1.5 text-sm text-error">{error}</p>}
      {helperText && !error && <p className="mt-1.5 text-sm text-slate-500">{helperText}</p>}
    </div>
  )
}

export default Input

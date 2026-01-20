import React from 'react'

interface ToggleProps {
  checked: boolean
  onChange: (checked: boolean) => void
  disabled?: boolean
  size?: 'sm' | 'md'
  className?: string
}

const sizeClasses = {
  sm: {
    track: 'h-5 w-9',
    thumb: 'h-4 w-4',
    translate: 'translate-x-4',
  },
  md: {
    track: 'h-6 w-11',
    thumb: 'h-5 w-5',
    translate: 'translate-x-5',
  },
}

export const Toggle: React.FC<ToggleProps> = ({
  checked,
  onChange,
  disabled = false,
  size = 'md',
  className = '',
}) => {
  const sizes = sizeClasses[size]

  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      onClick={() => !disabled && onChange(!checked)}
      disabled={disabled}
      className={`
        relative inline-flex flex-shrink-0 cursor-pointer rounded-full
        border-2 border-transparent transition-colors duration-200 ease-in-out
        focus:outline-none focus:ring-2 focus:ring-stripe-primary focus:ring-offset-2
        disabled:cursor-not-allowed disabled:opacity-50
        ${sizes.track}
        ${checked ? 'bg-stripe-primary' : 'bg-slate-200'}
        ${className}
      `}
    >
      <span
        className={`
          pointer-events-none inline-block transform rounded-full
          bg-white shadow ring-0 transition duration-200 ease-in-out
          ${sizes.thumb}
          ${checked ? sizes.translate : 'translate-x-0'}
        `}
      />
    </button>
  )
}

export default Toggle

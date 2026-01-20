import React from 'react'

interface CardProps {
  children: React.ReactNode
  className?: string
  hoverable?: boolean
}

interface CardHeaderProps {
  children: React.ReactNode
  className?: string
  action?: React.ReactNode
}

interface CardBodyProps {
  children: React.ReactNode
  className?: string
}

interface CardFooterProps {
  children: React.ReactNode
  className?: string
}

export const Card: React.FC<CardProps> & {
  Header: React.FC<CardHeaderProps>
  Body: React.FC<CardBodyProps>
  Footer: React.FC<CardFooterProps>
} = ({ children, className = '', hoverable = false }) => {
  return (
    <div
      className={`
        bg-white border border-slate-100 rounded-lg shadow-sm overflow-hidden
        transition-all duration-200 ease-out
        ${hoverable ? 'hover:shadow-md hover:-translate-y-0.5 cursor-pointer' : ''}
        ${className}
      `}
    >
      {children}
    </div>
  )
}

const CardHeader: React.FC<CardHeaderProps> = ({ children, className = '', action }) => (
  <div className={`px-6 py-4 border-b border-slate-100 flex items-center justify-between ${className}`}>
    <div className="font-semibold text-slate-900">{children}</div>
    {action && <div>{action}</div>}
  </div>
)

const CardBody: React.FC<CardBodyProps> = ({ children, className = '' }) => (
  <div className={`p-6 ${className}`}>{children}</div>
)

const CardFooter: React.FC<CardFooterProps> = ({ children, className = '' }) => (
  <div className={`px-6 py-4 bg-slate-50 border-t border-slate-100 ${className}`}>{children}</div>
)

Card.Header = CardHeader
Card.Body = CardBody
Card.Footer = CardFooter

export default Card

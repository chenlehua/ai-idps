import React from 'react'
import Button from './Button'

interface PaginationProps {
  current: number
  total: number
  pageSize: number
  onChange: (page: number) => void
  className?: string
}

export const Pagination: React.FC<PaginationProps> = ({
  current,
  total,
  pageSize,
  onChange,
  className = '',
}) => {
  const totalPages = Math.ceil(total / pageSize)
  const start = current * pageSize + 1
  const end = Math.min((current + 1) * pageSize, total)

  if (total === 0) return null

  return (
    <div className={`flex items-center justify-between ${className}`}>
      <div className="text-sm text-slate-500">
        显示 {start} - {end} 条，共 {total} 条
      </div>
      <div className="flex items-center gap-2">
        <Button
          variant="secondary"
          size="sm"
          onClick={() => onChange(Math.max(0, current - 1))}
          disabled={current === 0}
        >
          上一页
        </Button>
        <span className="px-3 py-1 text-sm text-slate-500">
          {current + 1} / {totalPages || 1}
        </span>
        <Button
          variant="secondary"
          size="sm"
          onClick={() => onChange(Math.min(totalPages - 1, current + 1))}
          disabled={current >= totalPages - 1}
        >
          下一页
        </Button>
      </div>
    </div>
  )
}

export default Pagination

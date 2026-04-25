import { type ReactNode } from 'react'
import { cn } from '@/lib/utils'
import { EmptyState, ErrorState } from './index'

export interface Column<T> {
  key:       string
  header:    string
  width?:    string
  align?:    'left' | 'right' | 'center'
  mono?:     boolean       // renders in JetBrains Mono + cyan
  render?:   (row: T) => ReactNode
}

interface DataTableProps<T> {
  columns:     Column<T>[]
  data:        T[]
  keyField:    keyof T
  loading?:    boolean
  error?:      Error | null
  onRetry?:    () => void
  onRowClick?: (row: T) => void
  selectable?: boolean
  emptyTitle?: string
  emptyDesc?:  string
  className?:  string
}

const SKELETON_WIDTHS = ['60%', '75%', '45%', '80%', '55%', '70%', '40%', '65%']

export function DataTable<T>({
  columns, data, keyField, loading, error, onRetry,
  onRowClick, emptyTitle, emptyDesc, className,
}: DataTableProps<T>) {

  return (
    <div className={cn('w-full overflow-x-auto', className)}>
      <table className="w-full border-collapse" role="grid">
        <thead>
          <tr className="border-b border-border-strong">
            {columns.map(col => (
              <th
                key={col.key}
                scope="col"
                style={{ width: col.width }}
                className={cn(
                  'px-4 py-2.5 font-ui text-xs font-semibold tracking-wider uppercase text-text-secondary',
                  col.align === 'right'  && 'text-right',
                  col.align === 'center' && 'text-center',
                  !col.align             && 'text-left'
                )}
              >
                {col.header}
              </th>
            ))}
          </tr>
        </thead>

        <tbody>
          {/* Loading state */}
          {loading && SKELETON_WIDTHS.map((w, i) => (
            <tr key={i} className="border-b border-border/50">
              {columns.map((col, ci) => (
                <td key={col.key} className="px-4 py-3">
                  <div
                    className="skeleton h-3.5 rounded-sm"
                    style={{ width: ci === 0 ? w : '70%' }}
                  />
                </td>
              ))}
            </tr>
          ))}

          {/* Error state */}
          {!loading && error && (
            <tr>
              <td colSpan={columns.length} className="px-4 py-12">
                <ErrorState
                  title="Failed to load data"
                  message={error.message}
                  onRetry={onRetry}
                  compact
                />
              </td>
            </tr>
          )}

          {/* Empty state */}
          {!loading && !error && data.length === 0 && (
            <tr>
              <td colSpan={columns.length} className="px-4 py-16">
                <EmptyState
                  title={emptyTitle ?? 'No results'}
                  description={emptyDesc ?? 'No data matches the current filters.'}
                />
              </td>
            </tr>
          )}

          {/* Data rows */}
          {!loading && !error && data.map(row => (
            <tr
              key={String(row[keyField])}
              tabIndex={onRowClick ? 0 : undefined}
              role={onRowClick ? 'button' : undefined}
              aria-label={onRowClick ? `View details for row ${String(row[keyField])}` : undefined}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              onKeyDown={onRowClick
                ? e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onRowClick(row) } }
                : undefined
              }
              className={cn(
                'border-b border-border/50 transition-colors duration-150',
                onRowClick && 'cursor-pointer hover:bg-bg-hover focus:bg-bg-hover focus:outline-none'
              )}
            >
              {columns.map(col => {
                const raw = (row as any)[col.key]
                return (
                  <td
                    key={col.key}
                    className={cn(
                      'px-4 py-3',
                      col.mono
                        ? 'font-mono text-sm text-text-code'
                        : 'font-ui text-sm text-text-primary',
                      col.align === 'right'  && 'text-right',
                      col.align === 'center' && 'text-center'
                    )}
                  >
                    {col.render ? col.render(row) : raw ?? '—'}
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

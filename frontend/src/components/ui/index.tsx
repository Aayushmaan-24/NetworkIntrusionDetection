import { type ReactNode, useEffect, useState } from 'react'
import { AlertCircle, RotateCcw, Inbox, RefreshCw, X, WifiOff } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useAppStore, type Toast } from '@/store/appStore'

// ── EmptyState ────────────────────────────────────────────────
interface EmptyStateProps {
  icon?:        ReactNode
  title:        string
  description?: string
  action?:      { label: string; onClick: () => void }
}

export function EmptyState({ icon, title, description, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-12 text-center">
      <div className="text-text-tertiary">
        {icon ?? <Inbox size={36} strokeWidth={1} />}
      </div>
      <p className="font-display text-lg text-text-secondary tracking-wide">{title}</p>
      {description && (
        <p className="max-w-xs font-ui text-sm text-text-tertiary">{description}</p>
      )}
      {action && (
        <button
          onClick={action.onClick}
          className="mt-2 font-ui text-sm text-cyan underline-offset-4 hover:underline"
        >
          {action.label}
        </button>
      )}
    </div>
  )
}

// ── ErrorState ────────────────────────────────────────────────
interface ErrorStateProps {
  title?:     string
  message?:   string
  code?:      string
  host?:      string
  lastSignal?: string
  errorId?:   string
  onRetry?:   () => void
  compact?:   boolean
}

export function ErrorState({
  title, message, code, host, lastSignal, errorId, onRetry, compact,
}: ErrorStateProps) {
  /* Countdown timer — resets at 0 */
  const [countdown, setCountdown] = useState(60)
  const [retrying, setRetrying]   = useState(false)

  useEffect(() => {
    const t = setInterval(() => setCountdown(c => (c <= 1 ? 60 : c - 1)), 1000)
    return () => clearInterval(t)
  }, [])

  const handleRetry = async () => {
    setRetrying(true)
    setCountdown(60)
    await onRetry?.()
    setRetrying(false)
  }

  /* ── Compact inline variant ─────────────────────── */
  if (compact) {
    return (
      <div className="flex flex-col items-center gap-3 py-6 text-center">
        <AlertCircle size={28} className="text-critical" strokeWidth={1.5} />
        <p className="font-ui text-sm text-text-secondary">{title ?? 'Failed to load'}</p>
        {message && <p className="font-mono text-xs text-text-tertiary">{message}</p>}
        {onRetry && (
          <button
            onClick={handleRetry}
            className="flex items-center gap-1.5 font-ui text-xs text-cyan hover:text-cyan-dim transition-colors"
          >
            <RotateCcw size={12} /> Retry
          </button>
        )}
      </div>
    )
  }

  /* ── Full-page variant (matches reference design) ── */
  const displayCode    = code        ?? 'ERR_SIG_TIMEOUT_0x442'
  const displayHost    = host        ?? '192.168.1.104 [CORE-ALPHA]'
  const displaySignal  = lastSignal  ?? new Date().toISOString().replace('T', ' ').substring(0, 23) + ' UTC'
  const displayId      = errorId     ?? 'NIDS-404-500'

  return (
    <div className="flex min-h-[calc(100vh-130px)] items-center justify-center p-6">
      {/* Outer wrapper with corner bracket decorations */}
      <div className="relative w-full max-w-[580px]">

        {/* ── Corner brackets ────────────────────── */}
        {/* Top-left */}
        <span className="pointer-events-none absolute -top-px -left-px h-7 w-7 border-t-2 border-l-2 border-cyan" />
        {/* Top-right */}
        <span className="pointer-events-none absolute -top-px -right-px h-7 w-7 border-t-2 border-r-2 border-cyan" />
        {/* Bottom-left */}
        <span className="pointer-events-none absolute -bottom-px -left-px h-7 w-7 border-b-2 border-l-2 border-cyan" />
        {/* Bottom-right */}
        <span className="pointer-events-none absolute -bottom-px -right-px h-7 w-7 border-b-2 border-r-2 border-cyan" />

        {/* ── Panel content ──────────────────────── */}
        <div className="flex flex-col items-center gap-6 px-8 py-10 text-center">

          {/* Status chip */}
          <span className="inline-flex items-center gap-1.5 rounded-sm border border-critical/40 bg-critical/8 px-3 py-1 font-mono text-[10px] tracking-[0.18em] text-critical/90 uppercase">
            STATUS: ERROR_CRITICAL
          </span>

          {/* Animated wifi-off icon */}
          <div className="relative flex h-24 w-24 items-center justify-center">
            {/* Outer pulse ring */}
            <span className="absolute h-24 w-24 rounded-full border border-critical/20 animate-ping" style={{ animationDuration: '2.4s' }} />
            {/* Mid ring */}
            <span className="absolute h-20 w-20 rounded-full border border-critical/25" />
            {/* Icon container */}
            <div className="relative flex h-16 w-16 items-center justify-center rounded-full border-2 border-critical/50 bg-critical/10">
              <WifiOff size={32} className="text-critical" strokeWidth={1.5} />
            </div>
          </div>

          {/* Title + message */}
          <div className="space-y-2">
            <h2 className="font-display text-2xl tracking-wide text-text-primary">
              {title ?? 'Feed Disconnected'}
            </h2>
            <p className="mx-auto max-w-sm font-ui text-sm leading-relaxed text-text-secondary">
              {message ??
                'Data ingestion from the primary telemetry node has ceased. Real-time monitoring and packet inspection are currently unavailable.'}
            </p>
          </div>

          {/* Error detail rows */}
          <div className="w-full divide-y divide-border border border-border bg-bg-input/60 text-left">
            <div className="flex items-center justify-between px-5 py-3">
              <span className="font-ui text-xs tracking-wider text-text-tertiary uppercase">Error Code:</span>
              <span className="font-mono text-xs text-critical">{displayCode}</span>
            </div>
            <div className="flex items-center justify-between px-5 py-3">
              <span className="font-ui text-xs tracking-wider text-text-tertiary uppercase">Target Host:</span>
              <span className="font-mono text-xs text-text-code">{displayHost}</span>
            </div>
            <div className="flex items-center justify-between px-5 py-3">
              <span className="font-ui text-xs tracking-wider text-text-tertiary uppercase">Last Signal:</span>
              <span className="font-mono text-xs text-text-secondary">{displaySignal}</span>
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex w-full flex-col gap-2">
            <button
              onClick={handleRetry}
              disabled={retrying}
              className={cn(
                'flex h-12 w-full items-center justify-center gap-2.5',
                'bg-cyan font-display text-sm tracking-[0.12em] text-bg-base uppercase',
                'transition-all duration-200',
                'hover:bg-cyan-dim disabled:opacity-60',
                'shadow-glow',
              )}
            >
              <RefreshCw size={14} className={retrying ? 'animate-spin' : ''} />
              {retrying ? 'RECONNECTING...' : 'RETRY CONNECTION'}
            </button>

            <button className="flex h-12 w-full items-center justify-center border border-border font-display text-xs tracking-[0.1em] text-text-secondary uppercase hover:bg-bg-hover transition-colors">
              CONTACT INFRASTRUCTURE SUPPORT
            </button>
          </div>

          {/* Bottom status bar (inside panel) */}
          <div className="flex w-full items-center justify-between border-t border-border pt-3 font-mono text-[10px] tracking-wider text-text-tertiary">
            <div className="flex items-center gap-2">
              <span className="flex items-center gap-1.5 text-critical">
                <span className="h-1.5 w-1.5 rounded-full bg-critical animate-pulse" />
                GATEWAY OFFLINE
              </span>
              <span className="text-border-strong">|</span>
              <span>
                ATTEMPTING AUTOMATIC RECONNECT IN{' '}
                <span className="text-text-secondary">{countdown}S</span>...
              </span>
            </div>
            <span className="text-text-tertiary/60">ID: {displayId}</span>
          </div>

        </div>
      </div>
    </div>
  )
}

// ── ActionButton ──────────────────────────────────────────────
interface ActionButtonProps {
  variant?:  'primary' | 'secondary' | 'danger' | 'ghost'
  size?:     'sm' | 'md'
  loading?:  boolean
  disabled?: boolean
  icon?:     ReactNode
  children:  ReactNode
  onClick?:  () => void
  type?:     'button' | 'submit' | 'reset'
  className?: string
}

const BTN_VARIANTS = {
  primary:   'bg-cyan text-bg-base hover:bg-cyan-dim shadow-glow',
  secondary: 'border border-border-strong text-text-primary hover:bg-bg-hover',
  danger:    'border border-critical text-critical hover:bg-critical/10',
  ghost:     'text-text-secondary hover:text-text-primary hover:bg-bg-hover',
}

export function ActionButton({
  variant = 'secondary', size = 'md', loading, disabled,
  icon, children, onClick, type = 'button', className,
}: ActionButtonProps) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled || loading}
      aria-disabled={disabled || loading}
      className={cn(
        'inline-flex items-center gap-2 rounded-md font-display tracking-wide uppercase transition-all duration-150',
        'focus-visible:shadow-focus focus-visible:outline-none',
        'disabled:cursor-not-allowed disabled:opacity-40',
        size === 'md' ? 'h-9 px-5 text-sm' : 'h-7 px-3 text-xs',
        BTN_VARIANTS[variant],
        className
      )}
    >
      {loading
        ? <RefreshCw size={12} className="animate-spin" aria-hidden="true" />
        : icon
      }
      {loading ? 'ANALYZING...' : children}
    </button>
  )
}

// ── PaginationBar ─────────────────────────────────────────────
interface PaginationBarProps {
  page:     number
  pages:    number
  total:    number
  limit:    number
  onPage:   (p: number) => void
  onLimit:  (l: number) => void
}

export function PaginationBar({ page, pages, total, limit, onPage, onLimit }: PaginationBarProps) {
  const safePages = Math.max(1, pages)
  const safePage = Math.min(Math.max(page, 1), safePages)
  const from = total === 0 ? 0 : (safePage - 1) * limit + 1
  const to   = total === 0 ? 0 : Math.min(safePage * limit, total)

  const pageButtons = (() => {
    if (safePages <= 5) {
      return Array.from({ length: safePages }, (_, i) => i + 1)
    }
    const start = Math.min(Math.max(1, safePage - 2), safePages - 4)
    return Array.from({ length: 5 }, (_, i) => start + i)
  })()

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border px-4 py-3">
      <span className="font-ui text-xs text-text-tertiary">
        SHOWING {from} TO {to} OF {total.toLocaleString()} ENTRIES
      </span>

      <div className="flex items-center gap-1">
        <button onClick={() => onPage(1)}            disabled={safePage === 1}         className={paginBtn(safePage === 1)}>«</button>
        <button onClick={() => onPage(safePage - 1)} disabled={safePage === 1}         className={paginBtn(safePage === 1)}>‹</button>

        {pageButtons.map(p => (
          <button key={p} onClick={() => onPage(p)} className={cn(paginBtn(false), safePage === p && 'bg-cyan text-bg-base border-cyan')}>
            {p}
          </button>
        ))}

        <button onClick={() => onPage(safePage + 1)} disabled={safePage === safePages} className={paginBtn(safePage === safePages)}>›</button>
        <button onClick={() => onPage(safePages)}    disabled={safePage === safePages} className={paginBtn(safePage === safePages)}>»</button>
      </div>

      <select
        value={limit}
        onChange={e => onLimit(Number(e.target.value))}
        aria-label="Rows per page"
        className="h-7 rounded-md border border-border bg-bg-input px-2 font-mono text-xs text-text-primary focus:shadow-focus focus:outline-none"
      >
        {[10, 25, 50, 100].map(n => <option key={n} value={n}>SHOW {n}</option>)}
      </select>
    </div>
  )
}

const paginBtn = (disabled: boolean) => cn(
  'h-7 min-w-[28px] rounded-md border border-border px-2 font-mono text-xs',
  'text-text-secondary hover:bg-bg-hover transition-colors',
  disabled && 'opacity-30 cursor-not-allowed pointer-events-none'
)

// ── ToastContainer ────────────────────────────────────────────
export function ToastContainer() {
  const { toasts, removeToast } = useAppStore()

  return (
    <div
      aria-live="polite"
      aria-atomic="false"
      className="fixed right-4 top-16 z-50 flex flex-col gap-2"
    >
      {toasts.map(t => <ToastItem key={t.id} toast={t} onClose={() => removeToast(t.id)} />)}
    </div>
  )
}

function ToastItem({ toast, onClose }: { toast: Toast; onClose: () => void }) {
  useEffect(() => {
    const timer = setTimeout(onClose, 5000)
    return () => clearTimeout(timer)
  }, [onClose])

  const styles: Record<Toast['variant'], string> = {
    success:  'border-success/40 bg-success/10 text-success',
    warning:  'border-warning/40 bg-warning/10 text-warning',
    critical: 'border-critical/40 bg-critical/10 text-critical',
    info:     'border-info/40 bg-info/10 text-info',
  }

  return (
    <div
      role="alert"
      className={cn(
        'flex min-w-[280px] items-start justify-between gap-3 rounded-lg border p-3 shadow-modal',
        'bg-bg-surface font-ui text-sm animate-fade-in',
        styles[toast.variant]
      )}
    >
      <div>
        <p className="font-semibold tracking-wide uppercase text-xs">{toast.title}</p>
        {toast.message && <p className="mt-0.5 text-xs text-text-secondary">{toast.message}</p>}
      </div>
      <button onClick={onClose} aria-label="Dismiss" className="shrink-0 text-current opacity-60 hover:opacity-100">
        <X size={14} />
      </button>
    </div>
  )
}

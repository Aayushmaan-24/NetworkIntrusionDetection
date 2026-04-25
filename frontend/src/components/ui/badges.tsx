import { type ReactNode } from 'react'
import { cn } from '@/lib/utils'
import type { AlertSeverity, AlertStatus, RiskLevel } from '@/types/api'

// ── StatCard ─────────────────────────────────────────────────
interface StatCardProps {
  label:       string
  value:       string | number
  delta?:      string
  deltaDir?:   'up' | 'down' | 'neutral'
  icon?:       ReactNode
  variant?:    'default' | 'critical' | 'warning' | 'success' | 'info'
  loading?:    boolean
}

const STAT_ACCENT: Record<NonNullable<StatCardProps['variant']>, string> = {
  default:  'bg-border',
  critical: 'bg-critical',
  warning:  'bg-warning',
  success:  'bg-success',
  info:     'bg-cyan',
}

export function StatCard({ label, value, delta, deltaDir = 'neutral', icon, variant = 'default', loading }: StatCardProps) {
  if (loading) return <StatCardSkeleton />

  return (
    <div className="flex flex-col gap-3 rounded-lg border border-border bg-bg-surface p-5 shadow-card">
      <div className="flex items-start justify-between">
        <span className="font-ui text-xs font-medium tracking-wider text-text-secondary uppercase">
          {label}
        </span>
        {icon && <span className="text-text-tertiary">{icon}</span>}
      </div>

      <div className="font-display text-3xl tracking-tight text-text-primary">
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>

      {delta && (
        <div className={cn(
          'font-mono text-xs',
          deltaDir === 'up'   && 'text-success',
          deltaDir === 'down' && 'text-critical',
          deltaDir === 'neutral' && 'text-text-secondary'
        )}>
          {delta}
        </div>
      )}

      {/* Accent bar */}
      <div className={cn('h-0.5 w-full rounded-full', STAT_ACCENT[variant])} />
    </div>
  )
}

function StatCardSkeleton() {
  return (
    <div className="flex flex-col gap-3 rounded-lg border border-border bg-bg-surface p-5">
      <div className="skeleton h-3 w-24" />
      <div className="skeleton h-9 w-20" />
      <div className="skeleton h-2 w-16" />
      <div className="skeleton h-0.5 w-full" />
    </div>
  )
}

// ── StatusBadge ───────────────────────────────────────────────
type BadgeVariant = AlertSeverity | AlertStatus | 'active' | 'authorized' | 'online' | 'latency' | 'offline' | 'success'

const BADGE_STYLES: Record<BadgeVariant, string> = {
  critical:    'bg-critical/10 border border-critical text-critical',
  warning:     'bg-warning/10  border border-warning  text-warning',
  info:        'bg-info/10     border border-info      text-info',
  blocked:     'bg-critical/10 border border-critical  text-critical',
  success:     'bg-success/10  border border-success   text-success',
  authorized:  'bg-success/10  border border-success   text-success',
  online:      'bg-success/10  border border-success   text-success',
  pending:     'bg-warning/10  border border-warning   text-warning',
  latency:     'bg-warning/10  border border-warning   text-warning',
  mitigated:   'bg-cyan/10     border border-cyan      text-cyan',
  intercepted: 'bg-warning/10  border border-warning   text-warning',
  active:      'bg-info/10     border border-info      text-info',
  ignore:      'border border-border text-text-tertiary',
  offline:     'bg-critical/10 border border-critical text-critical',
}

interface StatusBadgeProps {
  variant: BadgeVariant
  label?:  string
}

export function StatusBadge({ variant, label }: StatusBadgeProps) {
  const text = label ?? variant.toUpperCase()
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-sm px-2 py-0.5',
        'font-ui text-xs font-semibold tracking-wider uppercase',
        BADGE_STYLES[variant] ?? BADGE_STYLES.info
      )}
      aria-label={`Status: ${text}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden="true" />
      {text}
    </span>
  )
}

// ── ProtocolChip ──────────────────────────────────────────────
export function ProtocolChip({ protocol }: { protocol: string }) {
  const styleByProtocol: Record<string, string> = {
    tcp: 'border-cyan/40 bg-cyan/10 text-cyan',
    udp: 'border-warning/40 bg-warning/10 text-warning',
    icmp: 'border-info/40 bg-info/10 text-info',
    http: 'border-success/40 bg-success/10 text-success',
    https: 'border-success/50 bg-success/15 text-success',
  }
  const style = styleByProtocol[protocol.toLowerCase()] ?? 'border-border-strong bg-bg-elevated text-text-primary'
  return (
    <span className={cn('inline-block rounded-sm border px-2 py-0.5 font-mono text-xs', style)}>
      {protocol.toUpperCase()}
    </span>
  )
}

// ── ConfidenceBar ─────────────────────────────────────────────
interface ConfidenceBarProps {
  value:   number    // 0–1
  label?:  string
  size?:   'sm' | 'md'
}

export function ConfidenceBar({ value, label, size = 'sm' }: ConfidenceBarProps) {
  const pct    = Math.round(value * 100)
  const color  = value < 0.3 ? 'bg-success' : value < 0.7 ? 'bg-warning' : 'bg-critical'
  const width  = size === 'sm' ? 'w-20' : 'w-full'

  return (
    <div className={cn('flex items-center gap-2', width)}>
      <div
        role="meter"
        aria-valuenow={pct}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={label ?? `Confidence: ${pct}%`}
        className="relative flex-1 h-1 rounded-full bg-border overflow-hidden"
      >
        <div
          className={cn('absolute inset-y-0 left-0 rounded-full transition-all', color)}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="font-mono text-xs text-text-secondary min-w-[36px] text-right">
        {pct}%
      </span>
    </div>
  )
}

// ── RiskBadge ─────────────────────────────────────────────────
const RISK_STYLES: Record<RiskLevel, string> = {
  high:   'bg-critical/10 border border-critical text-critical',
  medium: 'bg-warning/10  border border-warning  text-warning',
  low:    'bg-info/10     border border-info     text-info',
  normal: 'bg-success/10  border border-success  text-success',
}

export function RiskBadge({ level }: { level: RiskLevel }) {
  return (
    <span className={cn(
      'inline-flex items-center gap-1 rounded-sm px-2 py-0.5',
      'font-ui text-xs font-semibold tracking-wider uppercase',
      RISK_STYLES[level]
    )}>
      {level.toUpperCase()} RISK
    </span>
  )
}

import { RefreshCw } from 'lucide-react'
import { useHealth } from '@/hooks'
import { StatusBadge } from '@/components/ui/badges'
import { ErrorState } from '@/components/ui/index'
import { useAppStore } from '@/store/appStore'
import { cn } from '@/lib/utils'

export function HealthStatusPage() {
  const { data, isLoading, error, refetch, isFetching } = useHealth()
  const addToast = useAppStore(s => s.addToast)

  const hardRefresh = async () => {
    await refetch()
    window.location.reload()
  }

  const downloadHealthCsv = () => {
    if (!data) return
    const rows = [
      ['metric', 'value'],
      ['status', data.status],
      ['uptime', data.uptime_human],
      ['global_load', data.global_load.toFixed(1)],
      ['db_version', data.db_version],
      ['encryption', data.encryption],
      ['errors', String(data.error_count)],
      ['warnings', String(data.warning_count)],
    ]
    const csv = rows.map(r => r.join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'health-report.csv'
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
    addToast({ variant: 'success', title: 'Health CSV exported', message: 'Saved health-report.csv' })
  }

  const flushUiCache = () => {
    localStorage.removeItem('nids_app_started_at')
    addToast({ variant: 'warning', title: 'Frontend cache reset', message: 'Local health cache keys cleared.' })
    void refetch()
  }

  return (
    <div className="flex flex-col gap-6 animate-fade-in">
      {/* Page header */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="font-display text-xl tracking-wide text-text-primary uppercase">
            System Health Monitor
          </h1>
          {data && (
            <p className="font-mono text-xs tracking-wider text-text-tertiary">
              CORE NODE: {data.node_ip} / STATUS: {data.status.toUpperCase()}
            </p>
          )}
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={hardRefresh}
            disabled={isFetching}
            aria-label="Refresh health status"
            className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 font-ui text-xs text-text-secondary hover:bg-bg-hover disabled:opacity-40 transition-colors"
          >
            <RefreshCw size={12} className={isFetching ? 'animate-spin' : ''} />
            REFRESH
          </button>

          <span className={cn(
            'flex items-center gap-1.5 rounded-md border px-3 py-1.5 font-mono text-xs tracking-wider',
            data?.status === 'online'
              ? 'border-success/40 bg-success/10 text-success'
              : data?.status === 'warning'
              ? 'border-warning/40 bg-warning/10 text-warning'
              : 'border-critical/40 bg-critical/10 text-critical'
          )}>
            <span className="h-1.5 w-1.5 rounded-full bg-current animate-pulse" aria-hidden="true" />
            REAL-TIME SYNC
          </span>
        </div>
      </div>

      {/* Error */}
      {error && !isLoading && (
        <ErrorState
          title="Health data unavailable"
          message={(error as any)?.message}
          code={(error as any)?.code}
          onRetry={() => refetch()}
        />
      )}

      {/* Metric cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[
          { label: 'Core Engine Uptime', value: data?.uptime_human },
          { label: 'CPU Load',           value: data ? `${data.global_load.toFixed(1)}%` : undefined },
          { label: 'DB Version',         value: data?.db_version },
          { label: 'Encryption',         value: data?.encryption },
        ].map(({ label, value }) => (
          <div
            key={label}
            className="rounded-lg border border-border bg-bg-surface px-4 py-3"
          >
            <p className="font-ui text-xs tracking-wider text-text-secondary uppercase">{label}</p>
            {isLoading || !value
              ? <div className="skeleton mt-2 h-7 w-28 rounded-sm" />
              : <p className="mt-1 font-mono text-2xl text-text-primary">{value}</p>
            }
          </div>
        ))}
      </div>

      {/* Sensor list */}
      <div className="rounded-lg border border-border bg-bg-surface overflow-hidden">
        <div className="flex items-center justify-between border-b border-border px-5 py-3">
          <span className="font-ui text-sm font-medium text-text-primary">Active Sensors</span>
          {data && (
            <span className="rounded-sm border border-border px-2 py-0.5 font-mono text-xs text-text-secondary">
              TOTAL: {data.sensors.length}
            </span>
          )}
        </div>

        <div className="divide-y divide-border" role="list" aria-label="Sensor list">
          {isLoading
            ? Array.from({ length: 5 }, (_, i) => (
                <div key={i} className="flex items-center justify-between px-5 py-3.5" role="listitem">
                  <div className="space-y-1.5">
                    <div className="skeleton h-3.5 w-32 rounded-sm" />
                    <div className="skeleton h-3 w-20 rounded-sm" />
                  </div>
                  <div className="skeleton h-5 w-16 rounded-sm" />
                </div>
              ))
            : (data?.sensors ?? []).map(sensor => (
                <div
                  key={sensor.id}
                  className="flex items-center justify-between px-5 py-3.5"
                  role="listitem"
                >
                  <div>
                    <p className="font-display text-sm text-text-primary">{sensor.id}</p>
                    <p className="font-mono text-xs text-text-tertiary">{sensor.ip}</p>
                  </div>
                  <div className="flex items-center gap-3">
                    {sensor.latency_ms !== undefined && (
                      <span className="font-mono text-xs text-text-secondary">
                        {sensor.latency_ms}ms
                      </span>
                    )}
                    <StatusBadge
                      variant={
                        sensor.status === 'online'  ? 'authorized' :
                        sensor.status === 'latency' ? 'warning' : 'critical'
                      }
                      label={sensor.status.toUpperCase()}
                    />
                  </div>
                </div>
              ))
          }
        </div>
      </div>

      {/* Node latency gauges — SVG semi-circle arcs */}
      {data?.node_latency && (
        <div className="rounded-lg border border-border bg-bg-surface p-5">
          <h2 className="mb-5 font-ui text-sm font-medium text-text-primary uppercase tracking-wider">
            Detection Engine Node Latency (ms)
          </h2>
          <div className="grid grid-cols-2 gap-6 sm:grid-cols-4">
            {[
              { label: 'Primary\nDecryption',  value: data.node_latency.primary_decryption_ms,  max: 200 },
              { label: 'Heuristic\nAnalysis',  value: data.node_latency.heuristic_analysis_ms,  max: 200 },
              { label: 'Packet\nInspection',   value: data.node_latency.packet_inspection_ms,   max: 200 },
              { label: 'Metadata\nExtraction', value: data.node_latency.metadata_extraction_ms, max: 200 },
            ].map(({ label, value, max }) => (
              <SemiGauge key={label} label={label} value={value} max={max} />
            ))}
          </div>
        </div>
      )}

      {/* Event log */}
      <div className="rounded-lg border border-border bg-bg-surface overflow-hidden">
        <div className="flex items-center justify-between border-b border-border px-5 py-3">
          <span className="font-ui text-sm font-medium text-text-primary">System Event Log</span>
          <div className="flex gap-4">
            <button
              onClick={downloadHealthCsv}
              className="font-display text-xs tracking-wider text-text-secondary hover:text-cyan transition-colors uppercase"
            >
              Download CSV
            </button>
            <button
              onClick={flushUiCache}
              className="font-display text-xs tracking-wider text-text-secondary hover:text-critical transition-colors uppercase"
            >
              Flush Cache
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full" role="grid" aria-label="System event log">
            <thead>
              <tr className="border-b border-border-strong">
                {['Timestamp', 'Event ID', 'Source', 'Message', 'Status'].map(h => (
                  <th
                    key={h}
                    scope="col"
                    className="px-4 py-2.5 text-left font-ui text-xs font-semibold tracking-wider text-text-secondary uppercase"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>

            <tbody>
              {isLoading
                ? Array.from({ length: 4 }, (_, i) => (
                    <tr key={i} className="border-b border-border/50">
                      {Array.from({ length: 5 }, (_, j) => (
                        <td key={j} className="px-4 py-3">
                          <div className="skeleton h-3.5 rounded-sm" style={{ width: `${50 + j * 8}%` }} />
                        </td>
                      ))}
                    </tr>
                  ))
                : (data?.events ?? []).map(evt => (
                    <tr
                      key={evt.event_id}
                      className="border-b border-border/50 hover:bg-bg-hover transition-colors"
                    >
                      <td className="px-4 py-3 font-mono text-xs text-text-code whitespace-nowrap">
                        {evt.timestamp}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-text-secondary">
                        {evt.event_id}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-text-tertiary">
                        {evt.source}
                      </td>
                      <td className="px-4 py-3 font-ui text-sm text-text-primary">
                        {evt.message}
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge variant={evt.status as any} label={evt.status.toUpperCase()} />
                      </td>
                    </tr>
                  ))
              }
            </tbody>
          </table>
        </div>
      </div>

      {/* Footer metadata */}
      {data && (
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border pt-3 font-mono text-xs text-text-tertiary">
          <span>SEC-OPS OS V2.4.0 · DB_VER: {data.db_version}</span>
          <span>
            ENCRYPTION: {data.encryption} ACTIVE ·{' '}
            <span className={data.error_count > 0 ? 'text-critical' : ''}>
              {data.error_count} ERRORS
            </span>
            {' / '}
            <span className={data.warning_count > 0 ? 'text-warning' : ''}>
              {data.warning_count} WARNINGS
            </span>
          </span>
        </div>
      )}
    </div>
  )
}

// ── SVG Semi-circular gauge ───────────────────────────────────
function SemiGauge({ label, value, max }: { label: string; value: number; max: number }) {
  const SIZE   = 120
  const STROKE = 8
  const R      = (SIZE / 2) - STROKE / 2 - 2
  const CX     = SIZE / 2

  // Semi-circle arc (left → right, top half)
  const progress      = Math.min(Math.max(value / max, 0), 1)
  const circumference = Math.PI * R
  const dashOffset    = circumference * (1 - progress)

  const color =
    value < 50  ? '#2ECC71' :
    value < 100 ? '#F5A623' : '#FF3B3B'

  const filterId = `gauge-glow-${label.replace(/\W/g, '')}`

  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: SIZE, height: SIZE / 2 + 24 }}>
        <svg
          width={SIZE}
          height={SIZE / 2 + 16}
          viewBox={`0 0 ${SIZE} ${SIZE / 2 + 16}`}
          overflow="visible"
        >
          <defs>
            <filter id={filterId} x="-30%" y="-30%" width="160%" height="160%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Track (full half-circle) */}
          <path
            d={`M ${STROKE / 2 + 2} ${SIZE / 2} A ${R} ${R} 0 0 1 ${SIZE - STROKE / 2 - 2} ${SIZE / 2}`}
            fill="none"
            stroke="#1E2535"
            strokeWidth={STROKE}
            strokeLinecap="round"
          />

          {/* Progress arc */}
          <path
            d={`M ${STROKE / 2 + 2} ${SIZE / 2} A ${R} ${R} 0 0 1 ${SIZE - STROKE / 2 - 2} ${SIZE / 2}`}
            fill="none"
            stroke={color}
            strokeWidth={STROKE}
            strokeLinecap="round"
            strokeDasharray={`${circumference} ${circumference}`}
            strokeDashoffset={dashOffset}
            filter={`url(#${filterId})`}
            style={{ transition: 'stroke-dashoffset 0.6s cubic-bezier(.4,0,.2,1)' }}
          />

          {/* Tip dot */}
          {progress > 0.02 && (() => {
            const tipAngle = Math.PI * (1 - progress)
            const tipX = CX + R * Math.cos(tipAngle)
            const tipY = (SIZE / 2) - R * Math.sin(tipAngle)
            return (
              <circle
                cx={tipX}
                cy={tipY}
                r={STROKE / 2 + 1}
                fill={color}
                filter={`url(#${filterId})`}
              />
            )
          })()}
        </svg>

        {/* Value centered below arc */}
        <div
          className="absolute left-0 right-0 flex flex-col items-center"
          style={{ top: SIZE / 2 - 4 }}
        >
          <span className="font-display text-xl font-bold leading-none" style={{ color }}>
            {value}ms
          </span>
        </div>
      </div>

      {/* Label */}
      <p className="mt-1 text-center font-ui text-[10px] font-medium tracking-widest text-text-tertiary uppercase leading-tight whitespace-pre-line">
        {label}
      </p>
    </div>
  )
}

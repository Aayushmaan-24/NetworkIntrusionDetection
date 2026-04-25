import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { RefreshCw, ShieldAlert, ShieldOff, Clock, Zap, Database, ShieldCheck } from 'lucide-react'
import { StatCard } from '@/components/ui/badges'
import { ErrorState } from '@/components/ui/index'
import { useDashboard } from '@/hooks'
import { DashboardTimeline, ThreatDonut } from '@/components/charts/DashboardCharts'
import CardHover from '@/components/ui/card-hover'
import { useAppStore } from '@/store/appStore'

export function DashboardPage() {
  const navigate = useNavigate()
  const { data, isLoading, error, refetch, isFetching } = useDashboard()
  const liveTelemetry = useAppStore(s => s.liveTelemetry)
  const liveStreamConnected = useAppStore(s => s.liveStreamConnected)
  const [timelineMode, setTimelineMode] = useState<'realtime' | 'archive'>('realtime')
  const liveTotals = liveTelemetry?.totals

  const activeTimeline = useMemo(
    () => (timelineMode === 'realtime' ? data?.timeline : data?.archive_timeline),
    [data?.archive_timeline, data?.timeline, timelineMode],
  )

  const refreshPage = async () => {
    await refetch()
    window.location.reload()
  }

  const formatTime = (iso: string) => {
    const time = new Date(iso)
    if (Number.isNaN(time.getTime())) return 'just now'
    return time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  }

  return (
    <div className="flex flex-col gap-6 animate-fade-in">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-display text-xl tracking-wide text-text-primary uppercase">
            Overview
          </h1>
          <p className="font-mono text-xs text-text-tertiary tracking-wider">
            PACKET INSPECTION DENSITY · GLOBAL NODES
          </p>
        </div>
        <button
          onClick={refreshPage}
          disabled={isFetching}
          aria-label="Refresh dashboard"
          className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 font-ui text-xs text-text-secondary hover:bg-bg-hover disabled:opacity-40 transition-colors"
        >
          <RefreshCw size={12} className={isFetching ? 'animate-spin' : ''} />
          REFRESH
        </button>
      </div>

      {/* Stat cards grid */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Total Attacks [24H]"
          value={liveTotals?.attacks ?? data?.total_attacks_24h ?? 0}
          delta={data ? `+${data.total_attacks_delta.toFixed(1)}%` : undefined}
          deltaDir="up"
          icon={<ShieldAlert size={16} />}
          variant="critical"
          loading={isLoading}
        />
        <StatCard
          label="Threats Blocked"
          value={data?.threats_blocked ?? 0}
          delta={data ? `${data.threats_blocked_pct.toFixed(1)}%` : undefined}
          deltaDir="up"
          icon={<ShieldOff size={16} />}
          variant="success"
          loading={isLoading}
        />
        <StatCard
          label="Active Threats"
          value={liveTotals?.high_risk_connections ?? data?.active_threats ?? 0}
          delta={data?.active_threats_level?.toUpperCase()}
          deltaDir="neutral"
          icon={<Zap size={16} />}
          variant="warning"
          loading={isLoading}
        />
        <StatCard
          label="System Latency"
          value={data ? `${data.system_latency_ms}ms` : '—'}
          delta={data?.latency_status?.toUpperCase()}
          deltaDir="neutral"
          icon={<Clock size={16} />}
          variant="info"
          loading={isLoading}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[320px_1fr]">
        <div className="rounded-lg border border-border bg-bg-surface p-4">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="font-ui text-sm font-medium text-text-primary">Live DB Activity</h2>
            <Database size={14} className="text-cyan" />
          </div>
          <div className="space-y-3">
            {[
              { label: 'Predictions (1h)', value: data?.recent_predictions_1h ?? 0 },
              { label: 'Predictions (24h)', value: data?.recent_predictions_24h ?? 0 },
              { label: 'Actions (1h)', value: data?.recent_actions_1h ?? 0 },
              { label: 'Actions (24h)', value: data?.recent_actions_24h ?? 0 },
            ].map(row => (
              <div key={row.label} className="rounded-md border border-border/60 bg-bg-base/60 px-3 py-2">
                <p className="font-ui text-[10px] tracking-wider text-text-tertiary uppercase">{row.label}</p>
                <p className="font-display text-lg text-text-primary">
                  {(row.label === 'Predictions (1h)' ? liveTelemetry?.db_activity?.predictions_1h :
                    row.label === 'Predictions (24h)' ? liveTelemetry?.db_activity?.predictions_24h :
                    row.label === 'Actions (1h)' ? liveTelemetry?.db_activity?.actions_1h :
                    row.label === 'Actions (24h)' ? liveTelemetry?.db_activity?.actions_24h :
                    row.value
                  )?.toLocaleString?.() ?? row.value.toLocaleString()}
                </p>
              </div>
            ))}
            <p className={`font-mono text-[10px] tracking-wider ${liveStreamConnected ? 'text-cyan' : 'text-text-tertiary'}`}>
              STREAM: {liveStreamConnected ? 'LIVE' : 'RECONNECTING'}
            </p>
          </div>
        </div>

        <div className="rounded-lg border border-border bg-bg-surface p-4">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="font-ui text-sm font-medium text-text-primary">Recent Operator + Model Events</h2>
            <ShieldCheck size={14} className="text-cyan" />
          </div>
          <div className="max-h-56 space-y-2 overflow-auto pr-1">
            {(data?.activity_feed ?? []).length === 0 && (
              <p className="rounded-md border border-border/60 bg-bg-base/50 px-3 py-2 font-ui text-xs text-text-tertiary">
                No DB activity yet. Run predictions or apply actions on a connection to populate this feed.
              </p>
            )}
            {(data?.activity_feed ?? []).map((event, idx) => (
              <div key={`${event.created_at}-${idx}`} className="rounded-md border border-border/60 bg-bg-base/60 px-3 py-2">
                <div className="mb-1 flex items-center justify-between">
                  <p className="font-ui text-xs text-text-primary">{event.title}</p>
                  <span className="font-mono text-[10px] text-text-tertiary">{formatTime(event.created_at)}</span>
                </div>
                <p className="font-mono text-[11px] text-text-secondary">{event.detail}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Charts row */}
      {error ? (
        <ErrorState
          title="Failed to load dashboard data"
          message={(error as any)?.message}
          onRetry={() => refetch()}
        />
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_300px]">
          {/* Area chart */}
          <div className="rounded-lg border border-border bg-bg-surface p-5">
            <div className="mb-4 flex items-start justify-between">
              <div>
                <h2 className="font-ui text-base font-medium text-text-primary">
                  Attack Distribution over 24h
                </h2>
                <p className="font-mono text-xs tracking-wider text-text-tertiary uppercase">
                  Packet Inspection Density [Global Nodes]
                </p>
              </div>
              <div className="flex gap-1">
                {[
                  { key: 'realtime', label: 'REAL-TIME' },
                  { key: 'archive', label: 'ARCHIVE' },
                ].map(mode => (
                  <button
                    key={mode.key}
                    onClick={() => setTimelineMode(mode.key as 'realtime' | 'archive')}
                    className={`rounded-sm border px-2 py-1 font-display text-xs tracking-wider transition-colors ${
                      timelineMode === mode.key
                        ? 'text-cyan border-cyan bg-cyan/10'
                        : 'border-border text-text-secondary hover:bg-bg-hover'
                    }`}
                  >
                    {mode.label}
                  </button>
                ))}
              </div>
            </div>
            <DashboardTimeline data={activeTimeline} loading={isLoading} />
          </div>

          {/* Donut */}
          <div className="rounded-lg border border-border bg-bg-surface p-5">
            <h2 className="mb-1 font-ui text-base font-medium text-text-primary">
              Threat Levels
            </h2>
            <p className="mb-4 font-mono text-xs tracking-wider text-text-tertiary uppercase">
              Active Signature Matches
            </p>
            <ThreatDonut data={data?.threat_levels} loading={isLoading} />
          </div>
        </div>
      )}

      {/* ── Quick Intel cards ───────────────────────── */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
        <CardHover
          title="Network Intrusion Detection"
          tagLabel="Core"
          linkLabel="View live connections"
          linkHref="/connections"
          imageAlt="core threat stream visualization"
          variant="core"
        />
        <CardHover
          title="ML Threat Prediction Engine"
          tagLabel="AI/ML"
          linkLabel="Run prediction analysis"
          linkHref="/predict"
          imageAlt="machine learning prediction neural grid"
          variant="ml"
        />
        <CardHover
          title="System Health & Telemetry"
          tagLabel="Health"
          linkLabel="View sensor status"
          linkHref="/health"
          imageAlt="health telemetry control matrix"
          variant="health"
        />
      </div>

      {/* Recent alerts table */}
      <div className="rounded-lg border border-border bg-bg-surface">
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <div>
            <h2 className="font-ui text-base font-medium text-text-primary">Recent Security Alerts</h2>
            <p className="font-mono text-xs tracking-wider text-text-tertiary uppercase">
              Direct Stream From Sensor Cluster-A
            </p>
          </div>
          <button
            onClick={() => navigate('/connections?view=history&time=LAST%2024%20HOURS')}
            className="rounded-sm border border-border px-3 py-1.5 font-display text-xs tracking-wider text-text-secondary hover:bg-bg-hover transition-colors"
          >
            VIEW FULL LOGS
          </button>
        </div>

        {/* Alerts table — import DataTable or inline for brevity */}
        <AlertsTable data={data?.recent_alerts} loading={isLoading} />
      </div>
    </div>
  )
}

// ── Inline alerts table ───────────────────────────────────────
import type { Alert } from '@/types/api'
import { StatusBadge } from '@/components/ui/badges'

function AlertsTable({ data, loading }: { data?: Alert[]; loading: boolean }) {
  const headers = ['Timestamp', 'Severity', 'Vector', 'Source IP', 'Payload Action', 'Status']

  return (
    <div className="overflow-x-auto">
      <table className="w-full" role="grid">
        <thead>
          <tr className="border-b border-border-strong">
            {headers.map(h => (
              <th key={h} scope="col" className="px-4 py-2.5 text-left font-ui text-xs font-semibold tracking-wider text-text-secondary uppercase">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {loading ? Array.from({ length: 4 }, (_, i) => (
            <tr key={i} className="border-b border-border/50">
              {headers.map(h => (
                <td key={h} className="px-4 py-3">
                  <div className="skeleton h-3.5 rounded-sm w-3/4" />
                </td>
              ))}
            </tr>
          )) : (data ?? []).map((alert, i) => (
            <tr key={i} className="border-b border-border/50 hover:bg-bg-hover transition-colors">
              <td className="px-4 py-3 font-mono text-sm text-text-code">{alert.timestamp}</td>
              <td className="px-4 py-3"><StatusBadge variant={alert.severity} /></td>
              <td className="px-4 py-3 font-ui text-sm text-text-primary">{alert.vector}</td>
              <td className="px-4 py-3 font-mono text-sm text-text-code">{alert.source_ip}</td>
              <td className="px-4 py-3 font-mono text-xs text-text-tertiary">{alert.payload_action}</td>
              <td className="px-4 py-3"><StatusBadge variant={alert.status} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

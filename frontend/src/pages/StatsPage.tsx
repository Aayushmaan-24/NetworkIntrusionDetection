import { useLocation, NavLink } from 'react-router-dom'
import { RefreshCw } from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from 'recharts'
import { useStatsAttacks, useStatsProtocols, useStatsServices } from '@/hooks'
import { EmptyState, ErrorState } from '@/components/ui/index'
import { cn } from '@/lib/utils'

const STATS_TABS = [
  { to: '/stats/attacks',   label: 'Attacks'   },
  { to: '/stats/protocols', label: 'Protocols' },
  { to: '/stats/services',  label: 'Services'  },
]

export function StatsPage() {
  const location = useLocation()
  const tab = location.pathname.split('/').pop() as 'attacks' | 'protocols' | 'services'

  const attacks   = useStatsAttacks()
  const protocols = useStatsProtocols()
  const services  = useStatsServices()

  const activeQuery =
    tab === 'attacks'   ? attacks :
    tab === 'protocols' ? protocols : services

  const refreshPage = async () => {
    await activeQuery.refetch()
    window.location.reload()
  }

  const rawData =
    tab === 'attacks'   ? attacks.data?.data :
    tab === 'protocols' ? protocols.data?.data : services.data?.data

  const chartData = (rawData ?? []).map((d: any) => ({
    name:  d.attack_type ?? d.protocol ?? d.service ?? '—',
    count: d.count,
    pct:   d.pct,
  }))

  return (
    <div className="flex flex-col gap-6 animate-fade-in">

      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h1 className="font-display text-xl tracking-wide text-text-primary uppercase">
          Analytics
        </h1>

        <div className="flex items-center gap-2">
          {/* Tab nav */}
          <nav className="flex gap-1" aria-label="Stats view tabs">
            {STATS_TABS.map(t => (
              <NavLink
                key={t.to}
                to={t.to}
                className={({ isActive }) => cn(
                  'rounded-sm border px-3 py-1.5 font-display text-xs tracking-wider uppercase transition-colors',
                  isActive
                    ? 'border-cyan bg-cyan/10 text-cyan'
                    : 'border-border text-text-secondary hover:bg-bg-hover'
                )}
              >
                {t.label}
              </NavLink>
            ))}
          </nav>

          <button
            onClick={refreshPage}
            disabled={activeQuery.isFetching}
            aria-label="Refresh stats"
            className="flex items-center justify-center h-8 w-8 rounded-md border border-border text-text-tertiary hover:bg-bg-hover hover:text-text-primary disabled:opacity-40 transition-colors"
          >
            <RefreshCw size={13} className={activeQuery.isFetching ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {/* Chart panel */}
      <div className="rounded-lg border border-border bg-bg-surface p-5">

        {/* Loading skeleton */}
        {activeQuery.isLoading && (
          <div className="flex items-end gap-2 h-64" aria-label="Loading chart" aria-busy="true">
            {Array.from({ length: 12 }, (_, i) => (
              <div
                key={i}
                className="skeleton flex-1 rounded-sm"
                style={{ height: `${20 + ((i * 17) % 60)}%` }}
              />
            ))}
          </div>
        )}

        {/* Error */}
        {!activeQuery.isLoading && activeQuery.error && (
          <ErrorState
            title={`Failed to load ${tab} data`}
            message={(activeQuery.error as any)?.message}
            onRetry={() => activeQuery.refetch()}
            compact
          />
        )}

        {/* Empty */}
        {!activeQuery.isLoading && !activeQuery.error && chartData.length === 0 && (
          <EmptyState
            title="No data for this period"
            description="No statistics are available. Check back after traffic has been captured."
          />
        )}

        {/* Chart */}
        {!activeQuery.isLoading && !activeQuery.error && chartData.length > 0 && (
          <>
            <div
              role="img"
              aria-label={`${tab} distribution bar chart, ${chartData.length} entries`}
            >
              <ResponsiveContainer width="100%" height={280}>
                <BarChart
                  data={chartData}
                  margin={{ top: 8, right: 8, left: 0, bottom: 32 }}
                >
                  <XAxis
                    dataKey="name"
                    tick={{ fontFamily: 'JetBrains Mono', fontSize: 10, fill: '#4A5570' }}
                    axisLine={false}
                    tickLine={false}
                    angle={-30}
                    textAnchor="end"
                    interval={0}
                  />
                  <YAxis
                    tick={{ fontFamily: 'JetBrains Mono', fontSize: 10, fill: '#4A5570' }}
                    axisLine={false}
                    tickLine={false}
                    width={40}
                  />
                  <Tooltip
                    contentStyle={{
                      background: '#161B27',
                      border: '1px solid #2A3448',
                      borderRadius: 4,
                      fontFamily: 'JetBrains Mono',
                      fontSize: 11,
                    }}
                    itemStyle={{ color: '#00C8C8' }}
                    cursor={{ fill: 'rgba(0,200,200,0.04)' }}
                    formatter={(value: number) => [value.toLocaleString(), 'Count']}
                  />
                  <Bar dataKey="count" radius={[2, 2, 0, 0]} maxBarSize={48}>
                    {chartData.map((_, i) => (
                      <Cell
                        key={i}
                        fill={i === 0 ? '#00C8C8' : '#1E2535'}
                        stroke={i === 0 ? '#00C8C8' : '#2A3448'}
                        strokeWidth={0.5}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            {/* Hidden data table for screen readers */}
            <table className="sr-only" aria-label={`${tab} data table`}>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Count</th>
                  <th>Percentage</th>
                </tr>
              </thead>
              <tbody>
                {chartData.map((row, i) => (
                  <tr key={i}>
                    <td>{row.name}</td>
                    <td>{row.count.toLocaleString()}</td>
                    <td>{row.pct.toFixed(1)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>

            {/* Visible raw data table */}
            <div className="mt-4 overflow-x-auto border-t border-border pt-4">
              <table className="w-full" role="grid">
                <thead>
                  <tr>
                    {['Name', 'Count', '%'].map(h => (
                      <th
                        key={h}
                        scope="col"
                        className={cn(
                          'py-2 font-ui text-xs font-semibold tracking-wider text-text-secondary uppercase',
                          h === '%' || h === 'Count' ? 'text-right px-4' : 'text-left px-4'
                        )}
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {chartData.map((row, i) => (
                    <tr
                      key={i}
                      className="border-b border-border/40 hover:bg-bg-hover transition-colors"
                    >
                      <td className="px-4 py-2.5 font-mono text-sm text-text-code">{row.name}</td>
                      <td className="px-4 py-2.5 font-mono text-sm text-text-primary text-right">
                        {row.count.toLocaleString()}
                      </td>
                      <td className="px-4 py-2.5 font-mono text-sm text-text-secondary text-right">
                        {row.pct.toFixed(1)}%
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

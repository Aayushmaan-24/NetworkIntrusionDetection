import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
} from 'recharts'
import type { TimelinePoint, ThreatLevels } from '@/types/api'

// ── DashboardTimeline ─────────────────────────────────────────
export function DashboardTimeline({
  data, loading,
}: { data?: TimelinePoint[]; loading?: boolean }) {
  if (loading) {
    return (
      <div className="flex items-end gap-0.5 h-[200px] overflow-hidden rounded">
        {Array.from({ length: 24 }, (_, i) => (
          <div
            key={i}
            className="skeleton flex-1 rounded-sm"
            style={{ height: `${20 + Math.sin(i * 0.5) * 40 + 40}%` }}
          />
        ))}
      </div>
    )
  }

  if (!data?.length) return null

  return (
    <div aria-label="Attack distribution timeline" role="img">
      <ResponsiveContainer width="100%" height={200}>
        <AreaChart data={data} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
          <defs>
            {/* Stronger cyan glow gradient */}
            <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%"  stopColor="#00C8C8" stopOpacity={0.45} />
              <stop offset="60%" stopColor="#00C8C8" stopOpacity={0.08} />
              <stop offset="100%" stopColor="#00C8C8" stopOpacity={0} />
            </linearGradient>
            {/* Glow filter for the stroke line */}
            <filter id="lineGlow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>
          <XAxis
            dataKey="time"
            tick={{ fontFamily: 'JetBrains Mono', fontSize: 10, fill: '#4A5570' }}
            axisLine={false} tickLine={false}
          />
          <YAxis
            tick={{ fontFamily: 'JetBrains Mono', fontSize: 10, fill: '#4A5570' }}
            axisLine={false} tickLine={false}
          />
          <Tooltip
            contentStyle={{
              background: 'rgba(17, 21, 32, 0.95)',
              border: '1px solid rgba(0, 200, 200, 0.3)',
              borderRadius: 4,
              fontFamily: 'JetBrains Mono',
              fontSize: 11,
              boxShadow: '0 0 16px rgba(0,200,200,0.15)',
            }}
            itemStyle={{ color: '#00C8C8' }}
            labelStyle={{ color: '#8A95B0', marginBottom: 4 }}
            cursor={{ stroke: 'rgba(0,200,200,0.4)', strokeWidth: 1, strokeDasharray: '4 4' }}
          />
          <Area
            type="monotone"
            dataKey="value"
            stroke="#00C8C8"
            strokeWidth={2}
            fill="url(#areaGrad)"
            dot={false}
            filter="url(#lineGlow)"
            activeDot={{ r: 4, fill: '#00C8C8', stroke: '#0B0E14', strokeWidth: 2 }}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}

// ── ThreatDonut ────────────────────────────────────────────────
const DONUT_COLORS = {
  critical:   '#FF3B3B',
  suspicious: '#4A90D9',
  benign:     '#2ECC71',
  other:      '#3A4560',
}

export function ThreatDonut({
  data, loading,
}: { data?: ThreatLevels; loading?: boolean }) {
  if (loading) {
    return (
      <div className="flex flex-col items-center gap-4">
        <div className="skeleton h-36 w-36 rounded-full" />
        {Array.from({ length: 4 }, (_, i) => (
          <div key={i} className="flex w-full items-center gap-2">
            <div className="skeleton h-2.5 w-2.5 rounded-full" />
            <div className="skeleton h-3 flex-1 rounded-sm" />
          </div>
        ))}
      </div>
    )
  }

  if (!data) return null

  const pieData = [
    { name: 'Critical',   value: data.critical.count,   key: 'critical'   as const },
    { name: 'Suspicious', value: data.suspicious.count, key: 'suspicious' as const },
    { name: 'Benign',     value: data.benign.count,     key: 'benign'     as const },
    { name: 'Other',      value: data.other.count,      key: 'other'      as const },
  ]

  const totalLabel = data.total_events >= 1000
    ? `${(data.total_events / 1000).toFixed(1)}k`
    : String(data.total_events)

  return (
    <div aria-label={`Threat levels: ${data.total_events} total events`} role="img">

      {/* Chart with center label overlaid */}
      <div className="relative mx-auto" style={{ width: 200, height: 200 }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <defs>
              <filter id="donutGlow">
                <feGaussianBlur stdDeviation="2.5" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>
            <Pie
              data={pieData}
              cx="50%"
              cy="50%"
              innerRadius={58}
              outerRadius={80}
              paddingAngle={3}
              dataKey="value"
              stroke="none"
              filter="url(#donutGlow)"
            >
              {pieData.map(entry => (
                <Cell key={entry.key} fill={DONUT_COLORS[entry.key]} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                background: 'rgba(17, 21, 32, 0.95)',
                border: '1px solid rgba(0,200,200,0.25)',
                borderRadius: 4,
                fontFamily: 'JetBrains Mono',
                fontSize: 11,
              }}
            />
          </PieChart>
        </ResponsiveContainer>

        {/* Center label — absolutely positioned inside the ring */}
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          {data.critical.count > 0 && (
            <span className="font-mono text-[10px] tracking-widest text-critical/80 uppercase mb-0.5">
              PEAK: {(data.critical.count / 1000).toFixed(1)} GB/S
            </span>
          )}
          <span className="font-display text-2xl font-bold tracking-tight text-text-primary leading-none">
            {totalLabel}
          </span>
          <span className="font-mono text-[10px] tracking-widest text-text-tertiary uppercase mt-0.5">
            EVENTS
          </span>
        </div>
      </div>

      {/* Legend */}
      <div className="mt-4 grid grid-cols-2 gap-x-4 gap-y-2">
        {pieData.map(entry => (
          <div key={entry.key} className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-1.5">
              <div
                className="h-2 w-2 rounded-full shrink-0"
                style={{ background: DONUT_COLORS[entry.key], boxShadow: `0 0 6px ${DONUT_COLORS[entry.key]}` }}
              />
              <span className="font-mono text-xs text-text-secondary">
                {entry.name.toUpperCase()}
              </span>
            </div>
            <span className="font-mono text-xs text-text-tertiary">
              {(data[entry.key as keyof ThreatLevels] as any)?.pct?.toFixed(0)}%
              <span className="ml-1 text-text-tertiary/60">
                · {entry.value.toLocaleString()}
              </span>
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

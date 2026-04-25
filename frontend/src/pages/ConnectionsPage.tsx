import { useMemo } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Download, RotateCcw, RadioTower, History, MapPinned } from 'lucide-react'
import { CircleMarker, MapContainer, Marker, Polyline, Popup, TileLayer, Tooltip } from 'react-leaflet'
import { divIcon, type LatLngExpression } from 'leaflet'
import { useConnections, useConnectionsGeoSummary } from '@/hooks'
import { DataTable, type Column } from '@/components/ui/DataTable'
import { PaginationBar, ActionButton } from '@/components/ui/index'
import { StatusBadge, ProtocolChip } from '@/components/ui/badges'
import { useAppStore } from '@/store/appStore'
import type { Connection, RiskLevel } from '@/types/api'

const COLUMNS: Column<Connection>[] = [
  { key: 'timestamp', header: 'Timestamp', mono: true, width: '180px' },
  {
    key: 'src_ip',
    header: 'Source IP',
    mono: true,
    render: row => `${row.src_ip}:${row.src_port}`,
  },
  {
    key: 'dst_ip',
    header: 'Destination IP',
    mono: true,
    render: row => `${row.dst_ip}:${row.dst_port}`,
  },
  {
    key: 'protocol',
    header: 'Protocol',
    width: '100px',
    render: row => <ProtocolChip protocol={row.protocol} />,
  },
  { key: 'flags', header: 'Flags', mono: true, width: '80px' },
  { key: 'bytes_human', header: 'Bytes', mono: true, align: 'right', width: '80px' },
  {
    key: 'status',
    header: 'Status',
    width: '120px',
    render: row => <StatusBadge variant={row.status} />,
  },
]

const TIME_OPTIONS = ['LAST 15 MINUTES', 'LAST 1 HOUR', 'LAST 24 HOURS', 'ALL']
const RISK_OPTIONS: Array<{ label: string; value: RiskLevel | '' }> = [
  { label: 'LOW TO CRITICAL', value: '' },
  { label: 'HIGH', value: 'high' },
  { label: 'MEDIUM', value: 'medium' },
  { label: 'LOW', value: 'low' },
  { label: 'NORMAL', value: 'normal' },
]

function csvEscape(value: string | number) {
  const str = String(value)
  if (str.includes(',') || str.includes('"') || str.includes('\n')) {
    return `"${str.replace(/"/g, '""')}"`
  }
  return str
}

const VIEW_OPTIONS = [
  { key: 'live', label: 'Live Feed', icon: RadioTower },
  { key: 'history', label: 'Historical Logs', icon: History },
  { key: 'map', label: 'Traffic Map', icon: MapPinned },
] as const

type ViewMode = (typeof VIEW_OPTIONS)[number]['key']

const CITY_COORDS: Record<string, { lat: number; lng: number }> = {
  Bengaluru: { lat: 12.9716, lng: 77.5946 },
  Chennai: { lat: 13.0827, lng: 80.2707 },
  Delhi: { lat: 28.6139, lng: 77.209 },
  Mumbai: { lat: 19.076, lng: 72.8777 },
  Hyderabad: { lat: 17.385, lng: 78.4867 },
  Kolkata: { lat: 22.5726, lng: 88.3639 },
  Pune: { lat: 18.5204, lng: 73.8567 },
  Ahmedabad: { lat: 23.0225, lng: 72.5714 },
  Jaipur: { lat: 26.9124, lng: 75.7873 },
  Kochi: { lat: 9.9312, lng: 76.2673 },
  Lucknow: { lat: 26.8467, lng: 80.9462 },
}

const INDIA_CENTER: LatLngExpression = [22.5937, 78.9629]
const LOCATION_PIN_ICON = divIcon({
  className: 'nids-map-pin',
  html: '<div class="nids-map-pin-inner"></div>',
  iconSize: [24, 32],
  iconAnchor: [12, 30],
  popupAnchor: [0, -28],
})

export function ConnectionsPage() {
  const navigate = useNavigate()
  const [params, setParams] = useSearchParams()
  const addToast = useAppStore(s => s.addToast)

  const page = Number(params.get('page') ?? 1)
  const limit = Number(params.get('limit') ?? 25)
  const protocol = params.get('protocol') ?? undefined
  const risk_level = (params.get('risk') ?? undefined) as RiskLevel | undefined
  const time_range = params.get('time') ?? 'LAST 15 MINUTES'
  const rawView = params.get('view') ?? 'live'
  const view = (rawView === 'history' || rawView === 'map' ? rawView : 'live') as ViewMode

  const { data, isLoading, error, refetch } = useConnections({ page, limit, protocol, risk_level })
  const { data: geoSummary } = useConnectionsGeoSummary({ protocol, risk_level })

  const protocolOptions = useMemo(() => {
    const unique = new Set((data?.data ?? []).map(row => row.protocol))
    return Array.from(unique).sort()
  }, [data?.data])

  const trendPoints = useMemo(() => {
    const rows = data?.data ?? []
    return Array.from({ length: 12 }, (_, idx) => {
      const row = rows[idx % Math.max(rows.length, 1)]
      const base = row?.bytes ?? 0
      const anomaly = row?.anomaly_score ?? 0
      const adjusted = Math.max(5, Math.round(base / 1024 + anomaly * 0.4 + (idx % 4) * 6))
      return { label: `${String(idx * 2).padStart(2, '0')}:00`, value: adjusted }
    })
  }, [data?.data])

  const cityHeat = useMemo<Record<string, number>>(() => {
    if (geoSummary?.city_breakdown?.length) {
      const buckets: Record<string, number> = {}
      for (const city of geoSummary.city_breakdown) {
        buckets[city.city] = city.count
      }
      return buckets
    }
    const buckets: Record<string, number> = {}
    for (const row of data?.data ?? []) {
      const city = row.region_city ?? 'Delhi'
      buckets[city] = (buckets[city] ?? 0) + 1
    }
    return buckets
  }, [data?.data, geoSummary?.city_breakdown])

  const avgAnomaly = useMemo(() => {
    const rows = data?.data ?? []
    if (rows.length === 0) return 0
    const total = rows.reduce((sum, row) => sum + (row.anomaly_score ?? 0), 0)
    return Math.round(total / rows.length)
  }, [data?.data])

  const mapPoints = useMemo(() => {
    if (geoSummary?.city_breakdown?.length) {
      return geoSummary.city_breakdown.map(city => ({
        city: city.city,
        country: city.country,
        lat: city.lat,
        lng: city.lng,
        count: city.count,
        avgAnomaly: city.avg_anomaly,
      }))
    }

    return Object.entries(cityHeat).map(([city, count]) => ({
      city,
      country: 'India',
      lat: CITY_COORDS[city]?.lat ?? 20.5937,
      lng: CITY_COORDS[city]?.lng ?? 78.9629,
      count,
      avgAnomaly,
    }))
  }, [geoSummary?.city_breakdown, cityHeat, avgAnomaly])

  const maxPointCount = useMemo(
    () => Math.max(1, ...mapPoints.map(p => p.count)),
    [mapPoints],
  )
  const cityThroughput = useMemo(
    () => [...mapPoints].sort((a, b) => b.count - a.count).slice(0, 6),
    [mapPoints],
  )

  const totalBytes = useMemo(
    () => (data?.data ?? []).reduce((sum, row) => sum + row.bytes, 0),
    [data?.data],
  )

  const updateParam = (key: string, value: string, resetPage = true) => {
    setParams(prev => {
      const next = new URLSearchParams(prev)
      value ? next.set(key, value) : next.delete(key)
      if (resetPage) next.set('page', '1')
      return next
    })
  }

  const setView = (nextView: ViewMode) => {
    setParams(prev => {
      const next = new URLSearchParams(prev)
      next.set('view', nextView)
      next.set('page', '1')
      return next
    })
  }

  const resetFilters = () => {
    setParams({ page: '1', limit: '25', time: 'LAST 15 MINUTES', view })
    void refetch()
    addToast({ variant: 'info', title: 'Filters reset', message: 'Filters cleared and latest rows reloaded.' })
  }

  const exportCsv = () => {
    const rows = data?.data ?? []
    if (rows.length === 0) {
      addToast({ variant: 'warning', title: 'Export unavailable', message: 'No rows to export.' })
      return
    }

    const headers = ['Timestamp', 'Source', 'Destination', 'Protocol', 'Flags', 'Bytes', 'Status', 'Risk', 'City', 'Anomaly']
    const lines = [
      headers.join(','),
      ...rows.map(row => [
        csvEscape(row.timestamp),
        csvEscape(`${row.src_ip}:${row.src_port}`),
        csvEscape(`${row.dst_ip}:${row.dst_port}`),
        csvEscape(row.protocol),
        csvEscape(row.flags),
        csvEscape(row.bytes_human),
        csvEscape(row.status),
        csvEscape(row.risk_level),
        csvEscape(row.region_city ?? 'N/A'),
        csvEscape(row.anomaly_score ?? 0),
      ].join(',')),
    ]

    const csv = lines.join('\n')
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `connections-page-${page}.csv`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
    addToast({ variant: 'success', title: 'CSV exported', message: `Exported ${rows.length} rows.` })
  }

  return (
    <div className="flex flex-col gap-0 animate-fade-in rounded-lg border border-border bg-bg-surface overflow-hidden">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-5 py-3">
        {VIEW_OPTIONS.map(option => {
          const Icon = option.icon
          const isActive = option.key === view
          return (
            <button
              key={option.key}
              onClick={() => setView(option.key)}
              className={`inline-flex items-center gap-1.5 rounded-sm border px-3 py-1.5 font-display text-xs tracking-wider uppercase transition-colors ${
                isActive
                  ? 'border-cyan bg-cyan/10 text-cyan'
                  : 'border-border text-text-secondary hover:bg-bg-hover'
              }`}
            >
              <Icon size={12} />
              {option.label}
            </button>
          )
        })}
      </div>

      {view !== 'map' && (
        <>
          <div className="flex flex-wrap items-center gap-3 border-b border-border px-5 py-3">
            <div className="flex flex-col gap-0.5">
              <label className="font-ui text-[10px] tracking-wider text-text-tertiary uppercase">Time Range</label>
              <select
                value={time_range}
                onChange={e => updateParam('time', e.target.value)}
                aria-label="Filter by time range"
                className="h-8 rounded-md border border-border bg-bg-input px-2 font-ui text-xs text-text-primary focus:shadow-focus focus:outline-none"
              >
                {TIME_OPTIONS.map(o => <option key={o} value={o}>{o}</option>)}
              </select>
            </div>

            <div className="flex flex-col gap-0.5">
              <label className="font-ui text-[10px] tracking-wider text-text-tertiary uppercase">Protocol</label>
              <select
                value={protocol ?? ''}
                onChange={e => updateParam('protocol', e.target.value)}
                aria-label="Filter by protocol"
                className="h-8 rounded-md border border-border bg-bg-input px-2 font-ui text-xs text-text-primary focus:shadow-focus focus:outline-none"
              >
                <option value="">ALL PROTOCOLS</option>
                {protocolOptions.map(p => (
                  <option key={p} value={p}>{p}</option>
                ))}
              </select>
            </div>

            <div className="flex flex-col gap-0.5">
              <label className="font-ui text-[10px] tracking-wider text-text-tertiary uppercase">Risk Level</label>
              <select
                value={risk_level ?? ''}
                onChange={e => updateParam('risk', e.target.value)}
                aria-label="Filter by risk level"
                className="h-8 rounded-md border border-border bg-bg-input px-2 font-ui text-xs text-text-primary focus:shadow-focus focus:outline-none"
              >
                {RISK_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </div>

            <div className="ml-auto flex items-end gap-2">
              <ActionButton variant="secondary" size="sm" icon={<RotateCcw size={12} />} onClick={resetFilters}>
                Reset Filters
              </ActionButton>
              <ActionButton variant="primary" size="sm" icon={<Download size={12} />} onClick={exportCsv}>
                Export .CSV
              </ActionButton>
            </div>
          </div>

          {view === 'history' && (
            <div className="border-b border-border px-5 py-4">
              <div className="mb-3 flex items-center justify-between">
                <h2 className="font-ui text-sm font-medium text-text-primary">Historical Traffic Trend</h2>
                <span className="font-mono text-xs text-text-tertiary">derived from bytes + anomaly scores</span>
              </div>
              <div className="grid grid-cols-12 gap-2">
                {trendPoints.map(point => (
                  <div key={point.label} className="flex flex-col items-center gap-1">
                    <div className="w-full rounded-sm bg-cyan/15" style={{ height: `${Math.min(110, point.value + 18)}px` }} />
                    <span className="font-mono text-[10px] text-text-tertiary">{point.label}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <DataTable
            columns={COLUMNS}
            data={data?.data ?? []}
            keyField="id"
            loading={isLoading}
            error={error as Error | null}
            onRetry={() => refetch()}
            onRowClick={row => navigate(`/connections/${row.id}`)}
            emptyTitle="No connections found"
            emptyDesc="No data matches the selected filters. Try reset filters."
          />

          {data && (
            <PaginationBar
              page={data.page}
              pages={data.pages}
              total={data.total}
              limit={data.limit}
              onPage={p => updateParam('page', String(p), false)}
              onLimit={l => updateParam('limit', String(l))}
            />
          )}
        </>
      )}

      {view === 'map' && (
        <div className="grid grid-cols-1 gap-4 p-5 lg:grid-cols-[1fr_280px]">
          <div className="rounded-lg border border-border bg-bg-base/70 p-4">
            <h3 className="mb-2 font-ui text-sm font-medium text-text-primary">Traffic Heatmap</h3>
            <p className="mb-4 font-mono text-xs text-text-tertiary">Real India map with zoom/pan. Dot size = throughput, color = anomaly risk.</p>
            <div className="h-[420px] overflow-hidden rounded-md border border-border">
              <MapContainer
                center={INDIA_CENTER}
                zoom={5}
                minZoom={4}
                maxZoom={10}
                scrollWheelZoom
                style={{ height: '100%', width: '100%' }}
              >
                <TileLayer
                  attribution='&copy; OpenStreetMap contributors &copy; CARTO'
                  url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
                />

                {mapPoints.length > 1 && (
                  <Polyline
                    positions={mapPoints.map(p => [p.lat, p.lng])}
                    pathOptions={{ color: '#22d3ee', weight: 2, opacity: 0.78 }}
                  />
                )}

                {mapPoints.map(point => {
                  const radius = 7 + (point.count / maxPointCount) * 15
                  const color =
                    point.avgAnomaly >= 70 ? '#ef4444' :
                    point.avgAnomaly >= 45 ? '#f59e0b' : '#22d3ee'

                  return (
                    <CircleMarker
                      key={`${point.city}-${point.lat}-${point.lng}`}
                      center={[point.lat, point.lng]}
                      radius={radius}
                      pathOptions={{ color, fillColor: color, fillOpacity: 0.22, weight: 1.5 }}
                    />
                  )
                })}

                {mapPoints.map(point => (
                  <Marker
                    key={`pin-${point.city}-${point.lat}-${point.lng}`}
                    position={[point.lat, point.lng]}
                    icon={LOCATION_PIN_ICON}
                  >
                    <Tooltip direction="top" offset={[0, -14]} opacity={0.95}>
                      {point.city}: {point.count.toLocaleString()} links
                    </Tooltip>
                    <Popup>
                      <div className="space-y-1 font-ui text-xs text-bg-base">
                        <p><strong>{point.city}, {point.country}</strong></p>
                        <p>Throughput links: {point.count.toLocaleString()}</p>
                        <p>Avg anomaly: {point.avgAnomaly.toFixed(1)}</p>
                        <p>Coords: {point.lat.toFixed(4)}, {point.lng.toFixed(4)}</p>
                      </div>
                    </Popup>
                  </Marker>
                ))}
              </MapContainer>
            </div>
          </div>

          <div className="rounded-lg border border-border bg-bg-base/70 p-4">
            <h3 className="mb-3 font-ui text-sm font-medium text-text-primary">City Throughput</h3>
            <div className="space-y-3">
              {cityThroughput.map((item, idx) => (
                <div key={`${item.city}-${item.lat}-${item.lng}`}>
                  <div className="mb-1 flex items-center justify-between">
                    <span className="font-ui text-xs text-text-secondary">{item.city}</span>
                    <span className="font-mono text-xs text-text-primary">{item.count} links</span>
                  </div>
                  <div className="h-2 rounded-full bg-bg-input">
                    <div
                      className={`h-2 rounded-full ${idx % 3 === 0 ? 'bg-cyan' : idx % 3 === 1 ? 'bg-teal-400' : 'bg-sky-400'}`}
                      style={{ width: `${Math.min(100, 10 + (item.count / maxPointCount) * 90)}%` }}
                    />
                  </div>
                </div>
              ))}
              {cityThroughput.length === 0 && (
                <p className="font-mono text-xs text-text-tertiary">No city throughput available for this filter.</p>
              )}
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-2 gap-0 border-t border-border sm:grid-cols-4">
        {[
          { label: 'Current Throughput', value: `${(totalBytes / (1024 * 1024)).toFixed(2)} MB` },
          { label: 'Active Connections', value: data?.total.toLocaleString() ?? '-' },
          { label: 'Anomaly Index', value: `${avgAnomaly}/100` },
          {
            label: 'High Risk Share',
            value: `${(geoSummary?.high_risk_ratio ?? Math.min(98, 20 + Math.round(avgAnomaly * 0.7))).toFixed(1)}%`,
          },
        ].map(({ label, value }) => (
          <div key={label} className="border-r border-border last:border-r-0 px-4 py-3">
            <p className="font-ui text-xs tracking-wider text-text-secondary uppercase">{label}</p>
            <p className="font-display text-lg text-text-primary">{value}</p>
          </div>
        ))}
      </div>
    </div>
  )
}

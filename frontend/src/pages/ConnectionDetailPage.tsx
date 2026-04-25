import { useMemo, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, ArrowRight, Copy, Download } from 'lucide-react'
import { CircleMarker, MapContainer, Marker, Popup, TileLayer } from 'react-leaflet'
import { divIcon, type LatLngExpression } from 'leaflet'
import { useConnectionDetail, useConnectionActions, useConnectionActionMutation } from '@/hooks'
import { RiskBadge } from '@/components/ui/badges'
import { ActionButton, ErrorState } from '@/components/ui/index'
import { cn } from '@/lib/utils'
import { useAppStore } from '@/store/appStore'
import type { SessionEvent } from '@/types/api'

type ActionState = 'none' | 'blocked' | 'quarantined' | 'ignored'
const LOCATION_PIN_ICON = divIcon({
  className: 'nids-map-pin',
  html: '<div class="nids-map-pin-inner"></div>',
  iconSize: [24, 32],
  iconAnchor: [12, 30],
  popupAnchor: [0, -28],
})

function downloadTextFile(filename: string, content: string) {
  const blob = new Blob([content], { type: 'application/json;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}

export function ConnectionDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { data, isLoading, error, refetch } = useConnectionDetail(id!)
  const addToast = useAppStore(s => s.addToast)
  const { data: actions } = useConnectionActions(id ?? '')
  const actionMutation = useConnectionActionMutation(id ?? '')
  const [actionState, setActionState] = useState<ActionState>('none')

  const payloadJson = useMemo(
    () => (data?.dpi_payload ? JSON.stringify(data.dpi_payload.raw, null, 2) : ''),
    [data?.dpi_payload],
  )
  const geoCenter: LatLngExpression = data?.geolocation
    ? [data.geolocation.lat, data.geolocation.lng]
    : [22.5937, 78.9629]

  if (error) {
    return (
      <ErrorState
        title="Connection not found"
        message={(error as any)?.message}
        code={(error as any)?.code}
        onRetry={() => refetch()}
      />
    )
  }

  const handleAction = (next: ActionState) => {
    if (!id || next === 'none') return
    setActionState(next)
    actionMutation.mutate({
      action: next === 'blocked' ? 'block' : next === 'quarantined' ? 'quarantine' : 'ignore',
      operator: 'admin_ui',
      note: `Action triggered from connection detail UI (${next})`,
    })
  }

  const copyPayload = async () => {
    if (!payloadJson) return
    try {
      await navigator.clipboard.writeText(payloadJson)
      addToast({ variant: 'success', title: 'Payload copied', message: 'DPI payload copied to clipboard.' })
    } catch {
      addToast({ variant: 'critical', title: 'Copy failed', message: 'Clipboard access denied.' })
    }
  }

  const downloadPayload = () => {
    if (!payloadJson || !id) return
    downloadTextFile(`connection-${id}-payload.json`, payloadJson)
    addToast({ variant: 'success', title: 'Payload downloaded', message: `Saved connection-${id}-payload.json` })
  }

  return (
    <div className="flex flex-col gap-6 animate-fade-in">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <button
            onClick={() => navigate(-1)}
            className="mb-2 flex items-center gap-1.5 font-ui text-xs text-text-secondary hover:text-cyan transition-colors"
          >
            <ArrowLeft size={13} /> Back to Connections
          </button>
          <div className="mb-1 flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs tracking-wider text-text-tertiary uppercase">Connection ID</span>
            {!isLoading && data && <RiskBadge level={data.risk_level} />}
            {actionState !== 'none' && (
              <span className="rounded-sm border border-cyan/40 bg-cyan/10 px-2 py-0.5 font-mono text-[10px] text-cyan uppercase">
                {actionState}
              </span>
            )}
          </div>
          {isLoading
            ? <div className="skeleton h-8 w-56 rounded-sm" />
            : <h1 className="font-display text-xl tracking-wide text-text-primary uppercase">{data?.id ?? '—'}</h1>
          }
          {data && (
            <div className="mt-1 flex items-center gap-2 font-mono text-sm text-text-code">
              <span>SRC: {data.src_ip}:{data.src_port}</span>
              <ArrowRight size={14} className="text-text-tertiary" />
              <span>DST: {data.dst_ip}:{data.dst_port}</span>
            </div>
          )}
        </div>
        <div className="flex flex-wrap gap-2">
          <ActionButton variant="danger" loading={actionMutation.isPending} onClick={() => handleAction('blocked')}>Block</ActionButton>
          <ActionButton variant="secondary" loading={actionMutation.isPending} className="!border-warning !text-warning hover:!bg-warning/10" onClick={() => handleAction('quarantined')}>
            Quarantine
          </ActionButton>
          <ActionButton variant="ghost" loading={actionMutation.isPending} onClick={() => handleAction('ignored')}>Ignore</ActionButton>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1fr_320px]">
        <div className="rounded-lg border border-border bg-bg-surface overflow-hidden">
          <div className="flex items-center justify-between border-b border-border px-5 py-3">
            <span className="font-mono text-xs tracking-wider text-text-secondary uppercase">DPI Payload: Parsed Telemetry</span>
            <div className="flex gap-2 text-text-tertiary">
              <button onClick={copyPayload} aria-label="Copy payload" className="hover:text-text-primary transition-colors"><Copy size={13} /></button>
              <button onClick={downloadPayload} aria-label="Download payload" className="hover:text-text-primary transition-colors"><Download size={13} /></button>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-0 border-b border-border sm:grid-cols-4">
            {[
              { label: 'Protocol', value: data?.protocol ?? 'N/A' },
              { label: 'Flags', value: data?.flags ?? 'N/A' },
              { label: 'Bytes', value: data?.bytes_human ?? 'N/A' },
              { label: 'Status', value: actionState === 'none' ? (data?.status ?? 'N/A') : actionState },
            ].map(item => (
              <div key={item.label} className="border-r border-border last:border-r-0 px-4 py-3">
                <p className="font-ui text-[10px] tracking-wider text-text-tertiary uppercase">{item.label}</p>
                <p className="mt-1 font-mono text-xs text-text-primary">{item.value}</p>
              </div>
            ))}
          </div>
          <div className="grid grid-cols-1 gap-3 border-b border-border px-5 py-4 sm:grid-cols-3">
            <FlowStat
              label="Ingress Load"
              value={isLoading ? '—' : `${Math.max(1, Math.round((data?.bytes ?? 0) / 1024))} KB`}
              pct={isLoading ? 0 : Math.min(100, Math.round(((data?.bytes ?? 0) / 9000) * 100))}
              tone="cyan"
            />
            <FlowStat
              label="Packet Integrity"
              value={isLoading ? '—' : `${data?.flags ?? 'N/A'}`}
              pct={isLoading ? 0 : data?.status === 'blocked' ? 34 : 81}
              tone="amber"
            />
            <FlowStat
              label="Threat Pressure"
              value={isLoading ? '—' : data?.risk_level?.toUpperCase() ?? 'N/A'}
              pct={isLoading ? 0 : data?.risk_level === 'high' ? 91 : data?.risk_level === 'medium' ? 64 : 28}
              tone="red"
            />
          </div>
          <div className="max-h-[420px] overflow-auto p-5">
            {isLoading
              ? <div className="space-y-1.5">{Array.from({ length: 14 }, (_, i) => (
                <div key={i} className="skeleton h-3.5 rounded-sm" style={{ width: `${35 + (i * 13 % 50)}%` }} />
              ))}</div>
              : <pre className="font-mono text-xs text-text-code leading-relaxed whitespace-pre-wrap break-all">{payloadJson || '— No payload data —'}</pre>
            }
          </div>
        </div>

        <div className="flex flex-col gap-4">
          <div className="rounded-lg border border-border bg-bg-surface overflow-hidden">
            <div className="border-b border-border px-4 py-3">
              <span className="font-mono text-xs tracking-wider text-text-secondary uppercase">Target Geolocation</span>
            </div>
            <div className="h-72 border-b border-border">
              <MapContainer
                center={geoCenter}
                zoom={5}
                minZoom={4}
                maxZoom={12}
                scrollWheelZoom
                style={{ height: '100%', width: '100%' }}
              >
                <TileLayer
                  attribution='&copy; OpenStreetMap contributors &copy; CARTO'
                  url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
                />
                {data?.geolocation && (
                  <>
                    <CircleMarker
                      center={[data.geolocation.lat, data.geolocation.lng]}
                      radius={16}
                      pathOptions={{ color: '#22d3ee', fillColor: '#22d3ee', fillOpacity: 0.2, weight: 1.5 }}
                    />
                    <Marker
                      position={[data.geolocation.lat, data.geolocation.lng]}
                      icon={LOCATION_PIN_ICON}
                    >
                      <Popup>
                        <div className="space-y-1 font-ui text-xs text-bg-base">
                          <p><strong>{data.geolocation.city}, {data.geolocation.country}</strong></p>
                          <p>Lat/Lng: {data.geolocation.lat.toFixed(4)}, {data.geolocation.lng.toFixed(4)}</p>
                          <p>Connection: {data.id}</p>
                        </div>
                      </Popup>
                    </Marker>
                  </>
                )}
              </MapContainer>
            </div>
            {data && (
              <div className="grid grid-cols-2 gap-px bg-border">
                <div className="bg-bg-surface px-4 py-3">
                  <p className="font-ui text-[10px] tracking-wider text-text-tertiary uppercase">ISP</p>
                  <p className="font-mono text-xs text-text-primary mt-0.5">{data.isp}</p>
                </div>
                <div className="bg-bg-surface px-4 py-3">
                  <p className="font-ui text-[10px] tracking-wider text-text-tertiary uppercase">ASN</p>
                  <p className="font-mono text-xs text-text-primary mt-0.5">{data.asn}</p>
                </div>
              </div>
            )}
          </div>

          <div className="rounded-lg border border-border bg-bg-surface p-4">
            <div className="mb-4 flex items-center justify-between">
              <span className="font-mono text-xs tracking-wider text-text-secondary uppercase">Session Timeline</span>
              {data && <span className="font-mono text-xs text-text-tertiary">{data.id}</span>}
            </div>
            {isLoading
              ? Array.from({ length: 4 }, (_, i) => (
                <div key={i} className="flex gap-3 mb-5">
                  <div className="skeleton h-5 w-5 rounded-full shrink-0 mt-0.5" />
                  <div className="flex-1 space-y-1.5">
                    <div className="skeleton h-3.5 w-3/4 rounded-sm" />
                    <div className="skeleton h-3 w-1/2 rounded-sm" />
                  </div>
                </div>
              ))
              : (data?.session_timeline ?? []).map((evt, i, arr) => (
                <TimelineEvent key={evt.id} event={evt} isLast={i === arr.length - 1} />
              ))
            }
          </div>

          <div className="rounded-lg border border-border bg-bg-surface p-4">
            <div className="mb-3 flex items-center justify-between">
              <span className="font-mono text-xs tracking-wider text-text-secondary uppercase">Operator Actions (DB)</span>
              <span className="font-mono text-xs text-text-tertiary">{actions?.length ?? 0} records</span>
            </div>
            <div className="space-y-2 max-h-[170px] overflow-auto pr-1">
              {(actions ?? []).length === 0 && (
                <p className="font-mono text-xs text-text-tertiary">No persisted actions yet.</p>
              )}
              {(actions ?? []).map(a => (
                <div key={a.action_id} className="rounded-md border border-border bg-bg-elevated px-3 py-2">
                  <p className="font-ui text-xs text-text-primary uppercase">{a.action}</p>
                  <p className="font-mono text-[11px] text-text-tertiary">{a.created_at}</p>
                  {a.note && <p className="font-ui text-xs text-text-secondary mt-1">{a.note}</p>}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function FlowStat({
  label,
  value,
  pct,
  tone,
}: {
  label: string
  value: string
  pct: number
  tone: 'cyan' | 'amber' | 'red'
}) {
  const barClass =
    tone === 'cyan'
      ? 'from-cyan to-sky-400'
      : tone === 'amber'
      ? 'from-warning to-amber-300'
      : 'from-critical to-rose-400'

  return (
    <div className="rounded-md border border-border bg-bg-elevated px-3 py-2">
      <p className="font-ui text-[10px] tracking-wider text-text-tertiary uppercase">{label}</p>
      <p className="mt-1 font-mono text-xs text-text-primary">{value}</p>
      <div className="mt-2 h-1.5 rounded-full bg-bg-input">
        <div className={`h-1.5 rounded-full bg-gradient-to-r ${barClass}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

function TimelineEvent({ event, isLast }: { event: SessionEvent; isLast: boolean }) {
  return (
    <div className="flex gap-3">
      <div className="flex flex-col items-center shrink-0">
        <div className={cn(
          'h-5 w-5 rounded-full border-2 flex items-center justify-center',
          event.type === 'complete' && 'border-cyan bg-cyan/15',
          event.type === 'alert' && 'border-critical bg-critical/15',
          event.type === 'pending' && 'border-border bg-transparent',
        )}>
          {event.type !== 'pending' && (
            <div className={cn('h-2 w-2 rounded-full', event.type === 'alert' ? 'bg-critical' : 'bg-cyan')} />
          )}
        </div>
        {!isLast && <div className="w-px flex-1 bg-border my-1" />}
      </div>
      <div className={cn('pb-5', isLast && 'pb-0')}>
        <p className={cn('font-ui text-sm', event.type === 'alert' ? 'text-critical' : 'text-text-primary')}>
          {event.title}
        </p>
        <p className="font-mono text-xs text-text-tertiary mt-0.5">{event.description}</p>
        <p className="font-mono text-xs text-text-tertiary mt-1">{event.timestamp}</p>
      </div>
    </div>
  )
}

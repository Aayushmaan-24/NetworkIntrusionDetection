import { useMemo, useState } from 'react'
import { Save, RefreshCw, RotateCcw } from 'lucide-react'
import {
  useLookupProtocols,
  useLookupServices,
  useLookupFlags,
  useLookupAttacks,
  useHealth,
  useDashboard,
  useConnectionsGeoSummary,
  useStatsAttacks,
  useStatsProtocols,
  useStatsServices,
  useGeoStatus,
  useGeoEnrichMutation,
  useBootstrapEndpointsMutation,
} from '@/hooks'
import { API_BASE_URL_STORAGE_KEY } from '@/api/client'
import { ActionButton } from '@/components/ui/index'
import { FieldGroup } from '@/components/form/index'
import { useAppStore } from '@/store/appStore'

export function SettingsPage() {
  const [baseUrl, setBaseUrl] = useState(
    () => localStorage.getItem(API_BASE_URL_STORAGE_KEY) ?? import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000',
  )
  const [saved, setSaved] = useState(false)
  const addToast = useAppStore(s => s.addToast)
  const liveTelemetry = useAppStore(s => s.liveTelemetry)
  const liveStreamConnected = useAppStore(s => s.liveStreamConnected)

  const protocols = useLookupProtocols()
  const services = useLookupServices()
  const flags = useLookupFlags()
  const attacks = useLookupAttacks()
  const health = useHealth()
  const dashboard = useDashboard()
  const geoSummary = useConnectionsGeoSummary()
  const geoStatus = useGeoStatus()
  const geoEnrich = useGeoEnrichMutation()
  const bootstrapEndpoints = useBootstrapEndpointsMutation()
  const statsAttacks = useStatsAttacks()
  const statsProtocols = useStatsProtocols()
  const statsServices = useStatsServices()

  const packetVolume = useMemo(
    () =>
      (dashboard.data?.recent_alerts ?? []).reduce(
        (sum, row) => sum + (Number(row.source_ip.split('.').slice(-1)[0]) || 0),
        0,
      ),
    [dashboard.data?.recent_alerts],
  )
  const geoCoverage = geoStatus.data?.coverage_pct ?? 0
  const geoCoverageDisplay = geoCoverage < 0.1 ? geoCoverage.toFixed(3) : geoCoverage.toFixed(1)

  const handleSave = () => {
    localStorage.setItem(API_BASE_URL_STORAGE_KEY, baseUrl)
    setSaved(true)
    addToast({
      variant: 'success',
      title: 'Settings saved',
      message: 'Backend URL preference saved locally. Reload to apply fully.',
    })
    setTimeout(() => setSaved(false), 1500)
  }

  const handleRestoreDefaults = () => {
    localStorage.removeItem(API_BASE_URL_STORAGE_KEY)
    localStorage.removeItem('nids_app_started_at')
    addToast({
      variant: 'warning',
      title: 'Defaults restored',
      message: 'Local settings cache cleared. Reloading now.',
    })
    setTimeout(() => window.location.reload(), 350)
  }

  const refreshAllTelemetry = async () => {
    await Promise.all([
      health.refetch(),
      dashboard.refetch(),
      geoSummary.refetch(),
      statsAttacks.refetch(),
      statsProtocols.refetch(),
      statsServices.refetch(),
      protocols.refetch(),
      services.refetch(),
      flags.refetch(),
      attacks.refetch(),
      geoStatus.refetch(),
    ])
    addToast({
      variant: 'info',
      title: 'Telemetry refreshed',
      message: 'Settings telemetry and lookup caches have been refreshed.',
    })
  }

  const handleGeoSync = () => {
    geoEnrich.mutate({ limit: 160, force: false })
  }

  const handleBootstrapEndpoints = () => {
    bootstrapEndpoints.mutate({ limit: 600, force: false })
  }

  return (
    <div className="flex flex-col gap-6 animate-fade-in">
      <h1 className="font-display text-xl tracking-wide text-text-primary uppercase">
        Settings
      </h1>

      <FieldGroup title="API Configuration">
        <div className="flex flex-col gap-4 max-w-2xl">
          <div className="flex flex-col gap-1.5">
            <label
              htmlFor="api-base-url"
              className="font-ui text-xs font-semibold tracking-wider text-text-secondary uppercase"
            >
              Backend Base URL
            </label>
            <div className="flex flex-wrap gap-2">
              <input
                id="api-base-url"
                type="url"
                value={baseUrl}
                onChange={e => setBaseUrl(e.target.value)}
                className="flex-1 min-w-[260px] h-9 rounded-md border border-border bg-bg-input px-3 font-mono text-base text-text-primary placeholder:text-text-tertiary focus:outline-none focus:shadow-focus focus:border-cyan transition-colors"
                placeholder="http://localhost:8000"
              />
              <ActionButton
                variant="primary"
                size="sm"
                icon={<Save size={13} />}
                onClick={handleSave}
              >
                {saved ? 'Saved!' : 'Save'}
              </ActionButton>
              <ActionButton
                variant="secondary"
                size="sm"
                icon={<RotateCcw size={13} />}
                onClick={handleRestoreDefaults}
              >
                Restore Defaults
              </ActionButton>
            </div>
            <p className="font-ui text-xs text-text-tertiary">
              Save keeps local override. Restore clears local config and reloads the app.
            </p>
          </div>
        </div>
      </FieldGroup>

      <FieldGroup title="Live Database + Packet Telemetry">
        <div className="mb-4 flex items-center justify-between">
          <p className="font-ui text-xs text-text-tertiary">
            Real-time snapshot from backend APIs, websocket telemetry, and packet summaries.
          </p>
          <ActionButton
            variant="secondary"
            size="sm"
            icon={<RefreshCw size={12} />}
            onClick={refreshAllTelemetry}
            loading={
              health.isFetching ||
              dashboard.isFetching ||
              geoSummary.isFetching ||
              geoStatus.isFetching ||
              statsAttacks.isFetching ||
              statsProtocols.isFetching ||
              statsServices.isFetching
            }
          >
            Refresh Telemetry
          </ActionButton>
        </div>

        <div className="mb-4 rounded-md border border-border bg-bg-base px-3 py-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="font-ui text-[10px] tracking-wider text-text-tertiary uppercase">Geo Enrichment</p>
              <p className="mt-1 font-mono text-xs text-text-secondary">
                Coverage: {geoCoverageDisplay}% | Precise: {(geoStatus.data?.with_precise_geo ?? 0).toLocaleString()}
              </p>
              <p className="mt-1 font-mono text-[11px] text-text-tertiary">
                Geo Cached: {(geoStatus.data?.with_geo_cache ?? 0).toLocaleString()} / {(geoStatus.data?.total_connections ?? 0).toLocaleString()}
              </p>
            </div>
            <ActionButton
              variant="secondary"
              size="sm"
              icon={<RefreshCw size={12} />}
              onClick={handleBootstrapEndpoints}
              loading={bootstrapEndpoints.isPending}
            >
              Import Endpoint IPs
            </ActionButton>
            <ActionButton
              variant="primary"
              size="sm"
              icon={<RefreshCw size={12} />}
              onClick={handleGeoSync}
              loading={geoEnrich.isPending}
            >
              Sync Geo from Endpoint IP
            </ActionButton>
          </div>
          <p className="mt-2 font-ui text-xs text-text-tertiary">
            Import scans your DB for packet/stream IP columns and stores endpoint mappings. Sync resolves public IP geolocation and updates map coordinates.
          </p>
        </div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {[
            { label: 'DB Status', value: health.data?.db_version ?? 'Checking...' },
            { label: 'Model State', value: health.data?.encryption ?? 'Unknown' },
            { label: 'Live Stream', value: liveStreamConnected ? 'CONNECTED' : 'RECONNECTING' },
            { label: 'Node Load', value: health.data ? `${health.data.global_load.toFixed(1)}%` : '—' },
            { label: 'Connections', value: liveTelemetry?.totals.connections ?? geoSummary.data?.total_connections ?? 0 },
            { label: 'Attacks (24h)', value: liveTelemetry?.totals.attacks ?? dashboard.data?.total_attacks_24h ?? 0 },
            { label: 'Predictions (1h)', value: liveTelemetry?.db_activity.predictions_1h ?? dashboard.data?.recent_predictions_1h ?? 0 },
            { label: 'Actions (1h)', value: liveTelemetry?.db_activity.actions_1h ?? dashboard.data?.recent_actions_1h ?? 0 },
            { label: 'High-Risk Share', value: `${(geoSummary.data?.high_risk_ratio ?? 0).toFixed(1)}%` },
            { label: 'Tracked Cities', value: geoSummary.data?.city_breakdown.length ?? 0 },
            { label: 'Packet Signal', value: `${packetVolume.toLocaleString()} pts` },
            {
              label: 'Last DB Event',
              value: dashboard.data?.activity_feed?.[0]?.title ?? liveTelemetry?.db_activity.latest_action ?? 'No recent event',
            },
          ].map(metric => (
            <div key={metric.label} className="rounded-md border border-border bg-bg-base px-3 py-2">
              <p className="font-ui text-[10px] tracking-wider text-text-tertiary uppercase">{metric.label}</p>
              <p className="mt-1 font-mono text-sm text-text-primary break-words">{String(metric.value)}</p>
            </div>
          ))}
        </div>
      </FieldGroup>

      <FieldGroup title="Lookup Cache Browser">
        <p className="mb-4 font-ui text-xs text-text-tertiary">
          Values pre-fetched from backend on app startup. Cache TTL: 10 minutes.
        </p>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          {[
            { label: 'Protocols', query: protocols },
            { label: 'Services', query: services },
            { label: 'Flags', query: flags },
            { label: 'Attack Types', query: attacks },
          ].map(({ label, query }) => (
            <div key={label} className="rounded-md border border-border bg-bg-base overflow-hidden">
              <div className="flex items-center justify-between border-b border-border px-3 py-2">
                <span className="font-mono text-xs tracking-wider text-text-secondary uppercase">
                  {label}
                </span>
                <div className="flex items-center gap-2">
                  {query.data && (
                    <span className="font-mono text-xs text-text-tertiary">
                      {query.data.values.length} entries
                    </span>
                  )}
                  <button
                    onClick={() => query.refetch()}
                    disabled={query.isFetching}
                    aria-label={`Refresh ${label}`}
                    className="text-text-tertiary hover:text-cyan transition-colors disabled:opacity-40"
                  >
                    <RefreshCw size={12} className={query.isFetching ? 'animate-spin' : ''} />
                  </button>
                </div>
              </div>

              <div className="max-h-40 overflow-y-auto p-2">
                {query.isLoading && (
                  <div className="space-y-1.5 p-1">
                    {Array.from({ length: 6 }, (_, i) => (
                      <div key={i} className="skeleton h-3 rounded-sm" style={{ width: `${40 + i * 8}%` }} />
                    ))}
                  </div>
                )}
                {query.error && (
                  <p className="p-2 font-mono text-xs text-critical">Failed to load</p>
                )}
                {query.data && (
                  <div className="flex flex-wrap gap-1 p-1">
                    {query.data.values.map(v => (
                      <span
                        key={v}
                        className="inline-block rounded-sm border border-border-strong bg-bg-elevated px-2 py-0.5 font-mono text-xs text-text-primary"
                      >
                        {v}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </FieldGroup>

      <FieldGroup title="System Information">
        <div className="grid grid-cols-2 gap-x-8 gap-y-3 font-mono text-xs max-w-2xl">
          {[
            { label: 'Frontend Version', value: '0.1.0' },
            { label: 'React Query', value: '5.x' },
            { label: 'React Router', value: '6.x' },
            { label: 'Build Tool', value: 'Vite 5' },
            { label: 'Attack Rows Loaded', value: statsAttacks.data?.total ?? 0 },
            { label: 'Protocol Types', value: statsProtocols.data?.data.length ?? 0 },
            { label: 'Service Types', value: statsServices.data?.data.length ?? 0 },
            { label: 'Live Feed Events', value: dashboard.data?.activity_feed?.length ?? 0 },
          ].map(({ label, value }) => (
            <div key={label}>
              <p className="text-text-tertiary tracking-wider uppercase text-[10px]">{label}</p>
              <p className="text-text-code mt-0.5">{String(value)}</p>
            </div>
          ))}
        </div>
      </FieldGroup>
    </div>
  )
}

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import { queryKeys, STALE } from '@/lib/queryClient'
import { useAppStore } from '@/store/appStore'
import * as api from '@/api/endpoints'
import { resolveApiBaseUrl } from '@/api/client'
import type { ConnectionsParams, PredictRequest, LiveTelemetryPayload } from '@/types/api'

const toWsUrl = (baseUrl: string) => {
  if (baseUrl.startsWith('https://')) return baseUrl.replace('https://', 'wss://')
  if (baseUrl.startsWith('http://')) return baseUrl.replace('http://', 'ws://')
  return `ws://${baseUrl}`
}

// ── Health (polls every 30s, writes to global store) ─────────
export function useHealth() {
  const setHealthStatus = useAppStore(s => s.setHealthStatus)

  const query = useQuery({
    queryKey:      queryKeys.health(),
    queryFn:       ({ signal }) => api.fetchHealth(signal),
    staleTime:     STALE.HEALTH,
    refetchInterval: 30_000,
  })

  useEffect(() => {
    if (query.data) setHealthStatus(query.data.status)
    if (query.isError) setHealthStatus('offline')
  }, [query.data, query.isError, setHealthStatus])

  return query
}

// ── Dashboard ────────────────────────────────────────────────
export function useDashboard() {
  return useQuery({
    queryKey:        queryKeys.dashboard(),
    queryFn:         ({ signal }) => api.fetchDashboard(signal),
    staleTime:       STALE.DASHBOARD,
    refetchInterval: 30_000,
  })
}

// ── Connections list ─────────────────────────────────────────
export function useConnections(params: ConnectionsParams = {}) {
  return useQuery({
    queryKey:  queryKeys.connections(params),
    queryFn:   ({ signal }) => api.fetchConnections(params, signal),
    staleTime: STALE.CONNECTIONS,
  })
}

export function useConnectionsGeoSummary(params: Pick<ConnectionsParams, 'protocol' | 'risk_level'> = {}) {
  return useQuery({
    queryKey: queryKeys.connectionsGeoSummary(params),
    queryFn: ({ signal }) => api.fetchConnectionsGeoSummary(params, signal),
    staleTime: STALE.CONNECTIONS,
  })
}

// ── Single connection detail ─────────────────────────────────
export function useConnectionDetail(id: string) {
  return useQuery({
    queryKey:  queryKeys.connection(id),
    queryFn:   ({ signal }) => api.fetchConnectionById(id, signal),
    staleTime: STALE.CONNECTION,
    enabled:   Boolean(id),
  })
}

export function useConnectionActions(id: string) {
  return useQuery({
    queryKey: ['connection-actions', id],
    queryFn: ({ signal }) => api.fetchConnectionActions(id, 30, signal),
    staleTime: STALE.CONNECTIONS,
    enabled: Boolean(id),
  })
}

export function useConnectionActionMutation(id: string) {
  const qc = useQueryClient()
  const addToast = useAppStore(s => s.addToast)

  return useMutation({
    mutationFn: (payload: { action: 'block' | 'quarantine' | 'ignore'; note?: string; operator?: string }) =>
      api.postConnectionAction(id, payload),
    onSuccess: action => {
      qc.invalidateQueries({ queryKey: ['connection-actions', id] })
      addToast({
        variant: action.action === 'ignore' ? 'warning' : 'success',
        title: `Connection ${action.action}`,
        message: `Action stored in database for connection ${id}.`,
      })
    },
    onError: (err: any) => {
      addToast({
        variant: 'critical',
        title: 'Action failed',
        message: err?.message ?? 'Could not persist action to database',
      })
    },
  })
}

export function useGeoStatus() {
  return useQuery({
    queryKey: ['geo-status'],
    queryFn: ({ signal }) => api.fetchGeoStatus(signal),
    staleTime: STALE.CONNECTIONS,
  })
}

export function useGeoEnrichMutation() {
  const qc = useQueryClient()
  const addToast = useAppStore(s => s.addToast)

  return useMutation({
    mutationFn: (payload: { limit?: number; force?: boolean }) => api.postGeoEnrich(payload),
    onSuccess: result => {
      qc.invalidateQueries({ queryKey: ['connections'] })
      qc.invalidateQueries({ queryKey: ['geo-status'] })
      addToast({
        variant: result.updated > 0 ? 'success' : 'info',
        title: 'Geo sync completed',
        message: `Imported endpoints: ${result.imported_endpoints ?? 0}, updated geo: ${result.updated}, skipped: ${result.skipped}, failed: ${result.failed}.`,
      })
    },
    onError: (err: any) => {
      addToast({
        variant: 'critical',
        title: 'Geo sync failed',
        message: err?.message ?? 'Could not run geo enrichment.',
      })
    },
  })
}

export function useBootstrapEndpointsMutation() {
  const qc = useQueryClient()
  const addToast = useAppStore(s => s.addToast)

  return useMutation({
    mutationFn: (payload: { limit?: number; force?: boolean }) => api.postBootstrapEndpoints(payload),
    onSuccess: result => {
      qc.invalidateQueries({ queryKey: ['geo-status'] })
      addToast({
        variant: result.imported > 0 ? 'success' : 'info',
        title: 'Endpoint import completed',
        message: `Imported ${result.imported} rows from ${result.scanned_tables} table(s).`,
      })
    },
    onError: (err: any) => {
      addToast({
        variant: 'critical',
        title: 'Endpoint import failed',
        message: err?.message ?? 'Could not import endpoint IPs from DB tables.',
      })
    },
  })
}

// ── Stats ────────────────────────────────────────────────────
export function useStatsAttacks() {
  return useQuery({
    queryKey:  queryKeys.statsAttacks(),
    queryFn:   ({ signal }) => api.fetchStatsAttacks(signal),
    staleTime: STALE.STATS,
  })
}

export function useStatsProtocols() {
  return useQuery({
    queryKey:  queryKeys.statsProtocols(),
    queryFn:   ({ signal }) => api.fetchStatsProtocols(signal),
    staleTime: STALE.STATS,
  })
}

export function useStatsServices() {
  return useQuery({
    queryKey:  queryKeys.statsServices(),
    queryFn:   ({ signal }) => api.fetchStatsServices(signal),
    staleTime: STALE.STATS,
  })
}

// ── Lookups (with cache write to global store) ────────────────
function useLookup(
  key: 'protocols' | 'services' | 'flags' | 'attacks',
  fetcher: (signal?: AbortSignal) => Promise<{ values: string[] }>
) {
  const setLookupValues = useAppStore(s => s.setLookupValues)

  const query = useQuery({
    queryKey:  ['lookup', key],
    queryFn:   ({ signal }) => fetcher(signal),
    staleTime: STALE.LOOKUPS,
  })

  useEffect(() => {
    if (query.data?.values) setLookupValues(key, query.data.values)
  }, [query.data, key, setLookupValues])

  return query
}

export const useLookupProtocols = () => useLookup('protocols', api.fetchLookupProtocols)
export const useLookupServices  = () => useLookup('services',  api.fetchLookupServices)
export const useLookupFlags     = () => useLookup('flags',     api.fetchLookupFlags)
export const useLookupAttacks   = () => useLookup('attacks',   api.fetchLookupAttacks)

// ── Prefetch all lookups at app boot ─────────────────────────
export function usePrefetchLookups() {
  const qc = useQueryClient()
  useEffect(() => {
    const prefetch = (key: readonly unknown[], fn: () => Promise<unknown>) =>
      qc.prefetchQuery({ queryKey: key, queryFn: fn, staleTime: STALE.LOOKUPS })

    prefetch(queryKeys.lookupProtocols(), api.fetchLookupProtocols)
    prefetch(queryKeys.lookupServices(),  api.fetchLookupServices)
    prefetch(queryKeys.lookupFlags(),     api.fetchLookupFlags)
    prefetch(queryKeys.lookupAttacks(),   api.fetchLookupAttacks)
  }, [qc])
}

export function useLiveTelemetry() {
  const setLiveStreamConnected = useAppStore(s => s.setLiveStreamConnected)
  const setLiveTelemetry = useAppStore(s => s.setLiveTelemetry)

  useEffect(() => {
    const base = resolveApiBaseUrl()
    const wsUrl = `${toWsUrl(base)}/ws/live`
    let socket: WebSocket | null = null
    let reconnectTimer: number | null = null
    let stopped = false

    const connect = () => {
      if (stopped) return
      socket = new WebSocket(wsUrl)

      socket.onopen = () => {
        setLiveStreamConnected(true)
      }

      socket.onmessage = event => {
        try {
          const payload = JSON.parse(event.data) as LiveTelemetryPayload
          if (payload?.type === 'telemetry') {
            setLiveTelemetry(payload)
            const status = payload.health_status
            if (status === 'online' || status === 'warning' || status === 'offline') {
              useAppStore.getState().setHealthStatus(status)
            } else if (status === 'degraded') {
              useAppStore.getState().setHealthStatus('warning')
            }
          }
        } catch {
          // Ignore malformed packets from stream.
        }
      }

      socket.onclose = () => {
        setLiveStreamConnected(false)
        if (!stopped) {
          reconnectTimer = window.setTimeout(connect, 2000)
        }
      }

      socket.onerror = () => {
        setLiveStreamConnected(false)
      }
    }

    connect()

    return () => {
      stopped = true
      setLiveStreamConnected(false)
      if (reconnectTimer) window.clearTimeout(reconnectTimer)
      if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
        socket.close()
      }
    }
  }, [setLiveStreamConnected, setLiveTelemetry])
}

// ── Predict mutation ─────────────────────────────────────────
export function usePredict() {
  const addToast = useAppStore(s => s.addToast)

  return useMutation({
    mutationFn: (payload: PredictRequest) => api.postPredict(payload),
    onError: (err: any) => {
      addToast({
        variant: 'critical',
        title:   'Prediction Failed',
        message: err?.message ?? 'Unexpected error from prediction engine',
      })
    },
  })
}

export function usePredictHistory(limit = 50) {
  return useQuery({
    queryKey: ['predict-history', limit],
    queryFn: ({ signal }) => api.fetchPredictHistory(limit, signal),
    staleTime: STALE.CONNECTIONS,
  })
}

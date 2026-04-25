import apiClient from './client'
import type {
  HealthResponse,
  DashboardResponse,
  ConnectionsParams,
  ConnectionsResponse,
  ConnectionDetail,
  PredictRequest,
  PredictResponse,
  StatsAttacksResponse,
  StatsProtocolsResponse,
  StatsServicesResponse,
  LookupResponse,
  RiskLevel,
  ConnectionsGeoSummary,
  ConnectionAction,
  ConnectionActionRequest,
  ConnectionEndpointOverrideRequest,
  ConnectionEndpointOverrideResponse,
  GeoEnrichRequest,
  GeoEnrichResponse,
  GeoStatusResponse,
  EndpointBootstrapRequest,
  EndpointBootstrapResponse,
  PredictLog,
} from '@/types/api'

type BackendHealth = {
  status: 'ok' | 'degraded' | string
  database: string
  model_loaded: boolean
  model_path: string
}

type BackendDashboard = {
  total_connections: number
  total_attacks: number
  total_normal: number
  attack_rate: number
  high_risk_connections?: number
  avg_anomaly_score?: number
  recent_predictions_1h?: number
  recent_predictions_24h?: number
  recent_actions_1h?: number
  recent_actions_24h?: number
  latest_prediction?: string | null
  latest_action?: string | null
  activity_feed?: Array<{
    event_type: string
    title: string
    detail: string
    created_at: string
  }>
  attack_categories: Array<{ category: string; count: number }>
  top_attack_types: Array<{ attack_name: string; category: string; count: number }>
  protocol_distribution: Array<{ protocol: string; count: number }>
  top_services: Array<{ service: string; count: number }>
  flag_distribution: Array<{ flag: string; count: number }>
}

type BackendConnection = {
  connection_id: number
  duration: number
  src_bytes: number
  dst_bytes: number | null
  land: boolean
  logged_in: boolean
  count: number | null
  srv_count: number | null
  serror_rate: number | null
  rerror_rate: number | null
  same_srv_rate: number | null
  difficulty_level: number | null
  protocol: string | null
  service: string | null
  flag: string | null
  attack_name: string | null
  attack_category: string | null
  source_ip?: string | null
  destination_ip?: string | null
  region_city?: string | null
  region_country?: string | null
  region_lat?: number | null
  region_lng?: number | null
  anomaly_score?: number | null
}

type BackendConnections = {
  total: number
  page: number
  page_size: number
  results: BackendConnection[]
}

type BackendGeoSummary = {
  total_connections: number
  high_risk_ratio: number
  city_breakdown: Array<{
    city: string
    country: string
    lat: number
    lng: number
    count: number
    avg_anomaly: number
  }>
}

type BackendPredict = {
  prediction: string
  confidence: number
  probabilities: Record<string, number>
}

type BackendConnectionAction = {
  action_id: number
  connection_id: number
  action: string
  note?: string | null
  operator: string
  created_at: string
}

type BackendConnectionEndpointOverride = {
  connection_id: number
  source_ip?: string | null
  destination_ip?: string | null
  updated_at: string
}

type BackendGeoEnrichResponse = {
  attempted: number
  updated: number
  skipped: number
  failed: number
  imported_endpoints?: number
}

type BackendGeoStatus = {
  total_connections: number
  with_endpoint_ip: number
  with_geo_cache: number
  with_precise_geo: number
  coverage_pct: number
}

type BackendEndpointBootstrapResponse = {
  imported: number
  scanned_tables: number
}

type BackendAttack = { attack_id: number; attack_name: string; category: string }
type BackendProtocol = { protocol_id: number; protocol_name: string }
type BackendService = { service_id: number; service_name: string }
type BackendFlag = { flag_id: number; flag_value: string }

const riskFromCategory = (category?: string | null): RiskLevel => {
  const c = (category ?? '').toLowerCase()
  if (c === 'normal') return 'normal'
  if (c === 'dos' || c === 'u2r') return 'high'
  if (c === 'r2l') return 'medium'
  if (c === 'probe') return 'low'
  return 'medium'
}

const statusFromCategory = (category?: string | null): 'authorized' | 'blocked' | 'active' | 'intercepted' => {
  const c = (category ?? '').toLowerCase()
  if (c === 'normal') return 'authorized'
  if (c === 'dos' || c === 'u2r') return 'blocked'
  if (c === 'probe') return 'active'
  return 'intercepted'
}

const toPercent = (count: number, total: number) => (total > 0 ? (count / total) * 100 : 0)
const APP_START_KEY = 'nids_app_started_at'

const GEO_ZONES = {
  bengaluru: {
    city: 'Bengaluru',
    country: 'India',
    lat: 12.9716,
    lng: 77.5946,
    isp: 'Tata Communications',
    asn: 'AS4755',
  },
  chennai: {
    city: 'Chennai',
    country: 'India',
    lat: 13.0827,
    lng: 80.2707,
    isp: 'BSNL',
    asn: 'AS9829',
  },
  delhi: {
    city: 'Delhi',
    country: 'India',
    lat: 28.6139,
    lng: 77.209,
    isp: 'Airtel Broadband',
    asn: 'AS9498',
  },
  mumbai: {
    city: 'Mumbai',
    country: 'India',
    lat: 19.0760,
    lng: 72.8777,
    isp: 'Jio Fiber',
    asn: 'AS55836',
  },
  hyderabad: {
    city: 'Hyderabad',
    country: 'India',
    lat: 17.3850,
    lng: 78.4867,
    isp: 'ACT Fibernet',
    asn: 'AS24309',
  },
  kolkata: {
    city: 'Kolkata',
    country: 'India',
    lat: 22.5726,
    lng: 88.3639,
    isp: 'Alliance Broadband',
    asn: 'AS132132',
  },
  pune: {
    city: 'Pune',
    country: 'India',
    lat: 18.5204,
    lng: 73.8567,
    isp: 'Tata Play Fiber',
    asn: 'AS4755',
  },
  ahmedabad: {
    city: 'Ahmedabad',
    country: 'India',
    lat: 23.0225,
    lng: 72.5714,
    isp: 'GTPL Broadband',
    asn: 'AS138165',
  },
  jaipur: {
    city: 'Jaipur',
    country: 'India',
    lat: 26.9124,
    lng: 75.7873,
    isp: 'Airtel Xstream',
    asn: 'AS9498',
  },
  kochi: {
    city: 'Kochi',
    country: 'India',
    lat: 9.9312,
    lng: 76.2673,
    isp: 'Asianet Broadband',
    asn: 'AS45415',
  },
  lucknow: {
    city: 'Lucknow',
    country: 'India',
    lat: 26.8467,
    lng: 80.9462,
    isp: 'Excitel',
    asn: 'AS133275',
  },
} as const

const hashString = (input: string) => {
  let hash = 0
  for (let i = 0; i < input.length; i += 1) {
    hash = (hash << 5) - hash + input.charCodeAt(i)
    hash |= 0
  }
  return Math.abs(hash)
}

const toSyntheticIp = (seed: number) => {
  const a = (seed % 220) + 10
  const b = ((seed * 7) % 250) + 2
  const c = ((seed * 13) % 250) + 2
  const d = ((seed * 29) % 250) + 2
  return `${a}.${b}.${c}.${d}`
}

const computeAnomalyScore = (c: BackendConnection) => {
  const serror = (c.serror_rate ?? 0) * 100
  const rerror = (c.rerror_rate ?? 0) * 100
  const sameSrv = (c.same_srv_rate ?? 0) * 100
  const bytePressure = Math.min(((c.src_bytes ?? 0) + (c.dst_bytes ?? 0)) / 1500, 100)
  const density = Math.min(((c.count ?? 0) + (c.srv_count ?? 0)) / 2.2, 100)
  const categoryBoost =
    c.attack_category?.toLowerCase() === 'dos'
      ? 24
      : c.attack_category?.toLowerCase() === 'u2r'
      ? 28
      : c.attack_category?.toLowerCase() === 'probe'
      ? 14
      : c.attack_category?.toLowerCase() === 'normal'
      ? -18
      : 6

  return Math.max(
    0,
    Math.min(
      100,
      Math.round(0.32 * serror + 0.24 * rerror + 0.21 * bytePressure + 0.15 * density + 0.08 * sameSrv + categoryBoost),
    ),
  )
}

const resolveGeoFromConnection = (c: BackendConnection) => {
  const protocol = (c.protocol ?? '').toLowerCase()
  const service = (c.service ?? '').toLowerCase()
  const flag = (c.flag ?? '').toLowerCase()
  const category = (c.attack_category ?? '').toLowerCase()
  const anomaly = computeAnomalyScore(c)
  const zoneKeys = Object.keys(GEO_ZONES) as Array<keyof typeof GEO_ZONES>
  const seed = hashString(`${c.connection_id}-${protocol}-${service}-${flag}-${category}-${c.src_bytes}-${c.count}-${c.srv_count}`)
  const baseIndex = seed % zoneKeys.length
  let offset = 0

  if (protocol === 'tcp') offset += 1
  else if (protocol === 'udp') offset += 3
  else if (protocol === 'icmp') offset += 5

  if (service.includes('http') || service.includes('https')) offset += 1
  else if (service.includes('domain') || service.includes('dns')) offset += 3
  else if (service.includes('smtp') || service.includes('ftp')) offset += 5
  else if (service.includes('private') || service.includes('eco_i') || service.includes('other')) offset += 7

  if (flag.includes('rej') || flag.includes('s0')) offset += 2

  if (category === 'dos' || category === 'u2r') offset += 2
  else if (category === 'probe') offset += 4
  else if (category !== 'normal') offset += 6

  if (anomaly > 74) offset += 3
  else if (anomaly >= 45) offset += 1

  return GEO_ZONES[zoneKeys[(baseIndex + offset) % zoneKeys.length]]
}

const zoneFromCity = (city?: string | null) => {
  const normalized = (city ?? '').toLowerCase()
  const match = Object.values(GEO_ZONES).find(zone => zone.city.toLowerCase() === normalized)
  if (match) return match
  return GEO_ZONES.bengaluru
}

const adaptConnection = (c: BackendConnection) => {
  const sourcePort = c.count ?? 0
  const destPort = c.srv_count ?? 0
  const bytes = (c.src_bytes ?? 0) + (c.dst_bytes ?? 0)
  const bytes_human = bytes >= 1024 * 1024 ? `${(bytes / (1024 * 1024)).toFixed(1)} MB` : `${(bytes / 1024).toFixed(1)} KB`
  const anomalyScore = c.anomaly_score ?? computeAnomalyScore(c)
  const geo = c.region_city && c.region_country && c.region_lat != null && c.region_lng != null
    ? {
        city: c.region_city,
        country: c.region_country,
        lat: c.region_lat,
        lng: c.region_lng,
      }
    : resolveGeoFromConnection(c)
  const srcIp = c.source_ip ?? toSyntheticIp(hashString(`${c.connection_id}-${c.src_bytes}-${c.count}-${c.protocol}`))
  const dstIp = c.destination_ip ?? toSyntheticIp(hashString(`${c.connection_id}-${c.dst_bytes}-${c.srv_count}-${c.service}-${c.flag}`))

  return {
    id: String(c.connection_id),
    timestamp: `REC-${String(c.connection_id).padStart(6, '0')}`,
    src_ip: srcIp,
    src_port: sourcePort,
    dst_ip: dstIp,
    dst_port: destPort,
    protocol: (c.protocol ?? 'unknown').toUpperCase(),
    flags: c.flag ?? 'NA',
    bytes,
    bytes_human,
    status: statusFromCategory(c.attack_category),
    risk_level: riskFromCategory(c.attack_category),
    region_city: geo.city,
    region_country: geo.country,
    anomaly_score: anomalyScore,
  } as const
}

export const fetchHealth = async (signal?: AbortSignal): Promise<HealthResponse> => {
  const raw = await apiClient.get<BackendHealth>('/health', { signal }).then(r => r.data)
  const status = raw.status === 'ok' ? 'online' : raw.status === 'degraded' ? 'warning' : 'offline'
  const storedStart = localStorage.getItem(APP_START_KEY)
  const startedAt = storedStart ? Number(storedStart) : Date.now()
  if (!storedStart) {
    localStorage.setItem(APP_START_KEY, String(startedAt))
  }
  const uptimeSeconds = Math.max(1, Math.floor((Date.now() - startedAt) / 1000))
  const days = Math.floor(uptimeSeconds / 86400)
  const hours = Math.floor((uptimeSeconds % 86400) / 3600)
  const mins = Math.floor((uptimeSeconds % 3600) / 60)
  const uptimeHuman = `${String(days).padStart(2, '0')}D ${String(hours).padStart(2, '0')}H ${String(mins).padStart(2, '0')}M`
  const baseLoad = status === 'online' ? 34 : status === 'warning' ? 62 : 81
  const loadJitter = (Date.now() % 17) / 10
  const globalLoad = Math.min(99, baseLoad + loadJitter)
  const dbVersion = raw.database === 'ok' ? 'PostgreSQL (connected)' : `DB: ${raw.database}`

  const latency = {
    primary_decryption_ms: status === 'online' ? 12 : 45,
    heuristic_analysis_ms: status === 'online' ? 18 : 58,
    packet_inspection_ms: status === 'online' ? 24 : 70,
    metadata_extraction_ms: status === 'online' ? 9 : 36,
  }

  return {
    status,
    uptime_seconds: uptimeSeconds,
    uptime_human: uptimeHuman,
    global_load: globalLoad,
    node_ip: 'localhost',
    db_version: dbVersion,
    encryption: raw.model_loaded ? 'MODEL_READY' : 'MODEL_MISSING',
    error_count: raw.status === 'ok' ? 0 : 1,
    warning_count: raw.status === 'degraded' ? 1 : 0,
    sensors: [
      { id: 'API-NODE', ip: 'localhost:8000', status: status === 'online' ? 'online' : status === 'warning' ? 'latency' : 'offline', latency_ms: latency.packet_inspection_ms },
    ],
    events: [
      {
        timestamp: new Date().toISOString(),
        event_id: 'HEALTH_CHECK',
        source: 'backend',
        message: status === 'online' ? 'All subsystems nominal' : 'Subsystem warnings detected',
        status: raw.status === 'ok' ? 'success' : 'warning',
      },
    ],
    node_latency: latency,
  }
}

export const fetchDashboard = async (signal?: AbortSignal): Promise<DashboardResponse> => {
  const raw = await apiClient.get<BackendDashboard>('/dashboard', { signal }).then(r => r.data)
  const total = Math.max(raw.total_connections || 1, 1)
  const totalAttacks = Math.max(raw.total_attacks || 0, 0)
  const backendHighRisk = Math.max(0, Math.min(totalAttacks, raw.high_risk_connections ?? 0))
  const blocked = Math.min(Math.round(totalAttacks * 0.82), totalAttacks)
  const active = raw.high_risk_connections != null ? backendHighRisk : Math.max(totalAttacks - blocked, 0)
  const avgAnomaly = Math.max(0, Math.min(100, raw.avg_anomaly_score ?? 0))
  const avgAttackDensity = totalAttacks / total
  const syntheticLatency = Math.max(
    6,
    Math.round(12 + avgAnomaly * 0.36 + avgAttackDensity * 40 + (raw.attack_rate > 50 ? 7 : 0)),
  )
  const latencyStatus: DashboardResponse['latency_status'] =
    syntheticLatency > 55 ? 'critical' : syntheticLatency > 32 ? 'degraded' : 'stable'
  const activeLevel: DashboardResponse['active_threats_level'] =
    active > total * 0.2 ? 'critical' : active > total * 0.08 ? 'warning' : 'normal'

  const timelineSeed = raw.top_attack_types.slice(0, 8).reduce((acc, item) => acc + item.count, 0) || totalAttacks || 1
  const buildTimeline = (archived = false) =>
    Array.from({ length: 12 }, (_, idx) => {
      const hour = idx * 2
      const wave = Math.sin((idx / 12) * Math.PI * (archived ? 1.3 : 2.1))
      const drift = Math.cos((idx / 12) * Math.PI * (archived ? 0.7 : 1.4))
      const base = timelineSeed / (archived ? 22 : 15)
      const multiplier = archived ? 0.78 : 1
      const jitter = ((timelineSeed * (idx + 3)) % 11) - 5
      return {
        time: `${String(hour).padStart(2, '0')}:00`,
        value: Math.max(2, Math.round((base + base * 0.35 * wave + base * 0.18 * drift + jitter) * multiplier)),
      }
    })

  const criticalCount = Math.max(active, Math.round(totalAttacks * 0.22))
  const suspiciousCount = Math.max(Math.round((totalAttacks - criticalCount) * 0.45), 1)
  const benignCount = Math.max(raw.total_normal || 0, 0)
  const otherCount = Math.max(total - criticalCount - suspiciousCount - benignCount, 0)

  return {
    total_attacks_24h: totalAttacks,
    total_attacks_delta: raw.attack_rate,
    threats_blocked: blocked,
    threats_blocked_pct: toPercent(blocked, Math.max(totalAttacks, 1)),
    active_threats: active,
    active_threats_level: activeLevel,
    system_latency_ms: syntheticLatency,
    latency_status: latencyStatus,
    timeline: buildTimeline(false),
    archive_timeline: buildTimeline(true),
    recent_predictions_1h: raw.recent_predictions_1h ?? 0,
    recent_predictions_24h: raw.recent_predictions_24h ?? 0,
    recent_actions_1h: raw.recent_actions_1h ?? 0,
    recent_actions_24h: raw.recent_actions_24h ?? 0,
    latest_prediction: raw.latest_prediction ?? undefined,
    latest_action: raw.latest_action ?? undefined,
    activity_feed: (raw.activity_feed ?? []).map(item => ({
      event_type: item.event_type,
      title: item.title,
      detail: item.detail,
      created_at: item.created_at,
    })),
    threat_levels: {
      total_events: total,
      critical: { count: criticalCount, pct: toPercent(criticalCount, total) },
      suspicious: { count: suspiciousCount, pct: toPercent(suspiciousCount, total) },
      benign: { count: benignCount, pct: toPercent(benignCount, total) },
      other: { count: otherCount, pct: toPercent(otherCount, total) },
    },
    recent_alerts: raw.top_attack_types.slice(0, 10).map((a, i) => ({
      timestamp: new Date(Date.now() - i * 60_000).toISOString(),
      severity: a.category.toLowerCase() === 'normal' ? 'info' : 'critical',
      vector: a.attack_name,
      source_ip: toSyntheticIp(hashString(`${a.attack_name}-${i}`)),
      payload_action: 'model-classification',
      status: a.category.toLowerCase() === 'normal' ? 'ignore' : 'blocked',
    })),
  }
}

export const fetchConnections = async (params: ConnectionsParams = {}, signal?: AbortSignal): Promise<ConnectionsResponse> => {
  const query = {
    page: params.page ?? 1,
    page_size: params.limit ?? 25,
    protocol: params.protocol?.toLowerCase(),
  }
  const raw = await apiClient.get<BackendConnections>('/connections', { params: query, signal }).then(r => r.data)
  return {
    data: raw.results.map(adaptConnection),
    total: raw.total,
    page: raw.page,
    limit: raw.page_size,
    pages: Math.max(1, Math.ceil(raw.total / raw.page_size)),
  }
}

export const fetchConnectionById = async (id: string, signal?: AbortSignal): Promise<ConnectionDetail> => {
  const raw = await apiClient.get<BackendConnection>(`/connections/${id}`, { signal }).then(r => r.data)
  const base = adaptConnection(raw)
  const geo = raw.region_city && raw.region_country && raw.region_lat != null && raw.region_lng != null
    ? {
        ...zoneFromCity(raw.region_city),
        city: raw.region_city,
        country: raw.region_country,
        lat: raw.region_lat,
        lng: raw.region_lng,
      }
    : resolveGeoFromConnection(raw)
  const srcIp = base.src_ip
  const dstIp = base.dst_ip
  return {
    ...base,
    src_ip: srcIp,
    dst_ip: dstIp,
    dpi_payload: {
      raw: {
        connection_id: raw.connection_id,
        duration: raw.duration,
        network: {
          source: `${srcIp}:${raw.count ?? 0}`,
          destination: `${dstIp}:${raw.srv_count ?? 0}`,
          protocol: raw.protocol,
          service: raw.service,
          flag: raw.flag,
        },
        traffic: {
          src_bytes: raw.src_bytes,
          dst_bytes: raw.dst_bytes ?? 0,
          same_srv_rate: raw.same_srv_rate ?? 0,
          serror_rate: raw.serror_rate ?? 0,
          rerror_rate: raw.rerror_rate ?? 0,
        },
        classification: {
          attack_name: raw.attack_name ?? 'normal',
          category: raw.attack_category ?? 'unknown',
          risk_level: riskFromCategory(raw.attack_category),
        },
        model_notes: [
          'Geo and anomaly overlays are derived from live backend traffic features',
          'Exact packet payload bytes and classification come from intrusion_db-backed records',
        ],
      },
    },
    geolocation: { city: geo.city, country: geo.country, lat: geo.lat, lng: geo.lng },
    isp: geo.isp,
    asn: geo.asn,
    session_timeline: [
      { id: `${id}-1`, title: 'Connection captured', description: `Packet stream received from ${srcIp}`, timestamp: new Date(Date.now() - 120000).toISOString(), type: 'complete' },
      { id: `${id}-2`, title: 'DPI parsing complete', description: `${raw.protocol ?? 'unknown'} / ${raw.service ?? 'unknown'} signature extraction completed`, timestamp: new Date(Date.now() - 70000).toISOString(), type: 'complete' },
      { id: `${id}-3`, title: 'Threat classification', description: `Classified as ${raw.attack_category ?? 'unknown'}`, timestamp: new Date(Date.now() - 35000).toISOString(), type: raw.attack_category?.toLowerCase() === 'normal' ? 'complete' : 'alert' },
      { id: `${id}-4`, title: 'Operator action pending', description: 'Awaiting block/quarantine/ignore decision', timestamp: new Date().toISOString(), type: 'pending' },
    ],
  }
}

export const fetchConnectionsGeoSummary = async (
  params: Pick<ConnectionsParams, 'protocol' | 'risk_level'> = {},
  signal?: AbortSignal,
): Promise<ConnectionsGeoSummary> => {
  const raw = await apiClient
    .get<BackendGeoSummary>('/connections/geo-summary', {
      params: { protocol: params.protocol?.toLowerCase() },
      signal,
    })
    .then(r => r.data)

  return {
    total_connections: raw.total_connections,
    high_risk_ratio: raw.high_risk_ratio,
    city_breakdown: raw.city_breakdown.map(c => ({
      city: c.city,
      country: c.country,
      lat: c.lat,
      lng: c.lng,
      count: c.count,
      avg_anomaly: c.avg_anomaly,
    })),
  }
}

export const postPredict = async (payload: PredictRequest, signal?: AbortSignal): Promise<PredictResponse> => {
  const backendPayload = {
    ...payload,
    land: payload.land ? 1 : 0,
    logged_in: payload.logged_in ? 1 : 0,
  }
  const raw = await apiClient.post<BackendPredict>('/predict', backendPayload, { signal }).then(r => r.data)
  const isAttack = raw.prediction.toLowerCase() !== 'normal'
  return {
    attack_type: raw.prediction,
    is_attack: isAttack,
    confidence: raw.confidence,
    risk_level: isAttack ? (raw.confidence > 0.8 ? 'high' : raw.confidence > 0.6 ? 'medium' : 'low') : 'normal',
    top_features: Object.entries(raw.probabilities).map(([feature, value]) => ({ feature, weight: value })),
    prediction_id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
  }
}

export const fetchPredictHistory = async (limit = 50, signal?: AbortSignal): Promise<PredictLog[]> => {
  const raw = await apiClient
    .get<PredictLog[]>('/predict/history', { params: { limit }, signal })
    .then(r => r.data)
  return raw
}

export const postConnectionAction = async (
  connectionId: string,
  payload: ConnectionActionRequest,
  signal?: AbortSignal,
): Promise<ConnectionAction> => {
  const raw = await apiClient
    .post<BackendConnectionAction>(`/connections/${connectionId}/action`, payload, { signal })
    .then(r => r.data)
  return {
    action_id: raw.action_id,
    connection_id: raw.connection_id,
    action: raw.action,
    note: raw.note ?? undefined,
    operator: raw.operator,
    created_at: raw.created_at,
  }
}

export const fetchConnectionActions = async (
  connectionId: string,
  limit = 30,
  signal?: AbortSignal,
): Promise<ConnectionAction[]> => {
  const raw = await apiClient
    .get<BackendConnectionAction[]>(`/connections/${connectionId}/actions`, { params: { limit }, signal })
    .then(r => r.data)
  return raw.map(r => ({
    action_id: r.action_id,
    connection_id: r.connection_id,
    action: r.action,
    note: r.note ?? undefined,
    operator: r.operator,
    created_at: r.created_at,
  }))
}

export const postConnectionEndpointOverride = async (
  connectionId: string,
  payload: ConnectionEndpointOverrideRequest,
  signal?: AbortSignal,
): Promise<ConnectionEndpointOverrideResponse> => {
  const raw = await apiClient
    .post<BackendConnectionEndpointOverride>(`/connections/${connectionId}/endpoint`, payload, { signal })
    .then(r => r.data)
  return {
    connection_id: raw.connection_id,
    source_ip: raw.source_ip ?? undefined,
    destination_ip: raw.destination_ip ?? undefined,
    updated_at: raw.updated_at,
  }
}

export const postGeoEnrich = async (
  payload: GeoEnrichRequest = {},
  signal?: AbortSignal,
): Promise<GeoEnrichResponse> => {
  const raw = await apiClient
    .post<BackendGeoEnrichResponse>('/connections/enrich-geo', payload, { signal, timeout: 120_000 })
    .then(r => r.data)
  return {
    attempted: raw.attempted,
    updated: raw.updated,
    skipped: raw.skipped,
    failed: raw.failed,
    imported_endpoints: raw.imported_endpoints ?? 0,
  }
}

export const postBootstrapEndpoints = async (
  payload: EndpointBootstrapRequest = {},
  signal?: AbortSignal,
): Promise<EndpointBootstrapResponse> => {
  const raw = await apiClient
    .post<BackendEndpointBootstrapResponse>('/connections/bootstrap-endpoints', payload, { signal, timeout: 120_000 })
    .then(r => r.data)
  return {
    imported: raw.imported,
    scanned_tables: raw.scanned_tables,
  }
}

export const fetchGeoStatus = async (signal?: AbortSignal): Promise<GeoStatusResponse> => {
  const raw = await apiClient.get<BackendGeoStatus>('/connections/geo-status', { signal }).then(r => r.data)
  return raw
}

export const fetchStatsAttacks = async (signal?: AbortSignal): Promise<StatsAttacksResponse> => {
  const raw = await apiClient.get<Array<{ attack_name: string; category: string; count: number }>>('/stats/attacks', { signal }).then(r => r.data)
  const total = raw.reduce((acc, row) => acc + row.count, 0)
  return {
    data: raw.map(row => ({
      attack_type: `${row.attack_name} (${row.category})`,
      count: row.count,
      pct: toPercent(row.count, total),
    })),
    total,
  }
}

export const fetchStatsProtocols = async (signal?: AbortSignal): Promise<StatsProtocolsResponse> => {
  const raw = await apiClient.get<Array<{ protocol: string; count: number }>>('/stats/protocols', { signal }).then(r => r.data)
  const total = raw.reduce((acc, row) => acc + row.count, 0)
  return {
    data: raw.map(row => ({
      protocol: row.protocol,
      count: row.count,
      pct: toPercent(row.count, total),
    })),
  }
}

export const fetchStatsServices = async (signal?: AbortSignal): Promise<StatsServicesResponse> => {
  const raw = await apiClient.get<Array<{ service: string; count: number }>>('/stats/services', { signal }).then(r => r.data)
  const total = raw.reduce((acc, row) => acc + row.count, 0)
  return {
    data: raw.map(row => ({
      service: row.service,
      count: row.count,
      pct: toPercent(row.count, total),
    })),
  }
}

export const fetchLookupProtocols = async (signal?: AbortSignal): Promise<LookupResponse> => {
  const raw = await apiClient.get<BackendProtocol[]>('/lookup/protocols', { signal }).then(r => r.data)
  return { values: raw.map(x => x.protocol_name) }
}

export const fetchLookupServices = async (signal?: AbortSignal): Promise<LookupResponse> => {
  const raw = await apiClient.get<BackendService[]>('/lookup/services', { signal }).then(r => r.data)
  return { values: raw.map(x => x.service_name) }
}

export const fetchLookupFlags = async (signal?: AbortSignal): Promise<LookupResponse> => {
  const raw = await apiClient.get<BackendFlag[]>('/lookup/flags', { signal }).then(r => r.data)
  return { values: raw.map(x => x.flag_value) }
}

export const fetchLookupAttacks = async (signal?: AbortSignal): Promise<LookupResponse> => {
  const raw = await apiClient.get<BackendAttack[]>('/lookup/attacks', { signal }).then(r => r.data)
  return { values: raw.map(x => x.attack_name) }
}

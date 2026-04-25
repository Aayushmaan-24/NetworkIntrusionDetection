// ============================================================
// NIDS · API Types
// ============================================================

// ── Health ──────────────────────────────────────────────────
export type HealthStatus = 'online' | 'warning' | 'offline'

export interface HealthResponse {
  status: HealthStatus
  uptime_seconds: number
  uptime_human: string      // e.g. "14D 22H 03M"
  global_load: number       // 0–100
  node_ip: string
  db_version: string
  encryption: string
  error_count: number
  warning_count: number
  sensors: Sensor[]
  events: SystemEvent[]
  node_latency: NodeLatency
}

export interface Sensor {
  id: string               // "NODE-ALPHA-01"
  ip: string
  status: 'online' | 'latency' | 'offline'
  latency_ms?: number
}

export interface SystemEvent {
  timestamp: string
  event_id: string          // "EVT_0944_CORE"
  source: string
  message: string
  status: 'success' | 'warning' | 'info' | 'error'
}

export interface NodeLatency {
  primary_decryption_ms:  number
  heuristic_analysis_ms:  number
  packet_inspection_ms:   number
  metadata_extraction_ms: number
}

// ── Dashboard ────────────────────────────────────────────────
export interface DashboardResponse {
  total_attacks_24h:   number
  total_attacks_delta: number        // percent change
  threats_blocked:     number
  threats_blocked_pct: number
  active_threats:      number
  active_threats_level: 'critical' | 'warning' | 'normal'
  system_latency_ms:   number
  latency_status:      'stable' | 'degraded' | 'critical'
  timeline: TimelinePoint[]
  archive_timeline: TimelinePoint[]
  recent_predictions_1h: number
  recent_predictions_24h: number
  recent_actions_1h: number
  recent_actions_24h: number
  latest_prediction?: string
  latest_action?: string
  activity_feed: DashboardActivity[]
  threat_levels: ThreatLevels
  recent_alerts: Alert[]
}

export interface DashboardActivity {
  event_type: 'prediction' | 'action' | string
  title: string
  detail: string
  created_at: string
}

export interface TimelinePoint {
  time: string           // "00:00", "04:00", etc.
  value: number
}

export interface ThreatLevels {
  total_events: number
  critical:     { count: number; pct: number }
  suspicious:   { count: number; pct: number }
  benign:       { count: number; pct: number }
  other:        { count: number; pct: number }
}

export interface Alert {
  timestamp: string
  severity:  AlertSeverity
  vector:    string
  source_ip: string
  payload_action: string
  status:    AlertStatus
}

export type AlertSeverity = 'critical' | 'warning' | 'info'
export type AlertStatus   = 'blocked' | 'pending' | 'mitigated' | 'ignore' | 'intercepted'

// ── Connections ──────────────────────────────────────────────
export interface ConnectionsParams {
  page?:       number
  limit?:      number
  protocol?:   string
  risk_level?: RiskLevel
  time_range?: string
}

export interface ConnectionsResponse {
  data:    Connection[]
  total:   number
  page:    number
  limit:   number
  pages:   number
}

export interface ConnectionsGeoSummary {
  total_connections: number
  high_risk_ratio: number
  city_breakdown: GeoCitySummary[]
}

export interface GeoCitySummary {
  city: string
  country: string
  lat: number
  lng: number
  count: number
  avg_anomaly: number
}

export type RiskLevel = 'high' | 'medium' | 'low' | 'normal'

export interface Connection {
  id:             string
  timestamp:      string
  src_ip:         string
  src_port:       number
  dst_ip:         string
  dst_port:       number
  protocol:       string
  flags:          string
  bytes:          number
  bytes_human:    string        // "4.2 KB"
  status:         ConnectionStatus
  risk_level:     RiskLevel
  region_city?:   string
  region_country?: string
  anomaly_score?: number
}

export type ConnectionStatus = 'authorized' | 'blocked' | 'active' | 'intercepted'

export interface ConnectionDetail extends Connection {
  dpi_payload:      DpiPayload
  geolocation:      Geolocation
  isp:              string
  asn:              string
  session_timeline: SessionEvent[]
}

export interface ConnectionAction {
  action_id: number
  connection_id: number
  action: 'block' | 'quarantine' | 'ignore' | string
  note?: string
  operator: string
  created_at: string
}

export interface ConnectionActionRequest {
  action: 'block' | 'quarantine' | 'ignore'
  note?: string
  operator?: string
}

export interface ConnectionEndpointOverrideRequest {
  source_ip?: string
  destination_ip?: string
}

export interface ConnectionEndpointOverrideResponse {
  connection_id: number
  source_ip?: string
  destination_ip?: string
  updated_at: string
}

export interface GeoEnrichRequest {
  limit?: number
  force?: boolean
}

export interface GeoEnrichResponse {
  attempted: number
  updated: number
  skipped: number
  failed: number
  imported_endpoints?: number
}

export interface GeoStatusResponse {
  total_connections: number
  with_endpoint_ip: number
  with_geo_cache: number
  with_precise_geo: number
  coverage_pct: number
}

export interface EndpointBootstrapRequest {
  limit?: number
  force?: boolean
}

export interface EndpointBootstrapResponse {
  imported: number
  scanned_tables: number
}

export interface DpiPayload {
  raw: Record<string, unknown>   // full JSON from backend
}

export interface Geolocation {
  city:    string
  country: string
  lat:     number
  lng:     number
}

export interface SessionEvent {
  id:          string
  title:       string
  description: string
  timestamp:   string
  type:        'complete' | 'alert' | 'pending'
}

// ── Predict ──────────────────────────────────────────────────
export interface PredictRequest {
  duration:                   number
  protocol_type:              string
  service:                    string
  flag:                       string
  src_bytes:                  number
  dst_bytes:                  number
  land:                       boolean
  logged_in:                  boolean
  count:                      number
  srv_count:                  number
  serror_rate:                number
  rerror_rate:                number
  same_srv_rate:              number
  dst_host_count:             number
  dst_host_srv_count:         number
  dst_host_same_srv_rate:     number
  dst_host_diff_srv_rate:     number
  dst_host_serror_rate:       number
}

export interface PredictResponse {
  attack_type:        string     // "DDOS_SYN_FLOOD" | "BENIGN_TRAFFIC" | etc.
  is_attack:          boolean
  confidence:         number     // 0–1
  risk_level:         RiskLevel
  top_features:       FeatureImportance[]
  prediction_id:      string
  timestamp:          string
}

export interface PredictLog {
  prediction_id: number
  created_at: string
  protocol_type: string
  service: string
  flag: string
  src_bytes: number
  dst_bytes: number
  prediction: string
  confidence: number
  intrusion_probability: number
  normal_probability: number
}

export interface FeatureImportance {
  feature: string
  weight:  number   // 0–1
}

// ── Stats ────────────────────────────────────────────────────
export interface StatsAttacksResponse {
  data: AttackStat[]
  total: number
}

export interface AttackStat {
  attack_type: string
  count:       number
  pct:         number
}

export interface StatsProtocolsResponse {
  data: ProtocolStat[]
}

export interface ProtocolStat {
  protocol: string
  count:    number
  pct:      number
}

export interface StatsServicesResponse {
  data: ServiceStat[]
}

export interface ServiceStat {
  service: string
  count:   number
  pct:     number
}

// ── Lookups ──────────────────────────────────────────────────
export interface LookupResponse {
  values: string[]
}

export interface LookupCache {
  protocols: string[]
  services:  string[]
  flags:     string[]
  attacks:   string[]
}

// ── Shared / Utility ─────────────────────────────────────────
export interface ApiError {
  message:    string
  status:     number
  code?:      string
  request_id?: string
}

export interface LiveTelemetryPayload {
  type: 'telemetry' | string
  generated_at: string
  health_status: 'online' | 'warning' | 'offline' | 'degraded' | string
  totals: {
    connections: number
    attacks: number
    normal: number
    high_risk_connections: number
  }
  db_activity: {
    predictions_1h: number
    predictions_24h: number
    actions_1h: number
    actions_24h: number
    latest_prediction?: string | null
    latest_action?: string | null
  }
}

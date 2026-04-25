"""
/connections  – paginated listing of connection records from PostgreSQL
"""
import hashlib
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, text

from database import get_db
from models import (
    Connection,
    ProtocolType,
    Service,
    Flag,
    AttackType,
    AttackCategory,
    Destination,
    ConnectionOperatorAction,
    ConnectionEndpointOverride,
    ConnectionGeoCache,
)
from schemas import (
    PaginatedConnections,
    ConnectionOut,
    GeoSummaryResponse,
    GeoCitySummary,
    ConnectionActionRequest,
    ConnectionActionOut,
    ConnectionEndpointOverrideRequest,
    ConnectionEndpointOverrideOut,
    GeoEnrichRequest,
    GeoEnrichResponse,
    EndpointBootstrapRequest,
    EndpointBootstrapResponse,
)
from services.geoip_service import lookup_public_ip_geo
router = APIRouter(prefix="/connections", tags=["Connections"])

GEO_ZONES = {
    "bengaluru": {
        "city": "Bengaluru",
        "country": "India",
        "lat": 12.9716,
        "lng": 77.5946,
    },
    "chennai": {
        "city": "Chennai",
        "country": "India",
        "lat": 13.0827,
        "lng": 80.2707,
    },
    "delhi": {
        "city": "Delhi",
        "country": "India",
        "lat": 28.6139,
        "lng": 77.2090,
    },
    "mumbai": {
        "city": "Mumbai",
        "country": "India",
        "lat": 19.0760,
        "lng": 72.8777,
    },
    "hyderabad": {
        "city": "Hyderabad",
        "country": "India",
        "lat": 17.3850,
        "lng": 78.4867,
    },
    "kolkata": {
        "city": "Kolkata",
        "country": "India",
        "lat": 22.5726,
        "lng": 88.3639,
    },
    "pune": {
        "city": "Pune",
        "country": "India",
        "lat": 18.5204,
        "lng": 73.8567,
    },
    "ahmedabad": {
        "city": "Ahmedabad",
        "country": "India",
        "lat": 23.0225,
        "lng": 72.5714,
    },
    "jaipur": {
        "city": "Jaipur",
        "country": "India",
        "lat": 26.9124,
        "lng": 75.7873,
    },
    "kochi": {
        "city": "Kochi",
        "country": "India",
        "lat": 9.9312,
        "lng": 76.2673,
    },
    "lucknow": {
        "city": "Lucknow",
        "country": "India",
        "lat": 26.8467,
        "lng": 80.9462,
    },
}


def _stable_int(seed: str) -> int:
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return int(digest[:12], 16)


def _synthetic_ip(seed: str) -> str:
    value = _stable_int(seed)
    a = (value % 220) + 10
    b = ((value * 7) % 250) + 2
    c = ((value * 13) % 250) + 2
    d = ((value * 29) % 250) + 2
    return f"{a}.{b}.{c}.{d}"


def _synthetic_public_ip(seed: str) -> str:
    value = _stable_int(seed)
    prefixes = [8, 23, 31, 45, 49, 66, 91, 103, 117, 139, 157, 185, 203]
    a = prefixes[value % len(prefixes)]
    b = ((value * 5) % 250) + 2
    c = ((value * 11) % 250) + 2
    d = ((value * 17) % 250) + 2
    return f"{a}.{b}.{c}.{d}"


def _compute_anomaly_score(c: Connection, dst_bytes: int | None) -> int:
    serror = (c.serror_rate or 0.0) * 100
    rerror = (c.rerror_rate or 0.0) * 100
    same_srv = (c.same_srv_rate or 0.0) * 100
    byte_pressure = min(((c.src_bytes or 0) + (dst_bytes or 0)) / 1500, 100)
    density = min(((c.count or 0) + (c.srv_count or 0)) / 2.2, 100)

    category = (c.attack.category.category_name if c.attack and c.attack.category else "").lower()
    if category == "dos":
        category_boost = 24
    elif category == "u2r":
        category_boost = 28
    elif category == "probe":
        category_boost = 14
    elif category == "normal":
        category_boost = -18
    else:
        category_boost = 6

    score = round(
        0.32 * serror
        + 0.24 * rerror
        + 0.21 * byte_pressure
        + 0.15 * density
        + 0.08 * same_srv
        + category_boost
    )
    return max(0, min(100, score))


def _resolve_geo(c: Connection, anomaly: int):
    protocol = (c.protocol.protocol_name if c.protocol else "").lower()
    service = (c.service.service_name if c.service else "").lower()
    flag = (c.flag.flag_value if c.flag else "").lower()
    category = (c.attack.category.category_name if c.attack and c.attack.category else "").lower()
    city_keys = list(GEO_ZONES.keys())
    seed = _stable_int(
        f"{c.connection_id}-{protocol}-{service}-{flag}-{category}-{c.src_bytes}-{c.count}-{c.srv_count}"
    )
    base_index = seed % len(city_keys)
    offset = 0

    if protocol == "tcp":
        offset += 1
    elif protocol == "udp":
        offset += 3
    elif protocol == "icmp":
        offset += 5

    if "http" in service or "https" in service:
        offset += 1
    elif "domain" in service or "dns" in service:
        offset += 3
    elif "smtp" in service or "ftp" in service:
        offset += 5
    elif "private" in service or "eco_i" in service or "other" in service:
        offset += 7

    if "rej" in flag or "s0" in flag:
        offset += 2

    if category in ("dos", "u2r"):
        offset += 2
    elif category == "probe":
        offset += 4
    elif category not in ("normal",):
        offset += 6

    if anomaly > 74:
        offset += 3
    elif anomaly >= 45:
        offset += 1

    city_key = city_keys[(base_index + offset) % len(city_keys)]
    return GEO_ZONES[city_key]


def _upsert_endpoint_override(
    db: Session,
    connection_id: int,
    source_ip: str | None,
    destination_ip: str | None,
) -> ConnectionEndpointOverride:
    row = (
        db.query(ConnectionEndpointOverride)
        .filter(ConnectionEndpointOverride.connection_id == connection_id)
        .first()
    )
    if not row:
        row = ConnectionEndpointOverride(connection_id=connection_id)
        db.add(row)
    row.source_ip = source_ip
    row.destination_ip = destination_ip
    return row


def _upsert_geo_cache(
    db: Session,
    connection_id: int,
    target_ip: str | None,
    city: str,
    country: str,
    lat: float,
    lng: float,
    provider: str,
    is_precise: bool,
) -> ConnectionGeoCache:
    row = (
        db.query(ConnectionGeoCache)
        .filter(ConnectionGeoCache.connection_id == connection_id)
        .first()
    )
    if not row:
        row = ConnectionGeoCache(connection_id=connection_id)
        db.add(row)
    row.target_ip = target_ip
    row.city = city
    row.country = country
    row.lat = lat
    row.lng = lng
    row.provider = provider
    row.is_precise = bool(is_precise)
    row.resolved_at = datetime.now(timezone.utc)
    return row


def _quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _bootstrap_endpoint_overrides(
    db: Session,
    limit: int = 2000,
    force: bool = False,
) -> tuple[int, int]:
    """
    Discover packet/IP source tables and upsert endpoint overrides.
    Looks for connection_id + source/destination IP columns across public schema.
    """
    ip_aliases = {
        "source": ["source_ip", "src_ip", "src_addr", "source_address"],
        "destination": ["destination_ip", "dst_ip", "dst_addr", "destination_address"],
    }
    rows = db.execute(
        text(
            """
            SELECT table_name, column_name
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND column_name IN (
                'connection_id',
                'source_ip', 'src_ip', 'src_addr', 'source_address',
                'destination_ip', 'dst_ip', 'dst_addr', 'destination_address'
              )
            ORDER BY table_name
            """
        )
    ).mappings().all()

    by_table: dict[str, set[str]] = {}
    for row in rows:
        table_name = str(row["table_name"])
        col = str(row["column_name"])
        by_table.setdefault(table_name, set()).add(col)

    preferred_order = [
        "packet_stream",
        "packet_logs",
        "network_packets",
        "traffic_logs",
        "connections",
    ]
    ordered_tables = sorted(
        by_table.keys(),
        key=lambda t: (preferred_order.index(t) if t in preferred_order else len(preferred_order), t),
    )
    skip_tables = {
        "connection_endpoint_overrides",
        "connection_geo_cache",
        "connection_operator_actions",
    }

    imported = 0
    scanned = 0
    remaining = max(1, limit)

    for table_name in ordered_tables:
        if table_name in skip_tables:
            continue
        columns = by_table[table_name]
        if "connection_id" not in columns:
            continue

        src_col = next((c for c in ip_aliases["source"] if c in columns), None)
        dst_col = next((c for c in ip_aliases["destination"] if c in columns), None)
        if not src_col and not dst_col:
            continue
        if remaining <= 0:
            break

        scanned += 1
        src_expr = _quote_ident(src_col) if src_col else "NULL"
        dst_expr = _quote_ident(dst_col) if dst_col else "NULL"
        sql = f"""
            SELECT connection_id, {src_expr} AS source_ip, {dst_expr} AS destination_ip
            FROM {_quote_ident(table_name)}
            WHERE ({src_expr} IS NOT NULL OR {dst_expr} IS NOT NULL)
            ORDER BY connection_id DESC
            LIMIT :limit
        """
        records = db.execute(text(sql), {"limit": remaining}).mappings().all()
        for rec in records:
            connection_id = rec.get("connection_id")
            if connection_id is None:
                continue
            source_ip = (rec.get("source_ip") or "").strip() or None
            destination_ip = (rec.get("destination_ip") or "").strip() or None
            if not source_ip and not destination_ip:
                continue

            existing = (
                db.query(ConnectionEndpointOverride)
                .filter(ConnectionEndpointOverride.connection_id == connection_id)
                .first()
            )
            if existing and not force:
                # preserve manually curated overrides
                continue
            _upsert_endpoint_override(
                db=db,
                connection_id=int(connection_id),
                source_ip=source_ip,
                destination_ip=destination_ip,
            )
            imported += 1
            remaining -= 1
            if remaining <= 0:
                break

    # Fallback for NSL-KDD-style schemas without packet IP columns:
    # derive deterministic endpoint IPs from connection features.
    if remaining > 0:
        scanned += 1
        fallback_rows = (
            db.query(Connection)
            .outerjoin(ProtocolType, Connection.protocol_id == ProtocolType.protocol_id)
            .outerjoin(Service, Connection.service_id == Service.service_id)
            .outerjoin(Flag, Connection.flag_id == Flag.flag_id)
            .outerjoin(Destination, Connection.destination_id == Destination.destination_id)
            .order_by(Connection.connection_id.desc())
            .limit(remaining * 2)
            .all()
        )
        for conn in fallback_rows:
            existing = (
                db.query(ConnectionEndpointOverride)
                .filter(ConnectionEndpointOverride.connection_id == conn.connection_id)
                .first()
            )
            if existing and not force:
                continue

            protocol = conn.protocol.protocol_name if conn.protocol else "na"
            service = conn.service.service_name if conn.service else "na"
            flag = conn.flag.flag_value if conn.flag else "na"
            src_ip = _synthetic_public_ip(
                f"src-{conn.connection_id}-{conn.src_bytes}-{conn.count}-{protocol}"
            )
            dst_bytes = conn.destination.dst_bytes if conn.destination else 0
            dst_ip = _synthetic_public_ip(
                f"dst-{conn.connection_id}-{dst_bytes}-{conn.srv_count}-{service}-{flag}"
            )
            _upsert_endpoint_override(
                db=db,
                connection_id=int(conn.connection_id),
                source_ip=src_ip,
                destination_ip=dst_ip,
            )
            imported += 1
            remaining -= 1
            if remaining <= 0:
                break

    return imported, scanned


def _row_to_out(c: Connection, db: Session) -> ConnectionOut:
    dst_bytes = c.destination.dst_bytes if c.destination else None
    anomaly = _compute_anomaly_score(c, dst_bytes)
    synthetic_geo = _resolve_geo(c, anomaly)
    geo_row = (
        db.query(ConnectionGeoCache)
        .filter(ConnectionGeoCache.connection_id == c.connection_id)
        .first()
    )
    geo = (
        {
            "city": geo_row.city,
            "country": geo_row.country,
            "lat": geo_row.lat,
            "lng": geo_row.lng,
        }
        if geo_row and geo_row.city and geo_row.country and geo_row.lat is not None and geo_row.lng is not None
        else synthetic_geo
    )
    endpoint_override = (
        db.query(ConnectionEndpointOverride)
        .filter(ConnectionEndpointOverride.connection_id == c.connection_id)
        .first()
    )
    src_ip = _synthetic_ip(
        f"{c.connection_id}-{c.src_bytes}-{c.count}-{c.protocol.protocol_name if c.protocol else 'na'}"
    )
    dst_ip = _synthetic_ip(
        f"{c.connection_id}-{dst_bytes or 0}-{c.srv_count}-{c.service.service_name if c.service else 'na'}-{c.flag.flag_value if c.flag else 'na'}"
    )
    if endpoint_override and endpoint_override.source_ip:
        src_ip = endpoint_override.source_ip
    if endpoint_override and endpoint_override.destination_ip:
        dst_ip = endpoint_override.destination_ip

    return ConnectionOut(
        connection_id=c.connection_id,
        duration=c.duration,
        src_bytes=c.src_bytes,
        dst_bytes=dst_bytes,
        land=c.land,
        logged_in=c.logged_in,
        count=c.count,
        srv_count=c.srv_count,
        serror_rate=c.serror_rate,
        rerror_rate=c.rerror_rate,
        same_srv_rate=c.same_srv_rate,
        difficulty_level=c.difficulty_level,
        protocol=c.protocol.protocol_name if c.protocol else None,
        service=c.service.service_name if c.service else None,
        flag=c.flag.flag_value if c.flag else None,
        attack_name=c.attack.attack_name if c.attack else None,
        attack_category=c.attack.category.category_name if c.attack and c.attack.category else None,
        source_ip=src_ip,
        destination_ip=dst_ip,
        region_city=geo["city"],
        region_country=geo["country"],
        region_lat=geo["lat"],
        region_lng=geo["lng"],
        region_source="geoip-cache" if geo_row and geo_row.is_precise else "inferred",
        geo_precise=bool(geo_row.is_precise) if geo_row else False,
        anomaly_score=anomaly,
    )


@router.get(
    "",
    response_model=PaginatedConnections,
    summary="List connections (paginated)",
)
def list_connections(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Records per page"),
    protocol: str | None = Query(None, description="Filter by protocol (tcp/udp/icmp)"),
    attack_category: str | None = Query(None, description="Filter by attack category (DoS/Probe/R2L/U2R/Normal)"),
    logged_in: bool | None = Query(None, description="Filter by logged_in flag"),
    db: Session = Depends(get_db),
):
    query = (
        db.query(Connection)
        .outerjoin(ProtocolType, Connection.protocol_id == ProtocolType.protocol_id)
        .outerjoin(Service, Connection.service_id == Service.service_id)
        .outerjoin(Flag, Connection.flag_id == Flag.flag_id)
        .outerjoin(AttackType, Connection.attack_id == AttackType.attack_id)
        .outerjoin(AttackCategory, AttackType.category_id == AttackCategory.category_id)
        .outerjoin(Destination, Connection.destination_id == Destination.destination_id)
    )

    if protocol:
        query = query.filter(func.lower(ProtocolType.protocol_name) == protocol.lower())
    if attack_category:
        query = query.filter(func.lower(AttackCategory.category_name) == attack_category.lower())
    if logged_in is not None:
        query = query.filter(Connection.logged_in == logged_in)

    total = query.count()
    offset = (page - 1) * page_size
    rows = query.order_by(Connection.connection_id).offset(offset).limit(page_size).all()

    return PaginatedConnections(
        total=total,
        page=page,
        page_size=page_size,
        results=[_row_to_out(c, db) for c in rows],
    )


@router.post(
    "/{connection_id}/action",
    response_model=ConnectionActionOut,
    summary="Persist operator action for a connection",
)
def create_connection_action(
    connection_id: int,
    payload: ConnectionActionRequest,
    db: Session = Depends(get_db),
):
    normalized = payload.action.strip().lower()
    if normalized not in {"block", "quarantine", "ignore"}:
        raise HTTPException(status_code=400, detail="action must be one of: block, quarantine, ignore")

    exists = (
        db.query(Connection.connection_id)
        .filter(Connection.connection_id == connection_id)
        .first()
    )
    if not exists:
        raise HTTPException(status_code=404, detail=f"Connection {connection_id} not found")

    row = ConnectionOperatorAction(
        connection_id=connection_id,
        action=normalized,
        note=(payload.note or "").strip() or None,
        operator=(payload.operator or "analyst").strip() or "analyst",
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return ConnectionActionOut(
        action_id=row.action_id,
        connection_id=row.connection_id,
        action=row.action,
        note=row.note,
        operator=row.operator,
        created_at=row.created_at.isoformat() if row.created_at else "",
    )


@router.get(
    "/{connection_id}/actions",
    response_model=list[ConnectionActionOut],
    summary="List operator actions for a connection",
)
def list_connection_actions(connection_id: int, limit: int = 30, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 200))
    rows = (
        db.query(ConnectionOperatorAction)
        .filter(ConnectionOperatorAction.connection_id == connection_id)
        .order_by(ConnectionOperatorAction.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        ConnectionActionOut(
            action_id=r.action_id,
            connection_id=r.connection_id,
            action=r.action,
            note=r.note,
            operator=r.operator,
            created_at=r.created_at.isoformat() if r.created_at else "",
        )
        for r in rows
    ]


@router.post(
    "/{connection_id}/endpoint",
    response_model=ConnectionEndpointOverrideOut,
    summary="Set real source/destination IP for a connection",
)
def set_connection_endpoint(
    connection_id: int,
    payload: ConnectionEndpointOverrideRequest,
    db: Session = Depends(get_db),
):
    exists = (
        db.query(Connection.connection_id)
        .filter(Connection.connection_id == connection_id)
        .first()
    )
    if not exists:
        raise HTTPException(status_code=404, detail=f"Connection {connection_id} not found")

    source_ip = (payload.source_ip or "").strip() or None
    destination_ip = (payload.destination_ip or "").strip() or None

    row = _upsert_endpoint_override(
        db=db,
        connection_id=connection_id,
        source_ip=source_ip,
        destination_ip=destination_ip,
    )
    db.commit()
    db.refresh(row)
    return ConnectionEndpointOverrideOut(
        connection_id=row.connection_id,
        source_ip=row.source_ip,
        destination_ip=row.destination_ip,
        updated_at=row.updated_at.isoformat() if row.updated_at else "",
    )


@router.post(
    "/enrich-geo",
    response_model=GeoEnrichResponse,
    summary="Resolve and persist geolocation for real endpoint IPs",
)
def enrich_geo(
    payload: GeoEnrichRequest,
    db: Session = Depends(get_db),
):
    safe_limit = max(1, min(payload.limit, 250))
    geo_lookup_budget = max(1, min(safe_limit, 120))
    imported_endpoints, _ = _bootstrap_endpoint_overrides(
        db=db,
        limit=max(safe_limit * 2, 400),
        force=False,
    )
    db.flush()

    attempted = 0
    updated = 0
    skipped = 0
    failed = 0

    query = (
        db.query(Connection.connection_id, ConnectionEndpointOverride.destination_ip)
        .join(
            ConnectionEndpointOverride,
            ConnectionEndpointOverride.connection_id == Connection.connection_id,
        )
        .order_by(Connection.connection_id.desc())
        .limit(geo_lookup_budget)
    )
    rows = query.all()
    now = datetime.now(timezone.utc)

    for connection_id, destination_ip in rows:
        attempted += 1
        existing_geo = (
            db.query(ConnectionGeoCache)
            .filter(ConnectionGeoCache.connection_id == connection_id)
            .first()
        )
        if existing_geo and not payload.force:
            skipped += 1
            continue

        lookup = lookup_public_ip_geo(destination_ip)
        if not lookup:
            if existing_geo:
                existing_geo.resolved_at = now
            failed += 1
            continue

        _upsert_geo_cache(
            db=db,
            connection_id=connection_id,
            target_ip=destination_ip,
            city=lookup.city or "Unknown",
            country=lookup.country or "Unknown",
            lat=float(lookup.lat or 0),
            lng=float(lookup.lng or 0),
            provider=lookup.provider,
            is_precise=lookup.is_precise,
        )
        updated += 1

    db.commit()
    return GeoEnrichResponse(
        attempted=attempted,
        updated=updated,
        skipped=skipped,
        failed=failed,
        imported_endpoints=imported_endpoints,
    )


@router.post(
    "/bootstrap-endpoints",
    response_model=EndpointBootstrapResponse,
    summary="Auto-import endpoint IPs from packet/stream tables",
)
def bootstrap_endpoints(
    payload: EndpointBootstrapRequest,
    db: Session = Depends(get_db),
):
    imported, scanned_tables = _bootstrap_endpoint_overrides(
        db=db,
        limit=payload.limit,
        force=payload.force,
    )
    db.commit()
    return EndpointBootstrapResponse(imported=imported, scanned_tables=scanned_tables)


@router.get(
    "/geo-status",
    summary="Get GeoIP enrichment coverage status",
)
def geo_status(db: Session = Depends(get_db)):
    total = db.query(func.count(Connection.connection_id)).scalar() or 0
    endpoint_total = db.query(func.count(ConnectionEndpointOverride.override_id)).scalar() or 0
    geo_total = db.query(func.count(ConnectionGeoCache.geo_id)).scalar() or 0
    precise_total = (
        db.query(func.count(ConnectionGeoCache.geo_id))
        .filter(ConnectionGeoCache.is_precise.is_(True))
        .scalar()
        or 0
    )
    return {
        "total_connections": int(total),
        "with_endpoint_ip": int(endpoint_total),
        "with_geo_cache": int(geo_total),
        "with_precise_geo": int(precise_total),
        "coverage_pct": round((geo_total / total) * 100, 2) if total else 0.0,
    }


@router.get(
    "/geo-summary",
    response_model=GeoSummaryResponse,
    summary="Geo distribution and anomaly summary",
)
def geo_summary(
    protocol: str | None = Query(None, description="Optional protocol filter"),
    attack_category: str | None = Query(None, description="Optional attack category filter"),
    db: Session = Depends(get_db),
):
    query = (
        db.query(Connection)
        .outerjoin(ProtocolType, Connection.protocol_id == ProtocolType.protocol_id)
        .outerjoin(Service, Connection.service_id == Service.service_id)
        .outerjoin(Flag, Connection.flag_id == Flag.flag_id)
        .outerjoin(AttackType, Connection.attack_id == AttackType.attack_id)
        .outerjoin(AttackCategory, AttackType.category_id == AttackCategory.category_id)
        .outerjoin(Destination, Connection.destination_id == Destination.destination_id)
    )

    if protocol:
        query = query.filter(func.lower(ProtocolType.protocol_name) == protocol.lower())
    if attack_category:
        query = query.filter(func.lower(AttackCategory.category_name) == attack_category.lower())

    rows = query.limit(20000).all()
    if not rows:
        return GeoSummaryResponse(total_connections=0, high_risk_ratio=0.0, city_breakdown=[])

    row_ids = [r.connection_id for r in rows]
    geo_cache_rows = (
        db.query(ConnectionGeoCache)
        .filter(ConnectionGeoCache.connection_id.in_(row_ids))
        .all()
    )
    geo_cache_map = {item.connection_id: item for item in geo_cache_rows}

    city_totals = {
        zone["city"]: {"count": 0, "anomaly_sum": 0.0}
        for zone in GEO_ZONES.values()
    }

    high_risk = 0
    for row in rows:
        dst_bytes = row.destination.dst_bytes if row.destination else None
        anomaly = _compute_anomaly_score(row, dst_bytes)
        if anomaly >= 70:
            high_risk += 1
        geo_row = geo_cache_map.get(row.connection_id)
        geo = (
            {
                "city": geo_row.city,
                "country": geo_row.country,
                "lat": geo_row.lat,
                "lng": geo_row.lng,
            }
            if geo_row and geo_row.city and geo_row.country and geo_row.lat is not None and geo_row.lng is not None
            else _resolve_geo(row, anomaly)
        )
        city = geo["city"]
        if city not in city_totals:
            city_totals[city] = {"count": 0, "anomaly_sum": 0.0}
        city_totals[city]["count"] += 1
        city_totals[city]["anomaly_sum"] += anomaly

    city_breakdown = []
    city_meta = {zone["city"]: zone for zone in GEO_ZONES.values()}
    for city, stats in city_totals.items():
        count = stats["count"]
        if count == 0:
            continue
        zone = city_meta.get(
            city,
            {
                "city": city,
                "country": "Unknown",
                "lat": 20.5937,
                "lng": 78.9629,
            },
        )
        avg_anomaly = round(stats["anomaly_sum"] / count, 2)
        city_breakdown.append(
            GeoCitySummary(
                city=zone["city"],
                country=zone["country"],
                lat=zone["lat"],
                lng=zone["lng"],
                count=count,
                avg_anomaly=avg_anomaly,
            )
        )
    city_breakdown.sort(key=lambda item: item.count, reverse=True)

    ratio = round((high_risk / len(rows)) * 100, 2)
    return GeoSummaryResponse(
        total_connections=len(rows),
        high_risk_ratio=ratio,
        city_breakdown=city_breakdown,
    )


@router.get(
    "/{connection_id}",
    response_model=ConnectionOut,
    summary="Get a single connection by ID",
)
def get_connection(connection_id: int, db: Session = Depends(get_db)):
    c = (
        db.query(Connection)
        .outerjoin(ProtocolType)
        .outerjoin(Service)
        .outerjoin(Flag)
        .outerjoin(AttackType)
        .outerjoin(AttackCategory)
        .outerjoin(Destination)
        .filter(Connection.connection_id == connection_id)
        .first()
    )
    if not c:
        raise HTTPException(status_code=404, detail=f"Connection {connection_id} not found")
    return _row_to_out(c, db)

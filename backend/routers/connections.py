"""
/connections  – paginated listing of connection records from PostgreSQL
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, select

from database import get_db
from models import Connection, ProtocolType, Service, Flag, AttackType, AttackCategory, Destination
from schemas import PaginatedConnections, ConnectionOut

router = APIRouter(prefix="/connections", tags=["Connections"])


def _row_to_out(c: Connection) -> ConnectionOut:
    dst_bytes = c.destination.dst_bytes if c.destination else None
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
        results=[_row_to_out(c) for c in rows],
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
    return _row_to_out(c)

"""
/stats  – aggregate statistics from PostgreSQL
/dashboard – summary stats for a frontend dashboard
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, case

from database import get_db
from models import Connection, AttackType, AttackCategory, ProtocolType, Service, Flag
from schemas import (
    DashboardStats,
    AttackDistributionItem,
    AttackCategoryItem,
    ProtocolStatsItem,
    ServiceStatsItem,
    FlagStatsItem,
)

router = APIRouter(tags=["Statistics"])


# ---------------------------------------------------------------------------
# /dashboard  – single call that returns everything a frontend needs
# ---------------------------------------------------------------------------

@router.get(
    "/dashboard",
    response_model=DashboardStats,
    summary="Full dashboard statistics",
)
def dashboard(db: Session = Depends(get_db)):
    # --- totals ---
    total = db.query(func.count(Connection.connection_id)).scalar() or 0

    normal_category_id = (
        db.query(AttackCategory.category_id)
        .filter(func.lower(AttackCategory.category_name) == "normal")
        .scalar()
    )
    normal_attack_ids = (
        db.query(AttackType.attack_id)
        .filter(AttackType.category_id == normal_category_id)
        .all()
    )
    normal_ids = [r[0] for r in normal_attack_ids]

    total_normal = (
        db.query(func.count(Connection.connection_id))
        .filter(Connection.attack_id.in_(normal_ids))
        .scalar()
        or 0
    )
    total_attacks = total - total_normal
    attack_rate = round(total_attacks / total * 100, 2) if total else 0.0

    # --- attack category breakdown ---
    cat_rows = (
        db.query(AttackCategory.category_name, func.count(Connection.connection_id))
        .join(AttackType, AttackType.category_id == AttackCategory.category_id)
        .join(Connection, Connection.attack_id == AttackType.attack_id)
        .group_by(AttackCategory.category_name)
        .order_by(func.count(Connection.connection_id).desc())
        .all()
    )
    attack_categories = [
        AttackCategoryItem(category=r[0], count=r[1]) for r in cat_rows
    ]

    # --- top 10 attack types ---
    atk_rows = (
        db.query(
            AttackType.attack_name,
            AttackCategory.category_name,
            func.count(Connection.connection_id),
        )
        .join(AttackCategory, AttackType.category_id == AttackCategory.category_id)
        .join(Connection, Connection.attack_id == AttackType.attack_id)
        .group_by(AttackType.attack_name, AttackCategory.category_name)
        .order_by(func.count(Connection.connection_id).desc())
        .limit(10)
        .all()
    )
    top_attack_types = [
        AttackDistributionItem(attack_name=r[0], category=r[1], count=r[2])
        for r in atk_rows
    ]

    # --- protocol distribution ---
    proto_rows = (
        db.query(ProtocolType.protocol_name, func.count(Connection.connection_id))
        .join(Connection, Connection.protocol_id == ProtocolType.protocol_id)
        .group_by(ProtocolType.protocol_name)
        .order_by(func.count(Connection.connection_id).desc())
        .all()
    )
    protocol_distribution = [
        ProtocolStatsItem(protocol=r[0], count=r[1]) for r in proto_rows
    ]

    # --- top 10 services ---
    svc_rows = (
        db.query(Service.service_name, func.count(Connection.connection_id))
        .join(Connection, Connection.service_id == Service.service_id)
        .group_by(Service.service_name)
        .order_by(func.count(Connection.connection_id).desc())
        .limit(10)
        .all()
    )
    top_services = [ServiceStatsItem(service=r[0], count=r[1]) for r in svc_rows]

    # --- flag distribution ---
    flag_rows = (
        db.query(Flag.flag_value, func.count(Connection.connection_id))
        .join(Connection, Connection.flag_id == Flag.flag_id)
        .group_by(Flag.flag_value)
        .order_by(func.count(Connection.connection_id).desc())
        .all()
    )
    flag_distribution = [FlagStatsItem(flag=r[0], count=r[1]) for r in flag_rows]

    return DashboardStats(
        total_connections=total,
        total_attacks=total_attacks,
        total_normal=total_normal,
        attack_rate=attack_rate,
        attack_categories=attack_categories,
        top_attack_types=top_attack_types,
        protocol_distribution=protocol_distribution,
        top_services=top_services,
        flag_distribution=flag_distribution,
    )


# ---------------------------------------------------------------------------
# /stats/attacks  – all attack types with their categories
# ---------------------------------------------------------------------------

@router.get(
    "/stats/attacks",
    summary="All attack types and counts",
)
def attack_stats(db: Session = Depends(get_db)):
    rows = (
        db.query(
            AttackType.attack_name,
            AttackCategory.category_name,
            func.count(Connection.connection_id).label("count"),
        )
        .join(AttackCategory, AttackType.category_id == AttackCategory.category_id)
        .join(Connection, Connection.attack_id == AttackType.attack_id)
        .group_by(AttackType.attack_name, AttackCategory.category_name)
        .order_by(func.count(Connection.connection_id).desc())
        .all()
    )
    return [{"attack_name": r[0], "category": r[1], "count": r[2]} for r in rows]


# ---------------------------------------------------------------------------
# /stats/protocols  – protocol breakdown
# ---------------------------------------------------------------------------

@router.get("/stats/protocols", summary="Protocol distribution")
def protocol_stats(db: Session = Depends(get_db)):
    rows = (
        db.query(ProtocolType.protocol_name, func.count(Connection.connection_id))
        .join(Connection, Connection.protocol_id == ProtocolType.protocol_id)
        .group_by(ProtocolType.protocol_name)
        .order_by(func.count(Connection.connection_id).desc())
        .all()
    )
    return [{"protocol": r[0], "count": r[1]} for r in rows]


# ---------------------------------------------------------------------------
# /stats/services  – service breakdown
# ---------------------------------------------------------------------------

@router.get("/stats/services", summary="Service distribution (top 20)")
def service_stats(db: Session = Depends(get_db)):
    rows = (
        db.query(Service.service_name, func.count(Connection.connection_id))
        .join(Connection, Connection.service_id == Service.service_id)
        .group_by(Service.service_name)
        .order_by(func.count(Connection.connection_id).desc())
        .limit(20)
        .all()
    )
    return [{"service": r[0], "count": r[1]} for r in rows]

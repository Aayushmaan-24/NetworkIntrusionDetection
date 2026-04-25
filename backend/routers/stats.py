"""
/stats  – aggregate statistics from PostgreSQL
/dashboard – summary stats for a frontend dashboard
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, case
from datetime import datetime, timedelta, timezone

from database import get_db
from models import (
    Connection,
    AttackType,
    AttackCategory,
    ProtocolType,
    Service,
    Flag,
    PredictionLog,
    ConnectionOperatorAction,
)
from schemas import (
    DashboardStats,
    DashboardActivityItem,
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

    normal_category_ids = (
        db.query(AttackCategory.category_id)
        .filter(func.lower(AttackCategory.category_name) == "normal")
        .all()
    )
    cat_ids = [r[0] for r in normal_category_ids]
    
    normal_attack_ids = (
        db.query(AttackType.attack_id)
        .filter(AttackType.category_id.in_(cat_ids))
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

    category_lower = func.lower(AttackCategory.category_name)
    category_boost = case(
        (category_lower == "dos", 24.0),
        (category_lower == "u2r", 28.0),
        (category_lower == "probe", 14.0),
        (category_lower == "normal", -18.0),
        else_=6.0,
    )

    anomaly_expr = (
        0.32 * (func.coalesce(Connection.serror_rate, 0.0) * 100.0)
        + 0.24 * (func.coalesce(Connection.rerror_rate, 0.0) * 100.0)
        + 0.21 * func.least((func.coalesce(Connection.src_bytes, 0.0) / 1500.0), 100.0)
        + 0.15 * func.least(((func.coalesce(Connection.count, 0.0) + func.coalesce(Connection.srv_count, 0.0)) / 2.2), 100.0)
        + 0.08 * (func.coalesce(Connection.same_srv_rate, 0.0) * 100.0)
        + category_boost
    )

    risk_rows = (
        db.query(
            func.count(Connection.connection_id).label("total"),
            func.avg(anomaly_expr).label("avg_anomaly"),
            func.sum(case((anomaly_expr >= 70.0, 1), else_=0)).label("high_risk"),
        )
        .outerjoin(AttackType, Connection.attack_id == AttackType.attack_id)
        .outerjoin(AttackCategory, AttackType.category_id == AttackCategory.category_id)
        .first()
    )
    high_risk_connections = int((risk_rows[2] or 0) if risk_rows else 0)
    avg_anomaly_score = float(round((risk_rows[1] or 0.0), 2) if risk_rows else 0.0)

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

    now_utc = datetime.now(timezone.utc)
    last_hour = now_utc - timedelta(hours=1)
    last_day = now_utc - timedelta(hours=24)

    recent_predictions_1h = (
        db.query(func.count(PredictionLog.prediction_id))
        .filter(PredictionLog.created_at >= last_hour)
        .scalar()
        or 0
    )
    recent_predictions_24h = (
        db.query(func.count(PredictionLog.prediction_id))
        .filter(PredictionLog.created_at >= last_day)
        .scalar()
        or 0
    )
    recent_actions_1h = (
        db.query(func.count(ConnectionOperatorAction.action_id))
        .filter(ConnectionOperatorAction.created_at >= last_hour)
        .scalar()
        or 0
    )
    recent_actions_24h = (
        db.query(func.count(ConnectionOperatorAction.action_id))
        .filter(ConnectionOperatorAction.created_at >= last_day)
        .scalar()
        or 0
    )

    latest_prediction_row = (
        db.query(PredictionLog)
        .order_by(PredictionLog.created_at.desc())
        .first()
    )
    latest_action_row = (
        db.query(ConnectionOperatorAction)
        .order_by(ConnectionOperatorAction.created_at.desc())
        .first()
    )

    feed_predictions = (
        db.query(PredictionLog)
        .order_by(PredictionLog.created_at.desc())
        .limit(8)
        .all()
    )
    feed_actions = (
        db.query(ConnectionOperatorAction)
        .order_by(ConnectionOperatorAction.created_at.desc())
        .limit(8)
        .all()
    )

    activity_feed: list[DashboardActivityItem] = []
    for row in feed_predictions:
        timestamp = row.created_at.isoformat() if row.created_at else ""
        activity_feed.append(
            DashboardActivityItem(
                event_type="prediction",
                title=f"Prediction: {row.prediction}",
                detail=f"{row.protocol_type.upper()} / {row.service} / confidence {round(float(row.confidence) * 100, 1)}%",
                created_at=timestamp,
            )
        )
    for row in feed_actions:
        timestamp = row.created_at.isoformat() if row.created_at else ""
        activity_feed.append(
            DashboardActivityItem(
                event_type="action",
                title=f"Operator action: {row.action}",
                detail=f"Conn #{row.connection_id} by {row.operator}",
                created_at=timestamp,
            )
        )
    activity_feed.sort(key=lambda item: item.created_at, reverse=True)
    activity_feed = activity_feed[:10]

    return DashboardStats(
        total_connections=total,
        total_attacks=total_attacks,
        total_normal=total_normal,
        attack_rate=attack_rate,
        high_risk_connections=high_risk_connections,
        avg_anomaly_score=avg_anomaly_score,
        recent_predictions_1h=recent_predictions_1h,
        recent_predictions_24h=recent_predictions_24h,
        recent_actions_1h=recent_actions_1h,
        recent_actions_24h=recent_actions_24h,
        latest_prediction=latest_prediction_row.prediction if latest_prediction_row else None,
        latest_action=latest_action_row.action if latest_action_row else None,
        activity_feed=activity_feed,
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

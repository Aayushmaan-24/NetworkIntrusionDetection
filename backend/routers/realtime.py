"""
/ws/live - websocket stream for live telemetry snapshots from PostgreSQL
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import case, func

from database import SessionLocal
from models import (
    AttackCategory,
    AttackType,
    Connection,
    ConnectionOperatorAction,
    PredictionLog,
)

router = APIRouter(tags=["Realtime"])


def _telemetry_snapshot():
    db = SessionLocal()
    try:
        total_connections = db.query(func.count(Connection.connection_id)).scalar() or 0

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
        normal_ids = [row[0] for row in normal_attack_ids]

        total_normal = (
            db.query(func.count(Connection.connection_id))
            .filter(Connection.attack_id.in_(normal_ids))
            .scalar()
            or 0
        )
        total_attacks = max(total_connections - total_normal, 0)

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

        latest_prediction = (
            db.query(PredictionLog)
            .order_by(PredictionLog.created_at.desc())
            .first()
        )
        latest_action = (
            db.query(ConnectionOperatorAction)
            .order_by(ConnectionOperatorAction.created_at.desc())
            .first()
        )

        high_risk_connections = (
            db.query(
                func.sum(
                    case(
                        (func.coalesce(Connection.serror_rate, 0.0) >= 0.35, 1),
                        else_=0,
                    )
                )
            ).scalar()
            or 0
        )

        return {
            "type": "telemetry",
            "generated_at": now_utc.isoformat(),
            "health_status": "online",
            "totals": {
                "connections": int(total_connections),
                "attacks": int(total_attacks),
                "normal": int(total_normal),
                "high_risk_connections": int(high_risk_connections),
            },
            "db_activity": {
                "predictions_1h": int(recent_predictions_1h),
                "predictions_24h": int(recent_predictions_24h),
                "actions_1h": int(recent_actions_1h),
                "actions_24h": int(recent_actions_24h),
                "latest_prediction": latest_prediction.prediction if latest_prediction else None,
                "latest_action": latest_action.action if latest_action else None,
            },
        }
    except Exception:
        return {
            "type": "telemetry",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "health_status": "degraded",
            "totals": {
                "connections": 0,
                "attacks": 0,
                "normal": 0,
                "high_risk_connections": 0,
            },
            "db_activity": {
                "predictions_1h": 0,
                "predictions_24h": 0,
                "actions_1h": 0,
                "actions_24h": 0,
                "latest_prediction": None,
                "latest_action": None,
            },
        }
    finally:
        db.close()


@router.websocket("/ws/live")
async def live_telemetry(ws: WebSocket):
    await ws.accept()
    try:
        while True:
            await ws.send_json(_telemetry_snapshot())
            await asyncio.sleep(3)
    except WebSocketDisconnect:
        return

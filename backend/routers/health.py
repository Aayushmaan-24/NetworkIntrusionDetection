"""
/health  – liveness + readiness probe
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from database import get_db
from config import MODEL_ABS_PATH
from schemas import HealthResponse

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("", response_model=HealthResponse, summary="Health check")
def health_check(db: Session = Depends(get_db)):
    # Check DB
    try:
        db.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception as e:
        db_status = f"error: {e}"

    # Check model file
    model_loaded = MODEL_ABS_PATH.exists()

    return HealthResponse(
        status="ok" if db_status == "ok" and model_loaded else "degraded",
        database=db_status,
        model_loaded=model_loaded,
        model_path=str(MODEL_ABS_PATH),
    )

"""
/predict  – ML model inference endpoint
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from schemas import PredictRequest, PredictResponse, PredictLogOut
from database import get_db
import ml_service
from models import PredictionLog

router = APIRouter(prefix="/predict", tags=["Prediction"])


@router.post(
    "",
    response_model=PredictResponse,
    summary="Classify a network connection",
    description=(
        "Accepts network connection features and returns a prediction of "
        "**Normal** or **Intrusion** along with class probabilities."
    ),
)
def predict_intrusion(req: PredictRequest, db: Session = Depends(get_db)) -> PredictResponse:
    try:
        result = ml_service.predict(req, db)

        log = PredictionLog(
            protocol_type=req.protocol_type,
            service=req.service,
            flag=req.flag,
            src_bytes=req.src_bytes,
            dst_bytes=req.dst_bytes,
            prediction=result.prediction,
            confidence=result.confidence,
            intrusion_probability=result.probabilities.get("Intrusion", 0.0),
            normal_probability=result.probabilities.get("Normal", 0.0),
        )
        db.add(log)
        db.commit()
        return result
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {e}")


@router.get(
    "/history",
    response_model=list[PredictLogOut],
    summary="Recent prediction history",
)
def prediction_history(limit: int = 50, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 500))
    rows = (
        db.query(PredictionLog)
        .order_by(PredictionLog.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        PredictLogOut(
            prediction_id=r.prediction_id,
            created_at=r.created_at.isoformat() if r.created_at else "",
            protocol_type=r.protocol_type,
            service=r.service,
            flag=r.flag,
            src_bytes=r.src_bytes,
            dst_bytes=r.dst_bytes,
            prediction=r.prediction,
            confidence=round(float(r.confidence), 4),
            intrusion_probability=round(float(r.intrusion_probability), 4),
            normal_probability=round(float(r.normal_probability), 4),
        )
        for r in rows
    ]

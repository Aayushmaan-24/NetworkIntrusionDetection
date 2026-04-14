"""
/predict  – ML model inference endpoint
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from schemas import PredictRequest, PredictResponse
from database import get_db
import ml_service

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
        return ml_service.predict(req, db)
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {e}")

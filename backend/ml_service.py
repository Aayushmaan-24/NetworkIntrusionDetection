"""
ML model loading and inference service.
Loads the trained Random Forest from intrusion_model.pkl and
encodes categorical features identically to the training notebook.
"""
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from functools import lru_cache
from sqlalchemy.orm import Session
from sqlalchemy import func

from config import MODEL_ABS_PATH
from schemas import PredictRequest, PredictResponse
from models import ProtocolType, Service, Flag


# Column order that the model was trained on (from the notebook)
FEATURE_COLUMNS = [
    'duration', 
    'src_bytes', 
    'dst_bytes', 
    'land', 
    'logged_in', 
    'count', 
    'srv_count', 
    'serror_rate', 
    'rerror_rate', 
    'same_srv_rate', 
    'dst_host_count', 
    'dst_host_srv_count', 
    'protocol_id', 
    'service_id', 
    'flag_id'
]

CLASS_LABELS = ["Normal", "Intrusion"]


@lru_cache(maxsize=1)
def load_model():
    """Load the pickled Random Forest model (cached after first call)."""
    if not MODEL_ABS_PATH.exists():
        raise FileNotFoundError(
            f"Model file not found at {MODEL_ABS_PATH}. "
            "Make sure intrusion_model.pkl exists in the ML-Based-Network-Intrusion-Detection-System folder."
        )
    return joblib.load(MODEL_ABS_PATH)


def _get_lookup_id(db: Session, model_class, field, item_value: str) -> int:
    """Helper to query the DB for lookup IDs. Raises ValueError if not found."""
    item = db.query(model_class).filter(func.lower(field) == item_value.lower()).first()
    if not item:
        raise ValueError(f"Unknown label: {item_value} for {model_class.__tablename__}")
    
    # Return the primary key
    for attr in ["protocol_id", "service_id", "flag_id"]:
        if hasattr(item, attr):
            return getattr(item, attr)
            
    raise ValueError(f"Could not find ID attribute on {model_class.__tablename__}")


def _encode_features(req: PredictRequest, db: Session) -> pd.DataFrame:
    """
    Convert a PredictRequest into the exact feature DataFrame the model expects.
    This means mapping protocol_type, service, and flag to their respective database IDs.
    """
    proto_id = _get_lookup_id(db, ProtocolType, ProtocolType.protocol_name, req.protocol_type)
    svc_id = _get_lookup_id(db, Service, Service.service_name, req.service)
    
    # Flag lookup needs exact matching without lowering everything since 'SF' is uppercase
    flag_item = db.query(Flag).filter(func.upper(Flag.flag_value) == req.flag.upper()).first()
    if not flag_item:
         raise ValueError(f"Unknown flag: {req.flag}")
    flag_id = flag_item.flag_id

    row = {
        "duration": req.duration,
        "src_bytes": req.src_bytes,
        "dst_bytes": req.dst_bytes,
        "land": int(req.land),
        "logged_in": int(req.logged_in),
        "count": req.count,
        "srv_count": req.srv_count,
        "serror_rate": req.serror_rate,
        "rerror_rate": req.rerror_rate,
        "same_srv_rate": req.same_srv_rate,
        "dst_host_count": req.dst_host_count,
        "dst_host_srv_count": req.dst_host_srv_count,
        "protocol_id": proto_id,
        "service_id": svc_id,
        "flag_id": flag_id,
    }

    df = pd.DataFrame([row])

    # Align to the exact column list the model was trained on
    df = df.reindex(columns=FEATURE_COLUMNS, fill_value=0)

    return df


def predict(req: PredictRequest, db: Session) -> PredictResponse:
    """Run inference and return structured prediction response."""
    model = load_model()
    X = _encode_features(req, db)

    pred_idx = int(model.predict(X)[0])
    proba = model.predict_proba(X)[0]

    # Model outputs binary: 0 = Normal, 1 = Intrusion
    classes = model.classes_
    proba_dict: dict[str, float] = {}
    for cls_idx, cls_val in enumerate(classes):
        label = "Normal" if int(cls_val) == 0 else "Intrusion"
        proba_dict[label] = round(float(proba[cls_idx]), 4)

    prediction_label = "Normal" if pred_idx == 0 else "Intrusion"
    confidence = proba_dict.get(prediction_label, float(max(proba)))

    return PredictResponse(
        prediction=prediction_label,
        confidence=round(confidence, 4),
        probabilities=proba_dict,
    )

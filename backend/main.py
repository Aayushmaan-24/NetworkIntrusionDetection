"""
ML-Based Network Intrusion Detection System – FastAPI Backend
=============================================================
Endpoints
---------
GET  /health                  → liveness + readiness probe
POST /predict                 → ML model inference
GET  /connections             → paginated connection records (filterable)
GET  /connections/{id}        → single connection record
GET  /dashboard               → full dashboard stats
GET  /stats/attacks           → per-attack-type counts
GET  /stats/protocols         → protocol distribution
GET  /stats/services          → service distribution (top 20)
GET  /lookup/protocols        → all protocol types
GET  /lookup/services         → all services
GET  /lookup/flags            → all flags
GET  /lookup/attacks          → all attack types with categories
GET  /docs                    → Swagger UI
GET  /redoc                   → ReDoc
"""
import sys
import os

# Make sure the backend/ folder itself is on the path so local imports work
sys.path.insert(0, os.path.dirname(__file__))

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routers import predict, connections, stats, lookup, health, realtime
import ml_service
from database import engine, Base
import models


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Pre-load the ML model on startup so the first request isn't slow."""
    try:
        # Ensure runtime extension tables exist.
        Base.metadata.create_all(
            bind=engine,
            tables=[
                models.PredictionLog.__table__,
                models.ConnectionOperatorAction.__table__,
                models.ConnectionEndpointOverride.__table__,
                models.ConnectionGeoCache.__table__,
            ],
        )
        ml_service.load_model()
        print("ML model loaded successfully.")
    except FileNotFoundError as e:
        print(f"Model not found at startup: {e}")
    yield
    print("Shutting down.")


app = FastAPI(
    title="Network Intrusion Detection API",
    description=(
        "REST API for the ML-Based Network Intrusion Detection System.\n\n"
        "Connects to the **intrusion_db** PostgreSQL database and serves "
        "predictions from a trained **Random Forest** classifier (NSL-KDD dataset)."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ---------------------------------------------------------------------------
# CORS – allow all origins in dev; tighten in production
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(health.router)
app.include_router(predict.router)
app.include_router(connections.router)
app.include_router(stats.router)
app.include_router(lookup.router)
app.include_router(realtime.router)


@app.get("/", tags=["Root"], summary="API root")
def root():
    return {
        "project": "ML-Based Network Intrusion Detection System",
        "version": "1.0.0",
        "docs": "/docs",
        "redoc": "/redoc",
        "health": "/health",
    }


# ---------------------------------------------------------------------------
# Dev entrypoint: `python main.py`
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    from config import settings

    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=True,
        reload_dirs=[os.path.dirname(__file__)],
    )


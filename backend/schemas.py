"""
Pydantic schemas for request/response validation.
"""
from __future__ import annotations
from typing import Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------

class PredictRequest(BaseModel):
    """All features expected by the trained Random Forest model."""
    duration: int = Field(..., ge=0, description="Connection duration in seconds")
    protocol_type: str = Field(..., description="Network protocol: tcp, udp, icmp")
    service: str = Field(..., description="Network service: http, ftp, smtp, etc.")
    flag: str = Field(..., description="Connection status flag: SF, S0, REJ, etc.")
    src_bytes: int = Field(..., ge=0, description="Bytes sent from source to destination")
    dst_bytes: int = Field(..., ge=0, description="Bytes sent from destination to source")
    land: int = Field(..., ge=0, le=1, description="1 if src/dst IPs and ports are equal")
    logged_in: int = Field(..., ge=0, le=1, description="1 if successfully logged in")
    count: int = Field(..., ge=0, description="Connections to same host in past 2 seconds")
    srv_count: int = Field(..., ge=0, description="Connections to same service in past 2 seconds")
    serror_rate: float = Field(..., ge=0.0, le=1.0, description="% of connections with SYN errors")
    rerror_rate: float = Field(..., ge=0.0, le=1.0, description="% of connections with REJ errors")
    same_srv_rate: float = Field(..., ge=0.0, le=1.0, description="% of connections to same service")
    dst_host_count: int = Field(..., ge=0, le=255, description="Count of connections to same destination host")
    dst_host_srv_count: int = Field(..., ge=0, le=255, description="Count of connections to same service on destination host")
    dst_host_same_srv_rate: float = Field(..., ge=0.0, le=1.0, description="% of connections to same service on destination host")
    dst_host_diff_srv_rate: float = Field(..., ge=0.0, le=1.0, description="% of connections to different services on destination host")
    dst_host_serror_rate: float = Field(..., ge=0.0, le=1.0, description="% of connections with SYN errors to destination host")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "duration": 0,
                    "protocol_type": "tcp",
                    "service": "http",
                    "flag": "SF",
                    "src_bytes": 215,
                    "dst_bytes": 45076,
                    "land": 0,
                    "logged_in": 1,
                    "count": 1,
                    "srv_count": 1,
                    "serror_rate": 0.0,
                    "rerror_rate": 0.0,
                    "same_srv_rate": 1.0,
                    "dst_host_count": 255,
                    "dst_host_srv_count": 255,
                    "dst_host_same_srv_rate": 1.0,
                    "dst_host_diff_srv_rate": 0.0,
                    "dst_host_serror_rate": 0.0,
                }
            ]
        }
    }


class PredictResponse(BaseModel):
    prediction: str               # "Normal" or "Intrusion"
    confidence: float             # probability of predicted class
    probabilities: dict[str, float]  # {"Normal": x, "Intrusion": y}


# ---------------------------------------------------------------------------
# Connections (paginated listing)
# ---------------------------------------------------------------------------

class ConnectionOut(BaseModel):
    connection_id: int
    duration: int
    src_bytes: int
    dst_bytes: Optional[int]
    land: bool
    logged_in: bool
    count: Optional[int]
    srv_count: Optional[int]
    serror_rate: Optional[float]
    rerror_rate: Optional[float]
    same_srv_rate: Optional[float]
    difficulty_level: Optional[int]
    protocol: Optional[str]
    service: Optional[str]
    flag: Optional[str]
    attack_name: Optional[str]
    attack_category: Optional[str]

    model_config = {"from_attributes": True}


class PaginatedConnections(BaseModel):
    total: int
    page: int
    page_size: int
    results: list[ConnectionOut]


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class AttackDistributionItem(BaseModel):
    attack_name: str
    category: str
    count: int


class AttackCategoryItem(BaseModel):
    category: str
    count: int


class ProtocolStatsItem(BaseModel):
    protocol: str
    count: int


class ServiceStatsItem(BaseModel):
    service: str
    count: int


class FlagStatsItem(BaseModel):
    flag: str
    count: int


class DashboardStats(BaseModel):
    total_connections: int
    total_attacks: int
    total_normal: int
    attack_rate: float
    attack_categories: list[AttackCategoryItem]
    top_attack_types: list[AttackDistributionItem]
    protocol_distribution: list[ProtocolStatsItem]
    top_services: list[ServiceStatsItem]
    flag_distribution: list[FlagStatsItem]


# ---------------------------------------------------------------------------
# Lookup tables
# ---------------------------------------------------------------------------

class AttackTypeOut(BaseModel):
    attack_id: int
    attack_name: str
    category: str

    model_config = {"from_attributes": True}


class ProtocolOut(BaseModel):
    protocol_id: int
    protocol_name: str

    model_config = {"from_attributes": True}


class ServiceOut(BaseModel):
    service_id: int
    service_name: str

    model_config = {"from_attributes": True}


class FlagOut(BaseModel):
    flag_id: int
    flag_value: str

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str
    database: str
    model_loaded: bool
    model_path: str

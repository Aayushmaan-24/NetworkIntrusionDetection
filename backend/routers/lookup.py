"""
/lookup  – static lookup tables (protocols, services, flags, attack types)
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from models import ProtocolType, Service, Flag, AttackType, AttackCategory
from schemas import ProtocolOut, ServiceOut, FlagOut, AttackTypeOut

router = APIRouter(prefix="/lookup", tags=["Lookup Tables"])


@router.get("/protocols", response_model=list[ProtocolOut], summary="All protocol types")
def get_protocols(db: Session = Depends(get_db)):
    return db.query(ProtocolType).order_by(ProtocolType.protocol_name).all()


@router.get("/services", response_model=list[ServiceOut], summary="All services")
def get_services(db: Session = Depends(get_db)):
    return db.query(Service).order_by(Service.service_name).all()


@router.get("/flags", response_model=list[FlagOut], summary="All connection flags")
def get_flags(db: Session = Depends(get_db)):
    return db.query(Flag).order_by(Flag.flag_value).all()


@router.get("/attacks", response_model=list[AttackTypeOut], summary="All attack types with their category")
def get_attacks(db: Session = Depends(get_db)):
    rows = (
        db.query(AttackType)
        .join(AttackCategory, AttackType.category_id == AttackCategory.category_id)
        .order_by(AttackCategory.category_name, AttackType.attack_name)
        .all()
    )
    return [
        AttackTypeOut(
            attack_id=r.attack_id,
            attack_name=r.attack_name,
            category=r.category.category_name,
        )
        for r in rows
    ]

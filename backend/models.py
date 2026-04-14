"""
SQLAlchemy ORM models mirroring the intrusion_db schema.
"""
from sqlalchemy import (
    BigInteger, Boolean, Column, Float, ForeignKey,
    Integer, SmallInteger, String,
)
from sqlalchemy.orm import relationship
from database import Base


class ProtocolType(Base):
    __tablename__ = "protocol_types"

    protocol_id = Column(Integer, primary_key=True, index=True)
    protocol_name = Column(String, nullable=False, unique=True)

    connections = relationship("Connection", back_populates="protocol")


class Service(Base):
    __tablename__ = "services"

    service_id = Column(Integer, primary_key=True, index=True)
    service_name = Column(String, nullable=False, unique=True)

    connections = relationship("Connection", back_populates="service")


class Flag(Base):
    __tablename__ = "flags"

    flag_id = Column(Integer, primary_key=True, index=True)
    flag_value = Column(String, nullable=False, unique=True)

    connections = relationship("Connection", back_populates="flag")


class AttackCategory(Base):
    __tablename__ = "attack_categories"

    category_id = Column(Integer, primary_key=True, index=True)
    category_name = Column(String, nullable=False, unique=True)

    attack_types = relationship("AttackType", back_populates="category")


class AttackType(Base):
    __tablename__ = "attack_types"

    attack_id = Column(Integer, primary_key=True, index=True)
    attack_name = Column(String, nullable=False, unique=True)
    category_id = Column(Integer, ForeignKey("attack_categories.category_id"), nullable=False)

    category = relationship("AttackCategory", back_populates="attack_types")
    connections = relationship("Connection", back_populates="attack")


class Destination(Base):
    __tablename__ = "destination"

    destination_id = Column(Integer, primary_key=True, index=True)
    dst_bytes = Column(BigInteger)
    dst_host_count = Column(SmallInteger)
    dst_host_srv_count = Column(SmallInteger)
    dst_host_same_srv_rate = Column(Float)
    dst_host_diff_srv_rate = Column(Float)
    dst_host_serror_rate = Column(Float)

    connections = relationship("Connection", back_populates="destination")


class Connection(Base):
    __tablename__ = "connections"

    connection_id = Column(BigInteger, primary_key=True, index=True)
    duration = Column(Integer, nullable=False)
    src_bytes = Column(BigInteger, nullable=False)
    land = Column(Boolean, nullable=False)
    logged_in = Column(Boolean, nullable=False)
    count = Column(SmallInteger)
    srv_count = Column(SmallInteger)
    serror_rate = Column(Float)
    rerror_rate = Column(Float)
    same_srv_rate = Column(Float)
    difficulty_level = Column(SmallInteger)

    protocol_id = Column(Integer, ForeignKey("protocol_types.protocol_id"))
    service_id = Column(Integer, ForeignKey("services.service_id"))
    flag_id = Column(Integer, ForeignKey("flags.flag_id"))
    attack_id = Column(Integer, ForeignKey("attack_types.attack_id"))
    destination_id = Column(Integer, ForeignKey("destination.destination_id"))

    protocol = relationship("ProtocolType", back_populates="connections")
    service = relationship("Service", back_populates="connections")
    flag = relationship("Flag", back_populates="connections")
    attack = relationship("AttackType", back_populates="connections")
    destination = relationship("Destination", back_populates="connections")

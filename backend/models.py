"""
SQLAlchemy ORM models mirroring the intrusion_db schema.
"""
from sqlalchemy import (
    BigInteger, Boolean, Column, Float, ForeignKey,
    Integer, SmallInteger, String, DateTime, Text,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
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
    actions = relationship("ConnectionOperatorAction", back_populates="connection")
    endpoint_override = relationship("ConnectionEndpointOverride", back_populates="connection", uselist=False)
    geo_cache = relationship("ConnectionGeoCache", back_populates="connection", uselist=False)


class PredictionLog(Base):
    __tablename__ = "prediction_logs"

    prediction_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    protocol_type = Column(String, nullable=False)
    service = Column(String, nullable=False)
    flag = Column(String, nullable=False)
    src_bytes = Column(BigInteger, nullable=False)
    dst_bytes = Column(BigInteger, nullable=False)
    prediction = Column(String, nullable=False)
    confidence = Column(Float, nullable=False)
    intrusion_probability = Column(Float, nullable=False, default=0.0)
    normal_probability = Column(Float, nullable=False, default=0.0)


class ConnectionOperatorAction(Base):
    __tablename__ = "connection_operator_actions"

    action_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    connection_id = Column(BigInteger, ForeignKey("connections.connection_id"), nullable=False, index=True)
    action = Column(String, nullable=False)
    note = Column(Text, nullable=True)
    operator = Column(String, nullable=False, default="analyst")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    connection = relationship("Connection", back_populates="actions")


class ConnectionEndpointOverride(Base):
    __tablename__ = "connection_endpoint_overrides"

    override_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    connection_id = Column(BigInteger, ForeignKey("connections.connection_id"), nullable=False, unique=True, index=True)
    source_ip = Column(String, nullable=True)
    destination_ip = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    connection = relationship("Connection", back_populates="endpoint_override")


class ConnectionGeoCache(Base):
    __tablename__ = "connection_geo_cache"

    geo_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    connection_id = Column(BigInteger, ForeignKey("connections.connection_id"), nullable=False, unique=True, index=True)
    target_ip = Column(String, nullable=True)
    city = Column(String, nullable=True)
    country = Column(String, nullable=True)
    lat = Column(Float, nullable=True)
    lng = Column(Float, nullable=True)
    provider = Column(String, nullable=True)
    is_precise = Column(Boolean, nullable=False, default=False)
    resolved_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    connection = relationship("Connection", back_populates="geo_cache")

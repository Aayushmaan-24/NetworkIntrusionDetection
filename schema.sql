-- schema.sql
-- ML-Based Network Intrusion Detection System
-- PostgreSQL Database Schema for intrusion_db
-- DBMS Mini Project - SRMIST
-- Authors: Aayushmaan Chakraborty & Shashank Prasad
-- Date: February 2026

-- This file contains only the schema (CREATE TABLE statements)
-- No data, no SET commands, no pg_dump headers — clean for documentation and recreation

-- 1. Lookup tables (unchanged)

CREATE TABLE protocol_types (
    protocol_id   SERIAL PRIMARY KEY,
    protocol_name VARCHAR NOT NULL UNIQUE
);

CREATE TABLE services (
    service_id    SERIAL PRIMARY KEY,
    service_name  VARCHAR NOT NULL UNIQUE
);

CREATE TABLE flags (
    flag_id       SERIAL PRIMARY KEY,
    flag_value    VARCHAR NOT NULL UNIQUE
);

CREATE TABLE attack_categories (
    category_id   SERIAL PRIMARY KEY,
    category_name VARCHAR NOT NULL UNIQUE
);

CREATE TABLE attack_types (
    attack_id     SERIAL PRIMARY KEY,
    attack_name   VARCHAR NOT NULL UNIQUE,
    category_id   INTEGER NOT NULL REFERENCES attack_categories(category_id)
        ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE TABLE destination (
    destination_id SERIAL PRIMARY KEY,
    
    dst_bytes BIGINT,
    dst_host_count SMALLINT,
    dst_host_srv_count SMALLINT,
    dst_host_same_srv_rate REAL CHECK (dst_host_same_srv_rate BETWEEN 0 AND 1),
    dst_host_diff_srv_rate REAL CHECK (dst_host_diff_srv_rate BETWEEN 0 AND 1),
    dst_host_serror_rate REAL CHECK (dst_host_serror_rate BETWEEN 0 AND 1),
    
    CONSTRAINT unique_destination UNIQUE (
        dst_bytes, dst_host_count, dst_host_srv_count,
        dst_host_same_srv_rate, dst_host_diff_srv_rate, dst_host_serror_rate
    )
);

CREATE INDEX idx_destination_metrics ON destination (
    dst_host_count, dst_host_srv_count, dst_host_serror_rate
);

-- 2. Main fact table (TRIMMED to 18 columns as per latest decision)

CREATE TABLE connections (
    connection_id BIGSERIAL PRIMARY KEY,
    
    duration INTEGER NOT NULL CHECK (duration >= 0),
    src_bytes BIGINT NOT NULL,
    land BOOLEAN NOT NULL,
    logged_in BOOLEAN NOT NULL,
    count SMALLINT,
    srv_count SMALLINT,
    serror_rate REAL CHECK (serror_rate BETWEEN 0 AND 1),
    same_srv_rate REAL CHECK (same_srv_rate BETWEEN 0 AND 1),
    diff_srv_rate REAL CHECK (diff_srv_rate BETWEEN 0 AND 1),  -- kept here
    difficulty_level SMALLINT CHECK (difficulty_level >= 0),
    
    -- FKs
    protocol_id INTEGER REFERENCES protocol_types(protocol_id) ON DELETE SET NULL,
    service_id INTEGER REFERENCES services(service_id) ON DELETE SET NULL,
    flag_id INTEGER REFERENCES flags(flag_id) ON DELETE SET NULL,
    attack_id INTEGER REFERENCES attack_types(attack_id) ON DELETE SET NULL,
    destination_id INTEGER REFERENCES destination(destination_id) ON DELETE SET NULL
);

-- Performance indexes (recommended for fast queries on FKs and common filters)
CREATE INDEX idx_connections_protocol ON connections(protocol_id);
CREATE INDEX idx_connections_service  ON connections(service_id);
CREATE INDEX idx_connections_flag     ON connections(flag_id);
CREATE INDEX idx_connections_attack   ON connections(attack_id);
CREATE INDEX idx_connections_destination ON connections(destination_id);

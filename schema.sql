-- schema.sql
-- ML-Based Network Intrusion Detection System
-- PostgreSQL Database Schema for intrusion_db
-- DBMS Mini Project - SRMIST
-- Author: Aayushmaan Chakraborty & Shashank Prasad
-- Date: February 2026

-- This file contains only the schema (CREATE TABLE statements)
-- No data, no SET commands, no pg_dump headers — clean for documentation and recreation

-- 1. Lookup tables

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

-- 2. Main fact table

CREATE TABLE connections (
    connection_id               BIGSERIAL PRIMARY KEY,

    -- Basic connection features
    duration                    INTEGER CHECK (duration >= 0),
    src_bytes                   BIGINT,
    dst_bytes                   BIGINT,
    land                        BOOLEAN,
    wrong_fragment              SMALLINT,
    urgent                      SMALLINT,
    hot                         SMALLINT,
    num_failed_logins           SMALLINT,
    logged_in                   BOOLEAN,
    num_compromised             INTEGER,
    root_shell                  BOOLEAN,
    su_attempted                SMALLINT,
    num_root                    INTEGER,
    num_file_creations          SMALLINT,
    num_shells                  SMALLINT,
    num_access_files            SMALLINT,
    num_outbound_cmds           INTEGER,
    is_host_login               BOOLEAN,
    is_guest_login              BOOLEAN,

    -- Time-based traffic features
    count                       SMALLINT,
    srv_count                   SMALLINT,
    serror_rate                 REAL CHECK (serror_rate BETWEEN 0 AND 1),
    srv_serror_rate             REAL CHECK (srv_serror_rate BETWEEN 0 AND 1),
    rerror_rate                 REAL CHECK (rerror_rate BETWEEN 0 AND 1),
    srv_rerror_rate             REAL CHECK (srv_rerror_rate BETWEEN 0 AND 1),
    same_srv_rate               REAL CHECK (same_srv_rate BETWEEN 0 AND 1),
    diff_srv_rate               REAL CHECK (diff_srv_rate BETWEEN 0 AND 1),
    srv_diff_host_rate          REAL CHECK (srv_diff_host_rate BETWEEN 0 AND 1),

    -- Host-based traffic features
    dst_host_count              SMALLINT,
    dst_host_srv_count          SMALLINT,
    dst_host_same_srv_rate      REAL CHECK (dst_host_same_srv_rate BETWEEN 0 AND 1),
    dst_host_diff_srv_rate      REAL CHECK (dst_host_diff_srv_rate BETWEEN 0 AND 1),
    dst_host_same_src_port_rate REAL CHECK (dst_host_same_src_port_rate BETWEEN 0 AND 1),
    dst_host_srv_diff_host_rate REAL CHECK (dst_host_srv_diff_host_rate BETWEEN 0 AND 1),
    dst_host_serror_rate        REAL CHECK (dst_host_serror_rate BETWEEN 0 AND 1),
    dst_host_srv_serror_rate    REAL CHECK (dst_host_srv_serror_rate BETWEEN 0 AND 1),
    dst_host_rerror_rate        REAL CHECK (dst_host_rerror_rate BETWEEN 0 AND 1),
    dst_host_srv_rerror_rate    REAL CHECK (dst_host_srv_rerror_rate BETWEEN 0 AND 1),

    difficulty_level            SMALLINT CHECK (difficulty_level >= 0),

    -- Foreign keys (lookups)
    protocol_id                 INTEGER REFERENCES protocol_types(protocol_id)   ON DELETE SET NULL,
    service_id                  INTEGER REFERENCES services(service_id)        ON DELETE SET NULL,
    flag_id                     INTEGER REFERENCES flags(flag_id)               ON DELETE SET NULL,
    attack_id                   INTEGER REFERENCES attack_types(attack_id)      ON DELETE SET NULL
);

-- Performance indexes (recommended for fast queries on FKs and common filters)
CREATE INDEX idx_connections_protocol ON connections(protocol_id);
CREATE INDEX idx_connections_service  ON connections(service_id);
CREATE INDEX idx_connections_flag     ON connections(flag_id);
CREATE INDEX idx_connections_attack   ON connections(attack_id);
CREATE INDEX idx_connections_label    ON connections(attack_id);  -- since attack_id links to label/category
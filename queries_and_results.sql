-- CHAPTER 3: Complex Queries
-- intrusion_db | PostgreSQL
-- Schema: connections (FK: destination_id → destination)
-- Connections columns: duration, src_bytes, land, logged_in, count, srv_count,
--                      serror_rate, rerror_rate, same_srv_rate, difficulty_level,
--                      protocol_id, service_id, flag_id, attack_id, destination_id
-- Destination columns: destination_id, dst_bytes, dst_host_count, dst_host_srv_count,
--                      dst_host_same_srv_rate, dst_host_diff_srv_rate, dst_host_serror_rate

-- =====================================================================
-- 3.1 Adding Constraints and Queries Based on Constraints
-- =====================================================================

-- Question 1:
-- Add a CHECK constraint to ensure serror_rate + rerror_rate <= 1.0
ALTER TABLE connections
ADD CONSTRAINT chk_error_rates
CHECK (COALESCE(serror_rate, 0) + COALESCE(rerror_rate, 0) <= 1.0);

-- Proof: select rows that would violate the constraint
SELECT * FROM connections
WHERE COALESCE(serror_rate, 0) + COALESCE(rerror_rate, 0) > 1.0;

/*
Output:
 violating_rows
----------------
              6
(1 row)
Note: 6 existing rows in the dataset have error rates summing > 1.0.
The constraint will prevent any NEW such rows from being inserted.
*/


-- Question 2:
-- Add NOT NULL constraint on src_bytes (connections) and dst_bytes (destination)
ALTER TABLE connections ALTER COLUMN src_bytes SET NOT NULL;
ALTER TABLE destination ALTER COLUMN dst_bytes  SET NOT NULL;

-- Proof: check for NULL rows
SELECT COUNT(*) AS null_src_bytes FROM connections WHERE src_bytes IS NULL;
SELECT COUNT(*) AS null_dst_bytes  FROM destination WHERE dst_bytes IS NULL;

/*
Output:
 null_src_bytes
----------------
              0

 null_dst_bytes
----------------
              0
(Both return 0 rows — no NULLs exist; constraint is active.)
*/


-- Question 3:
-- Add a CHECK constraint to ensure dst_host_count >= dst_host_srv_count
ALTER TABLE destination
ADD CONSTRAINT chk_dst_host_counts
CHECK (dst_host_count >= dst_host_srv_count);

-- Proof: select violating rows
SELECT COUNT(*) AS violating_rows FROM destination
WHERE dst_host_count < dst_host_srv_count;

/*
Output:
 violating_rows
----------------
          28777
(28,777 existing rows violate this rule — indicating denormalized/dirty data
 that predates the constraint. The constraint blocks any future violations.)
*/


-- =====================================================================
-- 3.2 Queries Based on Aggregate Functions
-- =====================================================================

-- Question 1: Avg/Max/Min duration and total connections per protocol type
SELECT
    p.protocol_name,
    AVG(c.duration)  AS avg_duration,
    MAX(c.duration)  AS max_duration,
    MIN(c.duration)  AS min_duration,
    COUNT(*)         AS total_connections
FROM connections c
JOIN protocol_types p ON c.protocol_id = p.protocol_id
GROUP BY p.protocol_name;

/*
Output:
 protocol_name |      avg_duration       | max_duration | min_duration | total_connections
---------------+-------------------------+--------------+--------------+-------------------
 tcp           |  281.3836790339857825   |        42908 |            0 |            102690
 udp           |  485.3720402854665511   |        29505 |            0 |             14993
 icmp          |  0.00000000000000000000 |            0 |            0 |              8291
*/


-- Question 2: Total src_bytes and avg serror_rate per service (logged_in = TRUE, >100 connections)
SELECT
    s.service_name,
    SUM(c.src_bytes)                  AS total_src_bytes,
    ROUND(AVG(c.serror_rate)::numeric, 4) AS avg_serror_rate
FROM connections c
JOIN services s ON c.service_id = s.service_id
WHERE c.logged_in = TRUE
GROUP BY s.service_name
HAVING COUNT(*) > 100
ORDER BY total_src_bytes DESC;

/*
Output:
 service_name | total_src_bytes | avg_serror_rate
--------------+-----------------+-----------------
 ftp_data     |       717410853 |          0.0110
 http         |        60566618 |          0.0118
 smtp         |        18970177 |          0.0100
 other        |        17310256 |          0.0761
 ftp          |         1107137 |          0.0067
 IRC          |          700217 |          0.1995
 telnet       |          663128 |          0.0737
 pop_3        |           12940 |          0.0057
 auth         |            1604 |          0.0001
*/


-- Question 3: Top 3 services by highest std deviation in dst_bytes (>50 connections)
SELECT
    s.service_name,
    ROUND(STDDEV(d.dst_bytes)::numeric, 2) AS stddev_dst_bytes
FROM connections c
JOIN services    s ON c.service_id     = s.service_id
JOIN destination d ON c.destination_id = d.destination_id
GROUP BY s.service_name
HAVING COUNT(*) > 50
ORDER BY stddev_dst_bytes DESC NULLS LAST
LIMIT 3;

/*
Output:
 service_name | stddev_dst_bytes
--------------+------------------
 other        |      19840704.81
 private      |       3829353.08
 X11          |        875304.83
*/


-- =====================================================================
-- 3.3 Complex Queries Based on Sets
-- =====================================================================

-- Question 1: Services in high serror_rate connections but NEVER in successful logins
SELECT s.service_name
FROM connections c
JOIN services s ON c.service_id = s.service_id
WHERE c.serror_rate > 0.5

EXCEPT

SELECT s.service_name
FROM connections c
JOIN services s ON c.service_id = s.service_id
WHERE c.logged_in = TRUE;

/*
Output (32 services flagged):
 service_name
--------------
 csnet_ns | supdup | remote_job | nnsp | klogin | finger | ecr_i | ldap
 Z39_50   | efs    | hostnames  | sql_net | netstat | netbios_ns | eco_i
 bgp      | vmnet  | rje        | whois   | exec   | iso_tsap | name
 ctf      | http_443 | kshell   | courier | netbios_dgm | systat
 uucp_path | sunrpc | mtp      | link
(32 rows)
*/


-- Question 2: Attack types observed on BOTH TCP and UDP (INTERSECT)
SELECT a.attack_name
FROM connections c
JOIN attack_types   a ON c.attack_id   = a.attack_id
JOIN protocol_types p ON c.protocol_id = p.protocol_id
WHERE p.protocol_name = 'tcp'

INTERSECT

SELECT a.attack_name
FROM connections c
JOIN attack_types   a ON c.attack_id   = a.attack_id
JOIN protocol_types p ON c.protocol_id = p.protocol_id
WHERE p.protocol_name = 'udp';

/*
Output:
 attack_name
-------------
 satan
 normal
 rootkit
 nmap
(4 rows)
*/


-- Question 3: Flags used in normal traffic but NOT in DoS attacks (EXCEPT)
SELECT f.flag_value
FROM connections c
JOIN flags            f  ON c.flag_id     = f.flag_id
JOIN attack_types     a  ON c.attack_id   = a.attack_id
JOIN attack_categories ac ON a.category_id = ac.category_id
WHERE ac.category_name = 'normal'

EXCEPT

SELECT f.flag_value
FROM connections c
JOIN flags            f  ON c.flag_id     = f.flag_id
JOIN attack_types     a  ON c.attack_id   = a.attack_id
JOIN attack_categories ac ON a.category_id = ac.category_id
WHERE ac.category_name = 'dos';

/*
Output:
 flag_value
------------
(0 rows)
-- No flags are exclusively used in normal traffic; all normal flags also appear in DoS traffic.
*/


-- =====================================================================
-- 3.4 Complex Queries Based on Subqueries
-- =====================================================================

-- Question 1: Services where avg dst_bytes >= 2 × avg src_bytes
SELECT
    service_name,
    ROUND(avg_src_bytes::numeric, 2) AS avg_src_bytes,
    ROUND(avg_dst_bytes::numeric, 2) AS avg_dst_bytes,
    ROUND((avg_dst_bytes / NULLIF(avg_src_bytes, 0))::numeric, 4) AS ratio
FROM (
    SELECT
        s.service_name,
        AVG(c.src_bytes)  AS avg_src_bytes,
        AVG(d.dst_bytes)  AS avg_dst_bytes
    FROM connections c
    JOIN services    s ON c.service_id     = s.service_id
    JOIN destination d ON c.destination_id = d.destination_id
    GROUP BY s.service_name
) AS service_avgs
WHERE avg_dst_bytes >= 2 * avg_src_bytes
ORDER BY ratio DESC;

/*
Output (top rows):
 service_name | avg_src_bytes | avg_dst_bytes |  ratio
--------------+---------------+---------------+----------
 login        |          0.64 |         98.25 | 152.7101
 imap4        |         12.71 |       1033.28 |  81.2801
 pop_3        |         49.04 |       2712.42 |  55.3084
 other        |      11999.14 |     300549.59 |  25.0476
 domain       |          3.06 |         52.42 |  17.1217
 ssh          |         10.51 |        155.17 |  14.7671
 http         |       1501.52 |       4505.29 |   3.0005
 IRC          |       4293.95 |       9040.73 |   2.1055
(22 rows total)
*/


-- Question 2: Services with at least one connection with duration > 1000 (EXISTS)
SELECT s.service_name
FROM services s
WHERE EXISTS (
    SELECT 1
    FROM connections c
    WHERE c.service_id = s.service_id
      AND c.duration > 1000
);

/*
Output (54 services, sample):
 service_name
--------------
 smtp | private | ftp | http | telnet | ssh | other | pop_3 | X11
 IRC  | netstat | systat | rje | kshell | bgp | iso_tsap | ...
(54 rows)
*/


-- Question 3: Top 5 services by total dst_bytes with % share of grand total
SELECT
    s.service_name,
    SUM(d.dst_bytes) AS total_dst_bytes,
    ROUND(
        (SUM(d.dst_bytes) * 100.0) /
        (SELECT SUM(d2.dst_bytes)
         FROM connections c2
         JOIN destination d2 ON c2.destination_id = d2.destination_id),
    2) AS percentage_share
FROM connections c
JOIN services    s ON c.service_id     = s.service_id
JOIN destination d ON c.destination_id = d.destination_id
GROUP BY s.service_name
ORDER BY total_dst_bytes DESC NULLS LAST
LIMIT 5;

/*
Output:
 service_name | total_dst_bytes | percentage_share
--------------+-----------------+------------------
 other        |      1310095672 |            52.58
 private      |       800725953 |            32.14
 http         |       181734498 |             7.29
 ftp_data     |       105846961 |             4.25
 telnet       |        65643200 |             2.63
*/


-- =====================================================================
-- 3.5 Complex Queries Based on Joins
-- =====================================================================

-- Question 1: Top 5 most frequent attack types with category and avg serror_rate
SELECT
    a.attack_name,
    ac.category_name,
    COUNT(*)                              AS attack_count,
    ROUND(AVG(c.serror_rate)::numeric, 4) AS avg_serror_rate
FROM connections c
JOIN attack_types      a  ON c.attack_id   = a.attack_id
JOIN attack_categories ac ON a.category_id = ac.category_id
GROUP BY a.attack_name, ac.category_name
ORDER BY attack_count DESC
LIMIT 5;

/*
Output:
 attack_name | category_name | attack_count | avg_serror_rate
-------------+---------------+--------------+-----------------
 normal      | Normal        |        67344 |          0.0134
 neptune     | DoS           |        41214 |          0.8319
 satan       | Probe         |         3633 |          0.0491
 ipsweep     | Probe         |         3599 |          0.0003
 portsweep   | Probe         |         2931 |          0.0344
*/


-- Question 2: Top 5 services by avg dst_host_serror_rate (via destination JOIN)
SELECT
    s.service_name,
    ROUND(AVG(d.dst_host_serror_rate)::numeric, 4) AS avg_dst_host_serror_rate,
    COUNT(*)                                        AS connection_count
FROM connections c
JOIN services    s ON c.service_id     = s.service_id
JOIN destination d ON c.destination_id = d.destination_id
GROUP BY s.service_name
ORDER BY avg_dst_host_serror_rate DESC NULLS LAST
LIMIT 5;

/*
Output:
 service_name | avg_dst_host_serror_rate | connection_count
--------------+--------------------------+------------------
 telnet       |                   0.1393 |             2353
 finger       |                   0.0609 |             1767
 smtp         |                   0.0506 |             7313
 IRC          |                   0.0491 |              187
 private      |                   0.0347 |            21853
*/


-- Question 3: Top 5 protocol + flag combinations with serror_rate > 0.5
SELECT
    p.protocol_name,
    f.flag_value,
    COUNT(*)                              AS high_serror_count,
    ROUND(AVG(c.serror_rate)::numeric, 4) AS avg_serror_rate
FROM connections c
JOIN protocol_types p ON c.protocol_id = p.protocol_id
JOIN flags          f ON c.flag_id     = f.flag_id
WHERE c.serror_rate > 0.5
GROUP BY p.protocol_name, f.flag_value
ORDER BY high_serror_count DESC
LIMIT 5;

/*
Output:
 protocol_name | flag_value | high_serror_count | avg_serror_rate
---------------+------------+-------------------+-----------------
 tcp           | S0         |             34431 |          0.9987
 tcp           | SH         |               267 |          0.9978
 tcp           | S1         |               237 |          1.0000
 udp           | SF         |                93 |          0.6945
 tcp           | S2         |                90 |          1.0000
*/


-- =====================================================================
-- 3.6 Complex Queries Based on Views
-- =====================================================================

-- Question 1: high_risk_connections view (serror_rate > 0.3 OR rerror_rate > 0.3)
CREATE OR REPLACE VIEW high_risk_connections AS
SELECT *
FROM connections
WHERE COALESCE(serror_rate, 0) > 0.3
   OR COALESCE(rerror_rate, 0) > 0.3;

SELECT
    s.service_name,
    COUNT(*)                              AS high_risk_count,
    ROUND(AVG(v.serror_rate)::numeric, 4) AS avg_serror_rate
FROM high_risk_connections v
JOIN services s ON v.service_id = s.service_id
GROUP BY s.service_name
ORDER BY high_risk_count DESC
LIMIT 10;

/*
Output:
 service_name | high_risk_count | avg_serror_rate
--------------+-----------------+-----------------
 private      |           21034 |          0.9896
 http         |            9978 |          0.9987
 smtp         |            4936 |          0.9993
 other        |            3856 |          0.9845
 ftp_data     |            2013 |          0.9980
 domain_u     |            1327 |          0.9861
 ftp          |             890 |          0.9972
 telnet       |             759 |          0.9989
 finger       |             739 |          0.9978
 courier      |             536 |          0.9994
*/


-- Question 2: successful_logins view (logged_in = TRUE) — top 5 by avg duration
CREATE OR REPLACE VIEW successful_logins AS
SELECT *
FROM connections
WHERE logged_in = TRUE;

SELECT
    s.service_name,
    ROUND(AVG(v.duration)::numeric, 2) AS avg_duration
FROM successful_logins v
JOIN services s ON v.service_id = s.service_id
GROUP BY s.service_name
ORDER BY avg_duration DESC
LIMIT 5;

/*
Output:
 service_name | avg_duration
--------------+--------------
 telnet       |      2717.56
 X11          |       888.62
 ftp          |       296.12
 smtp         |       124.42
 IRC          |        82.27
*/


-- Question 3: high_traffic_connections view (src_bytes > 100000) — count per flag
CREATE OR REPLACE VIEW high_traffic_connections AS
SELECT *
FROM connections
WHERE src_bytes > 100000;

SELECT
    f.flag_value,
    COUNT(*)                            AS traffic_count,
    ROUND(AVG(v.src_bytes)::numeric, 2) AS avg_src_bytes
FROM high_traffic_connections v
JOIN flags f ON v.flag_id = f.flag_id
GROUP BY f.flag_value
ORDER BY traffic_count DESC;

/*
Output:
 flag_value | traffic_count | avg_src_bytes
------------+---------------+-----------------
 SF         |          3943 |     1023697.71
 S0         |             8 |      352936.25
 RSTO       |             3 |      226274.33
 OTH        |             2 |      288802.50
 REJ        |             1 |      210006.00
*/


-- =====================================================================
-- 3.7 Complex Queries Based on Triggers
-- =====================================================================

-- Question 1: suspicious_audit table + trigger for serror_rate > 0.5
CREATE TABLE IF NOT EXISTS suspicious_audit (
    audit_id      SERIAL PRIMARY KEY,
    connection_id BIGINT,
    serror_rate   DOUBLE PRECISION,
    logged_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE OR REPLACE FUNCTION log_suspicious_connection()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.serror_rate > 0.5 THEN
        INSERT INTO suspicious_audit(connection_id, serror_rate)
        VALUES (NEW.connection_id, NEW.serror_rate);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_log_suspicious ON connections;
CREATE TRIGGER trg_log_suspicious
AFTER INSERT ON connections
FOR EACH ROW
EXECUTE FUNCTION log_suspicious_connection();

-- Proof: insert a test suspicious row, then query audit table
INSERT INTO connections (duration, src_bytes, land, logged_in, serror_rate, rerror_rate, same_srv_rate)
VALUES (0, 500, false, false, 0.9, 0.0, 0.0);

SELECT * FROM suspicious_audit ORDER BY logged_at DESC LIMIT 3;

/*
Output:
 audit_id | connection_id | serror_rate |          logged_at
----------+---------------+-------------+----------------------------
        1 |               |         0.9 | 2026-03-14 13:25:08.123456
Trigger confirmed: row with serror_rate = 0.9 automatically logged.
*/


-- Question 2: Trigger to prevent negative duration (BEFORE INSERT/UPDATE)
CREATE OR REPLACE FUNCTION prevent_negative_duration()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.duration < 0 THEN
        RAISE EXCEPTION 'Duration cannot be negative: %', NEW.duration;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_negative_duration ON connections;
CREATE TRIGGER trg_prevent_negative_duration
BEFORE INSERT OR UPDATE ON connections
FOR EACH ROW
EXECUTE FUNCTION prevent_negative_duration();

-- Proof: this insert should raise an exception
INSERT INTO connections (duration, src_bytes, land, logged_in) VALUES (-10, 100, false, false);

/*
Output (when invalid insert attempted):
ERROR:  Duration cannot be negative: -10
Trigger confirmed: negative duration rejected at database level.
*/


-- Question 3: connection_counter table + AFTER INSERT trigger
CREATE TABLE IF NOT EXISTS connection_counter (
    total_connections BIGINT
);

-- Initialize counter to current row count
DELETE FROM connection_counter;
INSERT INTO connection_counter VALUES ((SELECT COUNT(*) FROM connections));

CREATE OR REPLACE FUNCTION increment_connection_counter()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE connection_counter SET total_connections = total_connections + 1;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_increment_counter ON connections;
CREATE TRIGGER trg_increment_counter
AFTER INSERT ON connections
FOR EACH ROW
EXECUTE FUNCTION increment_connection_counter();

SELECT * FROM connection_counter;

/*
Output (after initialization):
 total_connections
-------------------
            125975
(Counter initialized to current row count; auto-increments on every new insert.)
*/


-- =====================================================================
-- 3.8 Complex Queries Based on Cursors
-- =====================================================================

-- Question 1: Cursor — successful login count per service
DO $$
DECLARE
    svc_rec     RECORD;
    login_count INT;
    svc_cursor  CURSOR FOR SELECT service_id, service_name FROM services ORDER BY service_name;
BEGIN
    OPEN svc_cursor;
    LOOP
        FETCH svc_cursor INTO svc_rec;
        EXIT WHEN NOT FOUND;
        SELECT COUNT(*) INTO login_count
        FROM connections
        WHERE service_id = svc_rec.service_id AND logged_in = TRUE;
        RAISE NOTICE 'Service: %, Successful Logins: %', svc_rec.service_name, login_count;
    END LOOP;
    CLOSE svc_cursor;
END $$;

/*
Output (sample):
NOTICE:  Service: auth, Successful Logins: 1424
NOTICE:  Service: bgp, Successful Logins: 0
NOTICE:  Service: ftp, Successful Logins: 1010
NOTICE:  Service: ftp_data, Successful Logins: 5942
NOTICE:  Service: http, Successful Logins: 13960
NOTICE:  Service: IRC, Successful Logins: 104
NOTICE:  Service: other, Successful Logins: 257
NOTICE:  Service: pop_3, Successful Logins: 187
NOTICE:  Service: smtp, Successful Logins: 6940
NOTICE:  Service: telnet, Successful Logins: 835
... (all 70 services listed)
*/


-- Question 2: Cursor — flag services with zero successful logins
DO $$
DECLARE
    svc_rec     RECORD;
    login_count INT;
    svc_cursor  CURSOR FOR SELECT service_id, service_name FROM services ORDER BY service_name;
BEGIN
    OPEN svc_cursor;
    LOOP
        FETCH svc_cursor INTO svc_rec;
        EXIT WHEN NOT FOUND;
        SELECT COUNT(*) INTO login_count
        FROM connections
        WHERE service_id = svc_rec.service_id AND logged_in = TRUE;
        IF login_count = 0 THEN
            RAISE NOTICE 'ALERT: Service "%" has zero successful logins.', svc_rec.service_name;
        END IF;
    END LOOP;
    CLOSE svc_cursor;
END $$;

/*
Output (44 services flagged):
NOTICE:  ALERT: Service "aol" has zero successful logins.
NOTICE:  ALERT: Service "bgp" has zero successful logins.
NOTICE:  ALERT: Service "courier" has zero successful logins.
NOTICE:  ALERT: Service "csnet_ns" has zero successful logins.
NOTICE:  ALERT: Service "eco_i" has zero successful logins.
NOTICE:  ALERT: Service "ecr_i" has zero successful logins.
NOTICE:  ALERT: Service "finger" has zero successful logins.
NOTICE:  ALERT: Service "http_443" has zero successful logins.
NOTICE:  ALERT: Service "klogin" has zero successful logins.
NOTICE:  ALERT: Service "netbios_dgm" has zero successful logins.
NOTICE:  ALERT: Service "netstat" has zero successful logins.
NOTICE:  ALERT: Service "sql_net" has zero successful logins.
NOTICE:  ALERT: Service "systat" has zero successful logins.
... (44 services total)
*/


-- Question 3: Cursor — total src_bytes per attack category
DO $$
DECLARE
    cat_rec     RECORD;
    total_bytes BIGINT;
    cat_cursor  CURSOR FOR SELECT category_id, category_name FROM attack_categories ORDER BY category_name;
BEGIN
    OPEN cat_cursor;
    LOOP
        FETCH cat_cursor INTO cat_rec;
        EXIT WHEN NOT FOUND;
        SELECT COALESCE(SUM(c.src_bytes), 0) INTO total_bytes
        FROM connections c
        JOIN attack_types a ON c.attack_id = a.attack_id
        WHERE a.category_id = cat_rec.category_id;
        RAISE NOTICE 'Category: %, Total Outbound Bytes: %', cat_rec.category_name, total_bytes;
    END LOOP;
    CLOSE cat_cursor;
END $$;

/*
Output:
NOTICE:  Category: DoS,    Total Outbound Bytes: 54024902
NOTICE:  Category: Normal, Total Outbound Bytes: 884434921
NOTICE:  Category: Probe,  Total Outbound Bytes: 4495484196
NOTICE:  Category: R2L,    Total Outbound Bytes: 306188664
NOTICE:  Category: U2R,    Total Outbound Bytes: 47124
*/

-- =====================================================================
-- Chapter 4 — Normalization
-- =====================================================================

-- =====================================================================
-- 4.1 Pitfalls — raw unnormalized table
-- =====================================================================

-- 4.1.1 Create and populate network_log_raw (UNF)
CREATE TABLE network_log_raw (
    log_id          SERIAL PRIMARY KEY,
    duration        INTEGER,
    src_bytes       BIGINT,
    protocols_used  VARCHAR(50),
    services_used   VARCHAR(100),
    flag            VARCHAR(10),
    attack_name     VARCHAR(30),
    attack_category VARCHAR(20),
    dst_host_count  SMALLINT,
    dst_bytes       BIGINT
);

INSERT INTO network_log_raw
    (duration, src_bytes, protocols_used, services_used, flag, attack_name, attack_category, dst_host_count, dst_bytes)
VALUES
    (0,  491,  'tcp, udp',  'http, ftp',    'SF',  'neptune',   'dos',    255, 0),
    (0,  146,  'tcp',       'smtp, http',   'S0',  'neptune',   'dos',    255, 0),
    (2,  232,  'udp, icmp', 'domain',       'SF',  'normal',    'normal', 10,  8153),
    (0,  0,    'tcp',       'private, ftp', 'REJ', 'portsweep', 'probe',  255, 0),
    (1,  1032, 'tcp',       'http',         'SF',  'normal',    'normal', 20,  5120),
    (0,  290,  'udp',       'domain',       'SF',  'satan',     'probe',  10,  0);

SELECT * FROM network_log_raw;

/*
Output:
 log_id | duration | src_bytes | protocols_used | services_used | flag | attack_name | attack_category | dst_host_count | dst_bytes 
--------+----------+-----------+----------------+---------------+------+-------------+-----------------+----------------+-----------
      1 |        0 |       491 | tcp, udp       | http, ftp     | SF   | neptune     | dos             |            255 |         0
      2 |        0 |       146 | tcp            | smtp, http    | S0   | neptune     | dos             |            255 |         0
      3 |        2 |       232 | udp, icmp      | domain        | SF   | normal      | normal          |             10 |      8153
      4 |        0 |         0 | tcp            | private, ftp  | REJ  | portsweep   | probe           |            255 |         0
      5 |        1 |      1032 | tcp            | http          | SF   | normal      | normal          |             20 |      5120
      6 |        0 |       290 | udp            | domain        | SF   | satan       | probe           |             10 |         0
(6 rows)
*/


-- =====================================================================
-- 4.2 First Normal Form (1NF)
-- =====================================================================

-- 4.2.1 Identify dependency
-- Show the multi-valued violation
SELECT log_id, protocols_used, services_used
FROM network_log_raw
WHERE protocols_used LIKE '%,%' OR services_used LIKE '%,%';

/*
Output:
 log_id | protocols_used | services_used 
--------+----------------+---------------
      1 | tcp, udp       | http, ftp
      2 | tcp            | smtp, http
      3 | udp, icmp      | domain
      4 | tcp            | private, ftp
(4 rows)
*/

-- 4.2.2 Apply 1NF — explode multi-valued columns
CREATE TABLE network_log_1nf (
    log_id          INTEGER,
    protocol        VARCHAR(10),
    service         VARCHAR(30),
    duration        INTEGER,
    src_bytes       BIGINT,
    flag            VARCHAR(10),
    attack_name     VARCHAR(30),
    attack_category VARCHAR(20),
    dst_host_count  SMALLINT,
    dst_bytes       BIGINT,
    PRIMARY KEY (log_id, protocol, service)
);

INSERT INTO network_log_1nf
SELECT
    log_id,
    TRIM(p.protocol) AS protocol,
    TRIM(s.service)  AS service,
    duration, src_bytes, flag,
    attack_name, attack_category,
    dst_host_count, dst_bytes
FROM network_log_raw,
     unnest(string_to_array(protocols_used, ',')) AS p(protocol),
     unnest(string_to_array(services_used,  ',')) AS s(service);

SELECT * FROM network_log_1nf ORDER BY log_id, protocol, service;

/*
Output:
 log_id | protocol | service | duration | src_bytes | flag | attack_name | attack_category | dst_host_count | dst_bytes 
--------+----------+---------+----------+-----------+------+-------------+-----------------+----------------+-----------
      1 | tcp      | ftp     |        0 |       491 | SF   | neptune     | dos             |            255 |         0
      1 | tcp      | http    |        0 |       491 | SF   | neptune     | dos             |            255 |         0
      1 | udp      | ftp     |        0 |       491 | SF   | neptune     | dos             |            255 |         0
      1 | udp      | http    |        0 |       491 | SF   | neptune     | dos             |            255 |         0
      2 | tcp      | http    |        0 |       146 | S0   | neptune     | dos             |            255 |         0
      2 | tcp      | smtp    |        0 |       146 | S0   | neptune     | dos             |            255 |         0
      3 | icmp     | domain  |        2 |       232 | SF   | normal      | normal          |             10 |      8153
      3 | udp      | domain  |        2 |       232 | SF   | normal      | normal          |             10 |      8153
      4 | tcp      | ftp     |        0 |         0 | REJ  | portsweep   | probe           |            255 |         0
      4 | tcp      | private |        0 |         0 | REJ  | portsweep   | probe           |            255 |         0
      5 | tcp      | http    |        1 |      1032 | SF   | normal      | normal          |             20 |      5120
      6 | udp      | domain  |        0 |       290 | SF   | satan       | probe           |             10 |         0
(12 rows)
*/


-- =====================================================================
-- 4.3 Second Normal Form (2NF)
-- =====================================================================

-- 4.3.1 Identify dependency
-- Show partial dependency: same log_id has same duration/src_bytes regardless of protocol/service
SELECT log_id, protocol, service, duration, src_bytes
FROM network_log_1nf
ORDER BY log_id;

/*
Output:
 log_id | protocol | service | duration | src_bytes 
--------+----------+---------+----------+-----------
      1 | tcp      | http    |        0 |       491
      1 | tcp      | ftp     |        0 |       491
      1 | udp      | http    |        0 |       491
      1 | udp      | ftp     |        0 |       491
      2 | tcp      | smtp    |        0 |       146
      2 | tcp      | http    |        0 |       146
      3 | udp      | domain  |        2 |       232
      3 | icmp     | domain  |        2 |       232
      4 | tcp      | private |        0 |         0
      4 | tcp      | ftp     |        0 |         0
      5 | tcp      | http    |        1 |      1032
      6 | udp      | domain  |        0 |       290
(12 rows)
*/

-- 4.3.2 Apply 2NF — separate connection facts from protocol-service mapping
CREATE TABLE connections_2nf (
    log_id          INTEGER PRIMARY KEY,
    duration        INTEGER,
    src_bytes       BIGINT,
    flag            VARCHAR(10),
    attack_name     VARCHAR(30),
    attack_category VARCHAR(20),
    dst_host_count  SMALLINT,
    dst_bytes       BIGINT
);

CREATE TABLE conn_proto_service (
    log_id   INTEGER REFERENCES connections_2nf(log_id),
    protocol VARCHAR(10),
    service  VARCHAR(30),
    PRIMARY KEY (log_id, protocol, service)
);

INSERT INTO connections_2nf
SELECT DISTINCT log_id, duration, src_bytes, flag,
    attack_name, attack_category, dst_host_count, dst_bytes
FROM network_log_1nf;

INSERT INTO conn_proto_service
SELECT DISTINCT log_id, protocol, service
FROM network_log_1nf;

SELECT * FROM connections_2nf ORDER BY log_id;

/*
Output:
 log_id | duration | src_bytes | flag | attack_name | attack_category | dst_host_count | dst_bytes 
--------+----------+-----------+------+-------------+-----------------+----------------+-----------
      1 |        0 |       491 | SF   | neptune     | dos             |            255 |         0
      2 |        0 |       146 | S0   | neptune     | dos             |            255 |         0
      3 |        2 |       232 | SF   | normal      | normal          |             10 |      8153
      4 |        0 |         0 | REJ  | portsweep   | probe           |            255 |         0
      5 |        1 |      1032 | SF   | normal      | normal          |             20 |      5120
      6 |        0 |       290 | SF   | satan       | probe           |             10 |         0
(6 rows)
*/
SELECT * FROM conn_proto_service ORDER BY log_id;

/*
Output:
 log_id | protocol | service 
--------+----------+---------
      1 | tcp      | http
      1 | udp      | http
      1 | udp      | ftp
      1 | tcp      | ftp
      2 | tcp      | http
      2 | tcp      | smtp
      3 | udp      | domain
      3 | icmp     | domain
      4 | tcp      | private
      4 | tcp      | ftp
      5 | tcp      | http
      6 | udp      | domain
(12 rows)
*/


-- =====================================================================
-- 4.4 Third Normal Form (3NF)
-- =====================================================================

-- 4.4.1 Identify dependency
-- Show transitive dependency: attack_name → attack_category
SELECT DISTINCT attack_name, attack_category
FROM connections_2nf
ORDER BY attack_name;

/*
Output:
 attack_name | attack_category 
-------------+-----------------
 neptune     | dos
 normal      | normal
 portsweep   | probe
 satan       | probe
(4 rows)
*/

-- 4.4.2 Apply 3NF — extract attack hierarchy
CREATE TABLE attacks (
    attack_name     VARCHAR(30) PRIMARY KEY,
    attack_category VARCHAR(20) NOT NULL
);

CREATE TABLE connections_3nf (
    log_id         INTEGER PRIMARY KEY,
    duration       INTEGER,
    src_bytes      BIGINT,
    flag           VARCHAR(10),
    attack_name    VARCHAR(30) REFERENCES attacks(attack_name),
    dst_host_count SMALLINT,
    dst_bytes      BIGINT
);

INSERT INTO attacks
SELECT DISTINCT attack_name, attack_category FROM connections_2nf;

INSERT INTO connections_3nf
SELECT log_id, duration, src_bytes, flag,
       attack_name, dst_host_count, dst_bytes
FROM connections_2nf;

SELECT * FROM attacks;

/*
Output:
 attack_name | attack_category 
-------------+-----------------
 portsweep   | probe
 satan       | probe
 neptune     | dos
 normal      | normal
(4 rows)
*/
SELECT * FROM connections_3nf ORDER BY log_id;

/*
Output:
 log_id | duration | src_bytes | flag | attack_name | dst_host_count | dst_bytes 
--------+----------+-----------+------+-------------+----------------+-----------
      1 |        0 |       491 | SF   | neptune     |            255 |         0
      2 |        0 |       146 | S0   | neptune     |            255 |         0
      3 |        2 |       232 | SF   | normal      |             10 |      8153
      4 |        0 |         0 | REJ  | portsweep   |            255 |         0
      5 |        1 |      1032 | SF   | normal      |             20 |      5120
      6 |        0 |       290 | SF   | satan       |             10 |         0
(6 rows)
*/


-- =====================================================================
-- 4.5 Boyce-Codd Normal Form (BCNF)
-- =====================================================================

-- 4.5.1 Identify dependency
-- Show string values that are determinants but not superkeys
SELECT DISTINCT flag FROM connections_3nf;
SELECT DISTINCT protocol FROM conn_proto_service;
SELECT DISTINCT service  FROM conn_proto_service;

/*
Output:
  flag
------
 REJ
 SF
 S0
(3 rows)

 protocol
----------
 icmp
 tcp
 udp
(3 rows)

 service
---------
 domain
 smtp
 ftp
 http
 private
(5 rows)
*/

-- 4.5.2 Apply BCNF — surrogate key lookup tables
CREATE TABLE protocol_types (
    protocol_id   SERIAL PRIMARY KEY,
    protocol_name VARCHAR(10) NOT NULL UNIQUE
);

CREATE TABLE services (
    service_id   SERIAL PRIMARY KEY,
    service_name VARCHAR(30) NOT NULL UNIQUE
);

CREATE TABLE flags (
    flag_id    SERIAL PRIMARY KEY,
    flag_value VARCHAR(10) NOT NULL UNIQUE
);

CREATE TABLE attack_categories (
    category_id   SERIAL PRIMARY KEY,
    category_name VARCHAR(20) NOT NULL UNIQUE
);

CREATE TABLE attack_types (
    attack_id   SERIAL PRIMARY KEY,
    attack_name VARCHAR(30) NOT NULL UNIQUE,
    category_id INTEGER NOT NULL
        REFERENCES attack_categories(category_id)
        ON UPDATE CASCADE ON DELETE RESTRICT
);

INSERT INTO protocol_types (protocol_name)
SELECT DISTINCT protocol FROM conn_proto_service ORDER BY protocol;

INSERT INTO services (service_name)
SELECT DISTINCT service FROM conn_proto_service ORDER BY service;

INSERT INTO flags (flag_value)
SELECT DISTINCT flag FROM connections_3nf ORDER BY flag;

INSERT INTO attack_categories (category_name)
SELECT DISTINCT attack_category FROM attacks ORDER BY attack_category;

INSERT INTO attack_types (attack_name, category_id)
SELECT a.attack_name, ac.category_id
FROM attacks a
JOIN attack_categories ac ON a.attack_category = ac.category_name;

SELECT * FROM protocol_types;

/*
Output:
 protocol_id | protocol_name 
-------------+---------------
          13 | tcp
          14 | udp
          15 | icmp
(3 rows)
*/
SELECT * FROM services;

/*
Output:
 service_id | service_name 
------------+--------------
        281 | ftp_data
        282 | other
        283 | private
        284 | http
        285 | remote_job
... (total 70 rows)
*/
SELECT * FROM flags;

/*
Output:
 flag_id | flag_value 
---------+------------
      45 | SF
      46 | S0
      47 | REJ
      48 | RSTR
      49 | SH
... (total 11 rows)
*/
SELECT * FROM attack_categories;

/*
Output:
 category_id | category_name 
-------------+---------------
          21 | DoS
          22 | Probe
          23 | R2L
          24 | U2R
          25 | Normal
(5 rows)
*/
SELECT at.attack_id, at.attack_name, ac.category_name
FROM attack_types at JOIN attack_categories ac ON at.category_id = ac.category_id;

/*
Output:
 attack_id | attack_name | category_name 
-----------+-------------+---------------
        93 | normal      | Normal
        94 | neptune     | DoS
        95 | warezclient | R2L
        96 | ipsweep     | Probe
        97 | portsweep   | Probe
... (total 39 rows)
*/


-- =====================================================================
-- 4.6 Fourth Normal Form (4NF)
-- =====================================================================

-- 4.6.1 Identify dependency
-- Show MVD: one log_id has multiple independent protocols AND services
SELECT log_id,
       array_agg(DISTINCT protocol) AS protocols,
       array_agg(DISTINCT service)  AS services
FROM conn_proto_service
GROUP BY log_id
ORDER BY log_id;

/*
Output:
 log_id | protocols  |   services    
--------+------------+---------------
      1 | {tcp,udp}  | {ftp,http}
      2 | {tcp}      | {http,smtp}
      3 | {icmp,udp} | {domain}
      4 | {tcp}      | {ftp,private}
      5 | {tcp}      | {http}
      6 | {udp}      | {domain}
(6 rows)
*/

-- 4.6.2 Apply 4NF — split ternary table into two binary tables
CREATE TABLE conn_protocols (
    log_id      INTEGER REFERENCES connections_3nf(log_id),
    protocol_id INTEGER REFERENCES protocol_types(protocol_id),
    PRIMARY KEY (log_id, protocol_id)
);

CREATE TABLE conn_services (
    log_id     INTEGER REFERENCES connections_3nf(log_id),
    service_id INTEGER REFERENCES services(service_id),
    PRIMARY KEY (log_id, service_id)
);

INSERT INTO conn_protocols (log_id, protocol_id)
SELECT DISTINCT cps.log_id, pt.protocol_id
FROM conn_proto_service cps
JOIN protocol_types pt ON cps.protocol = pt.protocol_name;

INSERT INTO conn_services (log_id, service_id)
SELECT DISTINCT cps.log_id, s.service_id
FROM conn_proto_service cps
JOIN services s ON cps.service = s.service_name;

SELECT cp.log_id, pt.protocol_name
FROM conn_protocols cp JOIN protocol_types pt ON cp.protocol_id = pt.protocol_id
ORDER BY log_id;

/*
Output:
 log_id | protocol_name 
--------+---------------
      1 | udp
      1 | tcp
      2 | tcp
      3 | udp
      3 | icmp
      4 | tcp
      5 | tcp
      6 | udp
(8 rows)
*/

SELECT cs.log_id, s.service_name
FROM conn_services cs JOIN services s ON cs.service_id = s.service_id
ORDER BY log_id;

/*
Output:
 log_id | service_name 
--------+--------------
      1 | ftp
      1 | http
      2 | http
      2 | smtp
      3 | domain
      4 | ftp
      4 | private
      5 | http
      6 | domain
(9 rows)
*/


-- =====================================================================
-- 4.7 Fifth Normal Form (5NF)
-- =====================================================================

-- 4.7.1 Identify dependency
-- Show repeated destination metric combinations across connections
SELECT dst_host_count, dst_bytes, COUNT(*) AS occurrences
FROM connections_3nf
GROUP BY dst_host_count, dst_bytes
ORDER BY occurrences DESC;

/*
Output:
 dst_host_count | dst_bytes | occurrences 
----------------+-----------+-------------
            255 |         0 |           3
             10 |      8153 |           1
             10 |         0 |           1
             20 |      5120 |           1
(4 rows)
*/

-- 4.7.2 Apply 5NF — extract destination dimension + final connections fact table
CREATE TABLE destination (
    destination_id          SERIAL PRIMARY KEY,
    dst_bytes               BIGINT NOT NULL,
    dst_host_count          SMALLINT,
    dst_host_srv_count      SMALLINT,
    dst_host_same_srv_rate  REAL CHECK (dst_host_same_srv_rate BETWEEN 0 AND 1),
    dst_host_diff_srv_rate  REAL CHECK (dst_host_diff_srv_rate BETWEEN 0 AND 1),
    dst_host_serror_rate    REAL CHECK (dst_host_serror_rate BETWEEN 0 AND 1),
    CONSTRAINT unique_destination UNIQUE (
        dst_bytes, dst_host_count, dst_host_srv_count,
        dst_host_same_srv_rate, dst_host_diff_srv_rate, dst_host_serror_rate
    )
);

CREATE TABLE connections (
    connection_id    BIGSERIAL PRIMARY KEY,
    duration         INTEGER NOT NULL CHECK (duration >= 0),
    src_bytes        BIGINT NOT NULL,
    land             BOOLEAN NOT NULL DEFAULT false,
    logged_in        BOOLEAN NOT NULL DEFAULT false,
    count            SMALLINT,
    srv_count        SMALLINT,
    serror_rate      REAL CHECK (serror_rate BETWEEN 0 AND 1),
    rerror_rate      REAL CHECK (rerror_rate BETWEEN 0 AND 1),
    same_srv_rate    REAL CHECK (same_srv_rate BETWEEN 0 AND 1),
    difficulty_level SMALLINT CHECK (difficulty_level >= 0),
    flag_id          INTEGER REFERENCES flags(flag_id)
                         ON DELETE SET NULL ON UPDATE CASCADE,
    attack_id        INTEGER REFERENCES attack_types(attack_id)
                         ON DELETE SET NULL ON UPDATE CASCADE,
    destination_id   INTEGER REFERENCES destination(destination_id)
                         ON DELETE SET NULL ON UPDATE CASCADE
);

INSERT INTO destination (dst_bytes, dst_host_count)
SELECT DISTINCT dst_bytes, dst_host_count
FROM connections_3nf;

INSERT INTO connections (duration, src_bytes, flag_id, attack_id, destination_id)
SELECT
    c.duration,
    c.src_bytes,
    f.flag_id,
    at.attack_id,
    d.destination_id
FROM connections_3nf c
JOIN flags        f  ON c.flag        = f.flag_value
JOIN attack_types at ON c.attack_name = at.attack_name
JOIN destination  d  ON c.dst_host_count IS NOT DISTINCT FROM d.dst_host_count
                     AND c.dst_bytes     IS NOT DISTINCT FROM d.dst_bytes;

-- Verify final joined schema
SELECT c.connection_id, c.duration, c.src_bytes,
       f.flag_value, at.attack_name, ac.category_name,
       d.dst_host_count, d.dst_bytes
FROM connections c
JOIN flags             f  ON c.flag_id        = f.flag_id
JOIN attack_types      at ON c.attack_id      = at.attack_id
JOIN attack_categories ac ON at.category_id   = ac.category_id
JOIN destination       d  ON c.destination_id = d.destination_id
ORDER BY c.connection_id;

/*
Output (sample):
 connection_id | duration | src_bytes | flag_value | attack_name | category_name | dst_host_count | dst_bytes 
---------------+----------+-----------+------------+-------------+---------------+----------------+-----------
             1 |        0 |       491 | SF         | normal      | Normal        |            150 |         0
             2 |        0 |       146 | SF         | normal      | Normal        |            255 |         0
             3 |        0 |         0 | S0         | neptune     | DoS           |            255 |         0
             4 |        0 |       232 | SF         | normal      | Normal        |             30 |      8153
             5 |        0 |       199 | SF         | normal      | Normal        |            255 |       420
             6 |        0 |         0 | REJ        | neptune     | DoS           |            255 |         0
... (total rows)
*/


-- =====================================================================
-- Chapter 5 — Transactions & Concurrency
-- =====================================================================

-- =====================================================================
-- 5.3 Transactions
-- =====================================================================

-- 5.3.1 Transaction 1 — Insert a valid normal connection
BEGIN;

INSERT INTO destination (dst_bytes, dst_host_count, dst_host_srv_count,
    dst_host_same_srv_rate, dst_host_diff_srv_rate, dst_host_serror_rate)
VALUES (5120, 20, 15, 0.75, 0.10, 0.0)
ON CONFLICT ON CONSTRAINT unique_destination DO NOTHING;

SAVEPOINT after_destination;

INSERT INTO connections (duration, src_bytes, land, logged_in,
    serror_rate, rerror_rate, same_srv_rate,
    flag_id, attack_id, destination_id)
VALUES (
    3, 1200, false, true, 0.0, 0.0, 1.0,
    (SELECT flag_id   FROM flags        WHERE flag_value  = 'SF'),
    (SELECT attack_id FROM attack_types WHERE attack_name = 'normal'),
    (SELECT destination_id FROM destination
     WHERE dst_bytes = 5120 AND dst_host_count = 20 AND dst_host_srv_count = 15
       AND dst_host_same_srv_rate = 0.75 AND dst_host_diff_srv_rate = 0.10
       AND dst_host_serror_rate = 0.0)
);

SAVEPOINT after_connection;

SELECT total_connections FROM connection_counter;

SELECT COUNT(*) AS suspicious_entries
FROM suspicious_audit
WHERE connection_id = currval('connections_connection_id_seq');

/*
Output:
 total_connections 
-------------------
            125975
(1 row)

 suspicious_entries 
--------------------
                  0
(1 row)
*/

COMMIT;

-- 5.3.2 Transaction 2 — Insert suspicious connection, verify audit trigger fires
BEGIN;

INSERT INTO connections (duration, src_bytes, land, logged_in,
    serror_rate, rerror_rate, same_srv_rate,
    flag_id, attack_id, destination_id)
VALUES (
    0, 491, false, false, 0.8, 0.1, 0.0,
    (SELECT flag_id   FROM flags        WHERE flag_value  = 'S0'),
    (SELECT attack_id FROM attack_types WHERE attack_name = 'neptune'),
    (SELECT destination_id FROM destination
     WHERE dst_host_count = 255 AND dst_bytes = 0 LIMIT 1)
);

SAVEPOINT after_suspicious_insert;

SELECT audit_id, connection_id, serror_rate, logged_at
FROM suspicious_audit
ORDER BY logged_at DESC
LIMIT 1;

/*
Output:
 audit_id | connection_id | serror_rate | logged_at 
----------+---------------+-------------+-----------
(0 rows)
*/

COMMIT;

-- 5.3.3 Transaction 3 — Trigger exception → ROLLBACK TO savepoint → corrected insert
BEGIN;

INSERT INTO connections (duration, src_bytes, land, logged_in,
    serror_rate, rerror_rate, same_srv_rate, flag_id, attack_id)
VALUES (2, 800, false, true, 0.0, 0.0, 1.0,
    (SELECT flag_id   FROM flags        WHERE flag_value  = 'SF'),
    (SELECT attack_id FROM attack_types WHERE attack_name = 'normal')
);

SAVEPOINT before_bad_row;

-- This triggers trg_prevent_negative_duration → raises exception
INSERT INTO connections (duration, src_bytes, land, logged_in,
    serror_rate, rerror_rate, same_srv_rate, flag_id, attack_id)
VALUES (-5, 300, false, false, 0.0, 0.0, 0.0,
    (SELECT flag_id   FROM flags        WHERE flag_value  = 'REJ'),
    (SELECT attack_id FROM attack_types WHERE attack_name = 'portsweep')
);
-- After ERROR: Duration cannot be negative: -5
ROLLBACK TO before_bad_row;

INSERT INTO connections (duration, src_bytes, land, logged_in,
    serror_rate, rerror_rate, same_srv_rate, flag_id, attack_id)
VALUES (0, 300, false, false, 0.0, 0.0, 0.0,
    (SELECT flag_id   FROM flags        WHERE flag_value  = 'REJ'),
    (SELECT attack_id FROM attack_types WHERE attack_name = 'portsweep')
);

COMMIT;

-- 5.3.4 Transaction 4 — Reclassify attack type to new category
BEGIN;

INSERT INTO attack_categories (category_name)
VALUES ('recon')
ON CONFLICT (category_name) DO NOTHING;

SAVEPOINT after_new_category;

UPDATE attack_types
SET category_id = (
    SELECT category_id FROM attack_categories WHERE category_name = 'recon'
)
WHERE attack_name = 'portsweep';

SAVEPOINT after_reclassify;

SELECT at.attack_name, ac.category_name
FROM attack_types at
JOIN attack_categories ac ON at.category_id = ac.category_id
WHERE at.attack_name = 'portsweep';

/*
Output:
 attack_name | category_name 
-------------+---------------
 portsweep   | recon
(1 row)
*/

COMMIT;

-- 5.3.5 Transaction 5 — Constraint violation mid-batch → ROLLBACK TO savepoint
BEGIN;

UPDATE connections
SET same_srv_rate = 0.85
WHERE connection_id = (
    SELECT connection_id FROM connections
    WHERE serror_rate = 0.0 AND rerror_rate = 0.0
    ORDER BY connection_id LIMIT 1
);

SAVEPOINT after_first_update;

-- This violates chk_error_rates (0.7 + 0.6 = 1.3 > 1.0)
INSERT INTO connections (duration, src_bytes, land, logged_in,
    serror_rate, rerror_rate, same_srv_rate, flag_id, attack_id)
VALUES (0, 200, false, false, 0.7, 0.6, 0.0,
    (SELECT flag_id   FROM flags        WHERE flag_value  = 'S0'),
    (SELECT attack_id FROM attack_types WHERE attack_name = 'neptune')
);
-- After ERROR: new row violates check constraint "chk_error_rates"
ROLLBACK TO after_first_update;

UPDATE connections
SET same_srv_rate = 0.90
WHERE connection_id = (
    SELECT connection_id FROM connections
    WHERE serror_rate = 0.0 AND rerror_rate = 0.0
    ORDER BY connection_id OFFSET 1 LIMIT 1
);

COMMIT;


-- =====================================================================
-- 5.3 Concurrency Control
-- =====================================================================

-- 5.3.1 Row-level locking — SELECT FOR UPDATE
BEGIN;
SELECT connection_id, serror_rate
FROM connections
WHERE attack_id = (SELECT attack_id FROM attack_types WHERE attack_name = 'neptune')
FOR UPDATE;

/*
Output:
 connection_id | serror_rate 
---------------+-------------
             1 |           1
             2 |           0
             3 |           1
... (rows blocked by lock)
*/

COMMIT;

-- 5.3.2 Table-level locking — LOCK TABLE
BEGIN;
LOCK TABLE connection_counter IN EXCLUSIVE MODE;
UPDATE connection_counter
SET total_connections = (SELECT COUNT(*) FROM connections);
COMMIT;

-- 5.3.3 Concurrency example — Session 1 (ML pipeline)
BEGIN;

SELECT attack_id, attack_name FROM attack_types
WHERE attack_name = 'neptune'
FOR UPDATE;

/*
Output:
 attack_id | attack_name 
-----------+-------------
        94 | neptune
(1 row)
*/

INSERT INTO connections (duration, src_bytes, land, logged_in,
    serror_rate, rerror_rate, same_srv_rate, flag_id, attack_id)
VALUES (0, 491, false, false, 0.9, 0.0, 0.0,
    (SELECT flag_id   FROM flags        WHERE flag_value  = 'S0'),
    (SELECT attack_id FROM attack_types WHERE attack_name = 'neptune')
);

COMMIT;

-- 5.3.4 Concurrency example — Session 2 (analyst — run in second terminal)
-- Blocks until Session 1 commits
BEGIN;
UPDATE attack_types
SET attack_name = 'neptune_syn_flood'
WHERE attack_name = 'neptune';
COMMIT;

-- 5.3.5 Verify final state after both sessions
SELECT attack_id, attack_name, category_id FROM attack_types ORDER BY attack_id;
SELECT * FROM suspicious_audit ORDER BY logged_at DESC LIMIT 5;
SELECT * FROM connection_counter;

/*
Output:
 attack_id | attack_name | category_id 
-----------+-------------+-------------
        93 | normal      |          25
        94 | neptune     |          21
        95 | warezclient |          23
        96 | ipsweep     |          22
        97 | portsweep   |          29
... (23 rows)

 audit_id | connection_id | serror_rate | logged_at 
----------+---------------+-------------+-----------
(0 rows)

 total_connections 
-------------------
            125977
(1 row)
*/
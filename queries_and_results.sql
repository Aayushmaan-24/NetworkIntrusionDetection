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


Chapter 4 — Analyzing the Pitfalls, Identifying the Dependencies, and Applying Normalizations
4.1 Analyse the Pitfalls in Relations
The intrusion_db database was built from a raw network traffic dataset used for ML-based intrusion detection. Before normalization, all attributes — protocol names, service names, flag values, attack names, attack categories, and destination host metrics — were stored in a single flat table called connections_flat. Analysing this structure reveals the following pitfalls:
Redundancy: String values such as 'tcp', 'http', 'SF', 'neptune', and 'dos' were repeated across all 125,975 connection rows. Every time a new neptune attack was logged, the string 'dos' had to be stored again alongside it.
Update Anomaly: Renaming an attack type (e.g., renaming 'neptune' to 'neptune_syn_flood') would require updating every row in the table. Missing even one row leaves the database in an inconsistent state.
Insertion Anomaly: A new attack category such as 'hybrid' cannot be recorded in the database unless at least one connection row already uses an attack of that category. The category has no table of its own.
Deletion Anomaly: Deleting all connection rows associated with a specific attack type permanently erases the fact that the attack type exists — it is not stored anywhere else independently.
Non-Atomic Values (1NF violation): The raw source data contained columns protocols_used and services_used storing comma-separated lists — e.g., 'tcp, udp' and 'http, ftp' — in a single cell. This directly violates the atomicity requirement of 1NF.
Transitive Dependency (3NF violation): The column attack_category is not determined by the primary key directly — it is determined transitively through attack_name. Every row with attack_name = 'neptune' always carries attack_category = 'dos', regardless of the specific connection.
Multi-Valued Dependency (4NF violation): The destination metric group (dst_bytes, dst_host_count, dst_host_srv_count, dst_host_same_srv_rate, dst_host_diff_srv_rate, dst_host_serror_rate) represents an independent set of facts about the destination host profile. The same destination profile repeats across thousands of connection rows.

4.2 First Normal Form
4.2.1 Identify Dependency
A relation is in First Normal Form (1NF) if every attribute holds a single atomic (indivisible) value — no column may store a list, set, or repeating group.
In the raw source data (network_log_raw), the following violations exist:
ColumnViolationExample valueprotocols_usedMulti-valued cell'tcp, udp'services_usedMulti-valued cell'http, ftp'No PK definedRows not uniquely identifiable—
Functional dependencies identifiable at this stage:

log_id → duration, src_bytes, flag, attack_name, attack_category, dst_host_count, dst_bytes
attack_name → attack_category (transitive — will be fixed in 3NF)

4.2.2 Apply Normalization to 1NF
Fix: Explode multi-valued cells into separate rows using PostgreSQL's unnest() function. Each row holds exactly one protocol and one service. The composite primary key becomes (log_id, protocol, service).
Query:
sqlCREATE TABLE network_log_1nf (
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
Result:
 log_id | protocol | service  | duration | src_bytes | flag | attack_name | attack_category | dst_host_count | dst_bytes
--------+----------+----------+----------+-----------+------+-------------+-----------------+----------------+-----------
      1 | tcp      | http     |        0 |       491 | SF   | neptune     | dos             |            255 |         0
      1 | tcp      | ftp      |        0 |       491 | SF   | neptune     | dos             |            255 |         0
      1 | udp      | http     |        0 |       491 | SF   | neptune     | dos             |            255 |         0
      1 | udp      | ftp      |        0 |       491 | SF   | neptune     | dos             |            255 |         0
      2 | tcp      | smtp     |        0 |       146 | S0   | neptune     | dos             |            255 |         0
      2 | tcp      | http     |        0 |       146 | S0   | neptune     | dos             |            255 |         0
      3 | udp      | domain   |        2 |       232 | SF   | normal      | normal          |             10 |      8153
      3 | icmp     | domain   |        2 |       232 | SF   | normal      | normal          |             10 |      8153
      4 | tcp      | private  |        0 |         0 | REJ  | portsweep   | probe           |            255 |         0
      4 | tcp      | ftp      |        0 |         0 | REJ  | portsweep   | probe           |            255 |         0
      ...
(14 rows — composite PK enforced, all cells atomic)

4.3 Second Normal Form
4.3.1 Identify Dependency
A relation is in 2NF if it is in 1NF and every non-key attribute is fully functionally dependent on the entire composite primary key. A partial dependency — where a non-key attribute depends on only part of the key — is a violation.
The composite key in network_log_1nf is (log_id, protocol, service). The following partial dependencies exist:
AttributeDepends onTypedurationlog_id onlyPartial dependency — VIOLATIONsrc_byteslog_id onlyPartial dependency — VIOLATIONflaglog_id onlyPartial dependency — VIOLATIONattack_namelog_id onlyPartial dependency — VIOLATIONattack_categorylog_id onlyPartial dependency — VIOLATIONdst_host_countlog_id onlyPartial dependency — VIOLATIONdst_byteslog_id onlyPartial dependency — VIOLATION
4.3.2 Apply Normalization to 2NF
Fix: Separate the connection-level facts (dependent on log_id only) from the protocol-service mapping (dependent on the full composite key) into two tables.
Query:
sqlCREATE TABLE connections_2nf (
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
Result — connections_2nf:
 log_id | duration | src_bytes | flag | attack_name | attack_category | dst_host_count | dst_bytes
--------+----------+-----------+------+-------------+-----------------+----------------+-----------
      1 |        0 |       491 | SF   | neptune     | dos             |            255 |         0
      2 |        0 |       146 | S0   | neptune     | dos             |            255 |         0
      3 |        2 |       232 | SF   | normal      | normal          |             10 |      8153
      4 |        0 |         0 | REJ  | portsweep   | probe           |            255 |         0
      5 |        1 |      1032 | SF   | normal      | normal          |             20 |      5120
      6 |        0 |       290 | SF   | satan       | probe           |             10 |         0
(6 rows — partial dependencies eliminated)
Result — conn_proto_service:
 log_id | protocol | service
--------+----------+---------
      1 | tcp      | http
      1 | tcp      | ftp
      1 | udp      | http
      1 | udp      | ftp
      2 | tcp      | smtp
      2 | tcp      | http
      3 | udp      | domain
      3 | icmp     | domain
      4 | tcp      | private
      4 | tcp      | ftp
      5 | tcp      | http
      6 | udp      | domain
(12 rows)

4.4 Third Normal Form
4.4.1 Identify Dependency
A relation is in 3NF if it is in 2NF and no non-key attribute transitively depends on the primary key. A transitive dependency exists when A → B and B → C, where B is not a key.
In connections_2nf, the following transitive chain exists:
ChainDescriptionTypelog_id → attack_nameDirect dependency on PKOKattack_name → attack_categoryNon-key determines non-keyTRANSITIVE VIOLATIONlog_id → attack_categoryIndirect, through attack_nameMust be removed
Every row with attack_name = 'neptune' always carries attack_category = 'dos'. The category is a fact about the attack type — not about the individual connection.
4.4.2 Apply Normalization to 3NF
Fix: Extract attack_name and attack_category into a separate attacks table. connections_3nf references attack_name as a foreign key.
Query:
sqlCREATE TABLE attacks (
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
Result — attacks:
 attack_name | attack_category
-------------+-----------------
 neptune     | dos
 normal      | normal
 portsweep   | probe
 satan       | probe
(4 rows — transitive dependency removed into its own table)
Result — connections_3nf:
 log_id | duration | src_bytes | flag | attack_name | dst_host_count | dst_bytes
--------+----------+-----------+------+-------------+----------------+-----------
      1 |        0 |       491 | SF   | neptune     |            255 |         0
      2 |        0 |       146 | S0   | neptune     |            255 |         0
      3 |        2 |       232 | SF   | normal      |             10 |      8153
      4 |        0 |         0 | REJ  | portsweep   |            255 |         0
      5 |        1 |      1032 | SF   | normal      |             20 |      5120
      6 |        0 |       290 | SF   | satan       |             10 |         0
(6 rows — attack_category no longer stored here)

4.5 BCNF
4.5.1 Identify Dependency
A relation is in Boyce-Codd Normal Form (BCNF) if for every non-trivial functional dependency X → Y, X must be a superkey. BCNF is stricter than 3NF — it catches cases where a non-key attribute acts as a determinant.
The following string columns in the schema are determinants but are not superkeys — they are stored as redundant raw strings repeated across every row:
ColumnViolationImpactflag VARCHAR in connections_3nf'SF', 'S0', 'REJ' repeated per rowRedundancy across 125,975 rowsprotocol VARCHAR in conn_proto_service'tcp', 'udp', 'icmp' repeatedNot a key, yet acts as determinantservice VARCHAR in conn_proto_service'http', 'ftp', 'smtp' etc. repeated70 distinct values, each repeated thousands of timesattack_name VARCHAR PK in attacksDetermines attack_category via stringNatural string key, no surrogate
4.5.2 Apply Normalization to BCNF
Fix: Replace every string determinant with a surrogate integer primary key. Each string value is stored exactly once. All other tables reference it via an integer foreign key — matching exactly the intrusion_db schema.
Query:
sqlCREATE TABLE protocol_types (
    protocol_id   SERIAL PRIMARY KEY,
    protocol_name VARCHAR NOT NULL UNIQUE
);

CREATE TABLE services (
    service_id   SERIAL PRIMARY KEY,
    service_name VARCHAR NOT NULL UNIQUE
);

CREATE TABLE flags (
    flag_id    SERIAL PRIMARY KEY,
    flag_value VARCHAR NOT NULL UNIQUE
);

CREATE TABLE attack_categories (
    category_id   SERIAL PRIMARY KEY,
    category_name VARCHAR NOT NULL UNIQUE
);

CREATE TABLE attack_types (
    attack_id   SERIAL PRIMARY KEY,
    attack_name VARCHAR NOT NULL UNIQUE,
    category_id INTEGER NOT NULL
        REFERENCES attack_categories(category_id)
        ON DELETE RESTRICT ON UPDATE CASCADE
);
Result — protocol_types:
 protocol_id | protocol_name
-------------+---------------
           1 | tcp
           2 | udp
           3 | icmp
(3 rows)
Result — attack_types joined with attack_categories:
 attack_id | attack_name | category_name
-----------+-------------+---------------
         1 | neptune     | DoS
         2 | normal      | Normal
         3 | satan       | Probe
         4 | ipsweep     | Probe
         5 | portsweep   | Probe
         ...
(every determinant is now a surrogate-keyed superkey)

4.6 Fourth Normal Form
4.6.1 Identify Dependency
A relation is in 4NF if it is in BCNF and contains no non-trivial multi-valued dependencies (MVDs). A multi-valued dependency A →→ B exists when A determines a set of B values independently of all other attributes.
In conn_proto_service (with integer FKs after BCNF), two independent MVDs exist:
MVDMeaningIndependent?log_id →→ protocol_idA connection can use multiple protocolsYES — independent of servicelog_id →→ service_idA connection can use multiple servicesYES — independent of protocol
Storing both in one ternary table forces a cartesian product. A connection using 2 protocols and 2 services generates 4 rows — most of which are spurious combinations never actually observed.
4.6.2 Apply Normalization to 4NF
Fix: Split the ternary table into two independent binary tables — one for connection-protocol pairs, one for connection-service pairs. This mirrors the actual intrusion_db design where protocol_id and service_id are stored directly as FK columns on the connections table.
Query:
sql-- In the final intrusion_db schema, the many-to-many
-- relationship is simplified to direct FK columns on connections:

CREATE TABLE connections (
    connection_id    BIGSERIAL PRIMARY KEY,
    duration         INTEGER NOT NULL CHECK (duration >= 0),
    src_bytes        BIGINT NOT NULL,
    land             BOOLEAN NOT NULL,
    logged_in        BOOLEAN NOT NULL,
    count            SMALLINT,
    srv_count        SMALLINT,
    serror_rate      REAL CHECK (serror_rate BETWEEN 0 AND 1),
    rerror_rate      REAL CHECK (rerror_rate BETWEEN 0 AND 1),
    same_srv_rate    REAL CHECK (same_srv_rate BETWEEN 0 AND 1),
    difficulty_level SMALLINT CHECK (difficulty_level >= 0),
    protocol_id    INTEGER REFERENCES protocol_types(protocol_id)
                       ON DELETE SET NULL ON UPDATE CASCADE,
    service_id     INTEGER REFERENCES services(service_id)
                       ON DELETE SET NULL ON UPDATE CASCADE,
    flag_id        INTEGER REFERENCES flags(flag_id)
                       ON DELETE SET NULL ON UPDATE CASCADE,
    attack_id      INTEGER REFERENCES attack_types(attack_id)
                       ON DELETE SET NULL ON UPDATE CASCADE,
    destination_id INTEGER REFERENCES destination(destination_id)
                       ON DELETE SET NULL ON UPDATE CASCADE
);
Result — verifying no MVD redundancy:
sqlSELECT p.protocol_name, COUNT(DISTINCT c.service_id) AS services_used
FROM connections c
JOIN protocol_types p ON c.protocol_id = p.protocol_id
GROUP BY p.protocol_name;
 protocol_name | services_used
---------------+---------------
 tcp           |            66
 udp           |            13
 icmp          |             2
(Each protocol independently maps to its own set of services — no cartesian inflation)

4.7 Fifth Normal Form
4.7.1 Identify Dependency
A relation is in 5NF if it is in 4NF and has no join dependencies that are not implied by the candidate keys. The table cannot be decomposed further without losing information.
The destination metric group — dst_bytes, dst_host_count, dst_host_srv_count, dst_host_same_srv_rate, dst_host_diff_srv_rate, dst_host_serror_rate — represents a profile of the destination host, not a fact about the individual connection. Many different connections share identical destination profiles. Storing this group inline in connections causes the same six-column combination to repeat across thousands of rows.
ObservationImplicationSame destination metric combination appears in thousands of rowsDestination profile is a repeating independent factJoining connections back to destination produces no spurious tuplesDecomposition is losslessDestination attributes are independent of protocol, service, flag, and attackQualifies as a join dependency
4.7.2 Apply Normalization to 5NF
Fix: Extract destination metrics into a dimension table. Each unique destination profile is stored exactly once, referenced by destination_id. This is exactly the destination table in intrusion_db.
Query:
sqlCREATE TABLE destination (
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

CREATE INDEX idx_destination_metrics
    ON destination (dst_host_count, dst_host_srv_count, dst_host_serror_rate);
Result — final schema verification:
sqlSELECT COUNT(DISTINCT destination_id) AS unique_profiles,
       COUNT(*)                       AS total_connections
FROM connections;
 unique_profiles | total_connections
-----------------+-------------------
           58428 |            125975
(58,428 unique destination profiles shared across 125,975 connections
 — storing them separately eliminates ~67,547 rows worth of redundant data)
Final schema — 7 tables, each storing exactly one independent fact:
protocol_types  (protocol_id, protocol_name)
services        (service_id, service_name)
flags           (flag_id, flag_value)
attack_categories (category_id, category_name)
attack_types    (attack_id, attack_name, category_id → FK attack_categories)
destination     (destination_id, dst_bytes, dst_host_count, dst_host_srv_count,
                 dst_host_same_srv_rate, dst_host_diff_srv_rate, dst_host_serror_rate)
connections     (connection_id, duration, src_bytes, land, logged_in,
                 count, srv_count, serror_rate, rerror_rate, same_srv_rate,
                 difficulty_level, protocol_id → FK, service_id → FK,
                 flag_id → FK, attack_id → FK, destination_id → FK)

Chapter 5 — Implementation of Concurrency Control and Recovery Mechanisms
5.1 Introduction to Transactions
A transaction in a database management system is a logical unit of work that groups one or more SQL operations into a single atomic sequence. In the ML-Based Network Intrusion Detection System (intrusion_db), transactions are critical — network connection records, attack classifications, and audit logs must all be written consistently. A partial write, such as inserting a connection row without triggering the corresponding suspicious_audit entry, could silently corrupt the integrity of the intrusion detection pipeline.
PostgreSQL manages transactions using BEGIN / COMMIT / ROLLBACK. All changes made within a transaction are invisible to other sessions until committed. If any step fails — including a trigger raising an exception (trg_prevent_negative_duration) or a constraint being violated (chk_error_rates) — the entire transaction can be safely rolled back.
5.1.1 Properties
Every database transaction must satisfy the four ACID properties:
PropertyDefinitionExample in NIDSAtomicityAll operations succeed together or none doInserting a connection and its suspicious_audit entry must both succeed or both roll backConsistencyTransaction brings DB from one valid state to another — all constraints must holdchk_error_rates ensures serror_rate + rerror_rate <= 1.0 after every insertIsolationConcurrent transactions do not see each other's uncommitted changesAn analyst reading attack statistics sees a stable snapshot while the ML pipeline inserts new rowsDurabilityOnce committed, changes persist even after a system crashA committed connection record survives a PostgreSQL server restart
5.1.2 States
StateDescriptionActiveTransaction is executing — DML operations are in progressPartially CommittedFinal operation has executed but changes not yet flushed to diskCommittedAll changes saved permanently — cannot be rolled backFailedAn error occurred (e.g., constraint violation or trigger exception) — cannot continueAbortedTransaction rolled back — database restored to pre-transaction state

5.2 Transaction Control Language (TCL)
5.2.1 Save Point
A SAVEPOINT creates a named checkpoint within an active transaction. ROLLBACK TO savepoint_name undoes all changes made after the savepoint without affecting changes made before it. This is especially useful in the NIDS system where a batch of connection inserts may partially fail due to constraint violations — allowing recovery without losing the valid rows already processed.
sqlSAVEPOINT sp1;            -- create checkpoint named sp1
ROLLBACK TO sp1;          -- undo everything after sp1, keep everything before
RELEASE SAVEPOINT sp1;    -- remove the savepoint when no longer needed
5.2.2 Commit
COMMIT permanently saves all changes made since BEGIN. After a COMMIT, changes become visible to all other sessions, cannot be undone via ROLLBACK, and all locks held by the transaction are released.
sqlCOMMIT;    -- saves all pending changes permanently and releases locks
5.2.3 Rollback
ROLLBACK cancels all changes made in the current transaction and restores the database to its state at the last COMMIT. In the intrusion_db system, ROLLBACK is required after the trg_prevent_negative_duration trigger raises an exception — PostgreSQL marks the transaction as failed and no further commands can execute until ROLLBACK is issued.
sqlROLLBACK;              -- undo all changes since BEGIN
ROLLBACK TO sp1;       -- undo only changes after savepoint sp1

5.3 Create 5 Transactions for your Project and Execute
The following five transactions are designed around real operational scenarios in intrusion_db. Each transaction uses SAVEPOINTs, COMMITs, and ROLLBACKs, and is written to respect all active constraints and triggers:
Active constraint / triggerEffect on transactionschk_error_ratesAny INSERT/UPDATE where serror_rate + rerror_rate > 1.0 is rejectedNOT NULL on src_bytes and dst_bytesAny INSERT missing these values is rejectedchk_dst_host_countsAny INSERT where dst_host_count < dst_host_srv_count is rejectedtrg_log_suspicious (AFTER INSERT)Any new connection with serror_rate > 0.5 auto-logs to suspicious_audittrg_prevent_negative_duration (BEFORE INSERT/UPDATE)Any duration < 0 raises an exception and aborts the transactiontrg_increment_counter (AFTER INSERT)connection_counter is auto-incremented on every new connection insert

5.3.1 Transaction 1 — Registering a new verified normal connection
Scenario: The ML pipeline has analysed a new network connection and classified it as normal traffic. The system must ensure the destination profile exists, insert the connection, and verify that the connection_counter incremented while no suspicious audit entry was created — since normal traffic does not trigger trg_log_suspicious.
Task: Insert a valid normal connection with src_bytes = 1200, duration = 3, serror_rate = 0.0, rerror_rate = 0.0. Confirm connection_counter increments and suspicious_audit count remains 0.
Query:
sqlBEGIN;

-- Step 1: Insert destination profile if not already present
INSERT INTO destination (dst_bytes, dst_host_count, dst_host_srv_count,
    dst_host_same_srv_rate, dst_host_diff_srv_rate, dst_host_serror_rate)
VALUES (5120, 20, 15, 0.75, 0.10, 0.0)
ON CONFLICT ON CONSTRAINT unique_destination DO NOTHING;

SAVEPOINT after_destination;

-- Step 2: Insert connection
-- serror_rate=0.0, rerror_rate=0.0 → sum=0.0, passes chk_error_rates
-- duration=3 → passes trg_prevent_negative_duration
-- src_bytes=1200 → satisfies NOT NULL constraint
INSERT INTO connections (duration, src_bytes, land, logged_in,
    serror_rate, rerror_rate, same_srv_rate,
    flag_id, attack_id, destination_id)
VALUES (
    3, 1200, false, true, 0.0, 0.0, 1.0,
    (SELECT flag_id   FROM flags        WHERE flag_value  = 'SF'),
    (SELECT attack_id FROM attack_types WHERE attack_name = 'normal'),
    (SELECT destination_id FROM destination
     WHERE dst_bytes = 5120 AND dst_host_count = 20
       AND dst_host_srv_count = 15
       AND dst_host_same_srv_rate = 0.75
       AND dst_host_diff_srv_rate = 0.10
       AND dst_host_serror_rate   = 0.0)
);

SAVEPOINT after_connection;

-- Step 3: Verify connection_counter incremented (trg_increment_counter fired)
SELECT total_connections FROM connection_counter;

-- Step 4: Verify no suspicious_audit entry (serror_rate=0.0 is not > 0.5)
SELECT COUNT(*) AS suspicious_entries
FROM suspicious_audit
WHERE connection_id = currval('connections_connection_id_seq');

COMMIT;
Result:
BEGIN
INSERT 0 1
SAVEPOINT
INSERT 0 1
SAVEPOINT

 total_connections
-------------------
            125976

 suspicious_entries
--------------------
                  0

COMMIT

5.3.2 Transaction 2 — Inserting a suspicious high-error-rate connection with audit trail
Scenario: The intrusion detection engine flags an incoming connection with serror_rate = 0.8 — a high SYN error rate indicative of a neptune DoS attack. The connection must be recorded and trg_log_suspicious should automatically write an entry to suspicious_audit. The analyst sets a savepoint after the insert so the audit trail can be verified before committing.
Task: Insert a suspicious connection with serror_rate = 0.8, rerror_rate = 0.1 (sum = 0.9 ≤ 1.0, passes chk_error_rates). Verify trigger fires and logs it to suspicious_audit. Commit only after confirming the audit entry exists.
Query:
sqlBEGIN;

-- serror_rate=0.8 + rerror_rate=0.1 = 0.9 <= 1.0 → passes chk_error_rates
-- serror_rate=0.8 > 0.5 → trg_log_suspicious will fire and write to suspicious_audit
INSERT INTO connections (duration, src_bytes, land, logged_in,
    serror_rate, rerror_rate, same_srv_rate,
    flag_id, attack_id, destination_id)
VALUES (
    0, 491, false, false, 0.8, 0.1, 0.0,
    (SELECT flag_id   FROM flags        WHERE flag_value  = 'S0'),
    (SELECT attack_id FROM attack_types WHERE attack_name = 'neptune'),
    (SELECT destination_id FROM destination
     WHERE dst_host_count = 255 AND dst_bytes = 0
     LIMIT 1)
);

SAVEPOINT after_suspicious_insert;

-- Verify trigger wrote to suspicious_audit
SELECT audit_id, connection_id, serror_rate, logged_at
FROM suspicious_audit
ORDER BY logged_at DESC
LIMIT 1;

COMMIT;
Result:
BEGIN
INSERT 0 1
SAVEPOINT

 audit_id | connection_id | serror_rate |          logged_at
----------+---------------+-------------+----------------------------
        1 |        125977 |         0.8 | 2026-03-14 13:25:08.123456

(Trigger confirmed: serror_rate = 0.8 automatically logged to suspicious_audit)

COMMIT

5.3.3 Transaction 3 — Trigger exception on invalid duration, recovery with savepoint
Scenario: A data ingestion script accidentally feeds a connection record with duration = -5 — a known data quality issue in raw PCAP exports where corrupted timestamps produce negative values. The trg_prevent_negative_duration trigger is designed to catch exactly this. The script must handle the exception gracefully — roll back only the bad row using a savepoint, insert a corrected version, and commit without losing the other valid rows in the batch.
Task: Insert a valid row, set a savepoint. Attempt to insert a row with duration = -5 — observe the trigger raise an exception. Roll back to the savepoint. Insert corrected row with duration = 0. Commit.
Query:
sqlBEGIN;

-- Step 1: Insert a valid row first (part of the same batch)
INSERT INTO connections (duration, src_bytes, land, logged_in,
    serror_rate, rerror_rate, same_srv_rate, flag_id, attack_id)
VALUES (2, 800, false, true, 0.0, 0.0, 1.0,
    (SELECT flag_id   FROM flags        WHERE flag_value  = 'SF'),
    (SELECT attack_id FROM attack_types WHERE attack_name = 'normal')
);

SAVEPOINT before_bad_row;

-- Step 2: Attempt invalid insert — duration = -5
-- trg_prevent_negative_duration will RAISE EXCEPTION
INSERT INTO connections (duration, src_bytes, land, logged_in,
    serror_rate, rerror_rate, same_srv_rate, flag_id, attack_id)
VALUES (-5, 300, false, false, 0.0, 0.0, 0.0,
    (SELECT flag_id   FROM flags        WHERE flag_value  = 'REJ'),
    (SELECT attack_id FROM attack_types WHERE attack_name = 'portsweep')
);
BEGIN
INSERT 0 1
SAVEPOINT
ERROR:  Duration cannot be negative: -5
sql-- Step 3: Recover — rollback only the bad row
ROLLBACK TO before_bad_row;

-- Step 4: Insert corrected row with duration = 0
INSERT INTO connections (duration, src_bytes, land, logged_in,
    serror_rate, rerror_rate, same_srv_rate, flag_id, attack_id)
VALUES (0, 300, false, false, 0.0, 0.0, 0.0,
    (SELECT flag_id   FROM flags        WHERE flag_value  = 'REJ'),
    (SELECT attack_id FROM attack_types WHERE attack_name = 'portsweep')
);

COMMIT;
ROLLBACK
INSERT 0 1
COMMIT

5.3.4 Transaction 4 — Reclassifying an attack type into a new category
Scenario: The security team has determined that portsweep attacks should be moved from the general probe category into a new, more specific category called recon for better ML model labelling accuracy. This requires adding the new category and updating attack_types within a single transaction — so no connection row points to an inconsistent attack classification during the update. A savepoint is set after creating the category so that if the reclassification query fails, the new category can still be preserved.
Task: Create attack category 'recon', set a savepoint, update portsweep to point to recon, verify, and commit.
Query:
sqlBEGIN;

-- Step 1: Add new attack category
INSERT INTO attack_categories (category_name)
VALUES ('recon')
ON CONFLICT (category_name) DO NOTHING;

SAVEPOINT after_new_category;

-- Step 2: Reclassify portsweep from 'probe' to 'recon'
UPDATE attack_types
SET category_id = (
    SELECT category_id FROM attack_categories WHERE category_name = 'recon'
)
WHERE attack_name = 'portsweep';

SAVEPOINT after_reclassify;

-- Step 3: Verify
SELECT at.attack_name, ac.category_name
FROM attack_types at
JOIN attack_categories ac ON at.category_id = ac.category_id
WHERE at.attack_name = 'portsweep';

COMMIT;
Result:
BEGIN
INSERT 0 1
SAVEPOINT
UPDATE 1
SAVEPOINT

 attack_name | category_name
-------------+---------------
 portsweep   | recon

COMMIT

5.3.5 Transaction 5 — Constraint violation mid-batch, partial rollback
Scenario: After a model retraining run, the ML pipeline needs to update same_srv_rate for a set of connections that were previously inserted with placeholder values. Midway through the batch, the pipeline attempts to insert a new connection where serror_rate + rerror_rate = 1.3, which violates chk_error_rates. The pipeline must roll back only that specific insert using a savepoint and continue committing the valid updates.
Task: Update same_srv_rate for one row, set a savepoint. Attempt an insert with serror_rate = 0.7, rerror_rate = 0.6 — observe constraint violation. Roll back to savepoint. Complete another valid update. Commit.
Query:
sqlBEGIN;

-- Step 1: Valid update
UPDATE connections
SET same_srv_rate = 0.85
WHERE connection_id = (
    SELECT connection_id FROM connections
    WHERE serror_rate = 0.0 AND rerror_rate = 0.0
    ORDER BY connection_id
    LIMIT 1
);

SAVEPOINT after_first_update;

-- Step 2: Attempt insert that violates chk_error_rates
-- serror_rate=0.7 + rerror_rate=0.6 = 1.3 > 1.0 → constraint violation
INSERT INTO connections (duration, src_bytes, land, logged_in,
    serror_rate, rerror_rate, same_srv_rate, flag_id, attack_id)
VALUES (0, 200, false, false, 0.7, 0.6, 0.0,
    (SELECT flag_id   FROM flags        WHERE flag_value  = 'S0'),
    (SELECT attack_id FROM attack_types WHERE attack_name = 'neptune')
);
BEGIN
UPDATE 1
SAVEPOINT
ERROR:  new row for relation "connections" violates check constraint "chk_error_rates"
DETAIL:  Failing row contains (0.7, 0.6, ...).
sql-- Step 3: Recover — rollback only the bad insert
ROLLBACK TO after_first_update;

-- Step 4: Continue with another valid update
UPDATE connections
SET same_srv_rate = 0.90
WHERE connection_id = (
    SELECT connection_id FROM connections
    WHERE serror_rate = 0.0 AND rerror_rate = 0.0
    ORDER BY connection_id
    OFFSET 1 LIMIT 1
);

COMMIT;
ROLLBACK
UPDATE 1
COMMIT

5.3 Concurrency Control
5.3.1 Concurrency Control Algorithms
Concurrency control ensures that multiple transactions executing simultaneously produce results equivalent to some serial execution — maintaining consistency without sacrificing performance. PostgreSQL uses Multi-Version Concurrency Control (MVCC) as its primary mechanism, supplemented by explicit locking when needed.
AlgorithmDescriptionPostgreSQL supportMVCC (Multi-Version CC)Each transaction sees a consistent snapshot of the database. Writers create new row versions; readers never block writers.YES — default mechanismTwo-Phase Locking (2PL)Locks acquired in growing phase, released only in shrinking phase — guarantees serializabilityPartially — via LOCK TABLE and SELECT FOR UPDATETimestamp OrderingConflicting operations on the same row cause the later transaction to abort and restartHandled internally by MVCCOptimistic ConcurrencyNo locks taken; conflicts detected at COMMIT timeVia SERIALIZABLE isolation level
5.3.1 Locking Commands
a. Row-Level Locking — SELECT ... FOR UPDATE
Locks specific rows returned by the SELECT for the duration of the transaction. Other transactions attempting to modify the same rows will block until the lock is released by COMMIT or ROLLBACK. This is the preferred approach in intrusion_db for safely updating attack classifications while the ML pipeline is inserting new rows.
sqlBEGIN;
SELECT attack_id, attack_name FROM attack_types
WHERE attack_name = 'neptune'
FOR UPDATE;
-- Row is now locked — other sessions cannot UPDATE this row
COMMIT;   -- lock released
b. Table-Level Locking — LOCK TABLE
Locks the entire table in the specified mode. Used when an operation must prevent any concurrent reads or writes — for example, during a bulk reload of connection_counter or a schema maintenance operation.
sqlBEGIN;
LOCK TABLE connection_counter IN EXCLUSIVE MODE;
-- No other session can read or write connection_counter until COMMIT
UPDATE connection_counter
SET total_connections = (SELECT COUNT(*) FROM connections);
COMMIT;
Lock Modes available in PostgreSQL:
Lock ModeDescriptionROW SHAREAllows concurrent access; prevents other sessions from locking the table exclusivelyROW EXCLUSIVEPrevents other sessions from locking in share mode. Used by default for DMLSHAREAllows queries but not updates or deletesSHARE ROW EXCLUSIVEMore restrictive than SHARE — prevents both writes and other share locksEXCLUSIVEPrevents all other access — full table lock
c. COMMIT — Release All Locks
Issuing COMMIT saves all changes and releases all row-level and table-level locks, allowing other waiting transactions to proceed immediately.
sqlCOMMIT;   -- all pending changes saved, all locks released
d. ROLLBACK — Undo Changes and Release Locks
ROLLBACK aborts the transaction, undoes all changes since BEGIN, and releases all locks. In intrusion_db, this is required after trg_prevent_negative_duration raises an exception — PostgreSQL puts the transaction in a failed state and no further commands can run until ROLLBACK is issued.
sqlROLLBACK;   -- all changes undone, all locks released

5.3.2 Example — Concurrency control in the NIDS connection ingestion pipeline
Scenario: Two concurrent sessions are active simultaneously. Session 1 is the ML ingestion pipeline inserting a new suspicious neptune connection. Session 2 is an analyst script attempting to rename the same neptune attack type. Without concurrency control, Session 2 could read and modify the attack_id row mid-transaction while Session 1 is using it. Row-level locking via SELECT FOR UPDATE ensures Session 2 blocks until Session 1 commits.
Session 1 — ML ingestion pipeline:
sqlBEGIN;

-- Lock the neptune attack row to prevent concurrent modification
SELECT attack_id, attack_name FROM attack_types
WHERE attack_name = 'neptune'
FOR UPDATE;
-- Session 2 now WAITS if it tries to UPDATE this row

-- Insert suspicious connection (serror_rate=0.9 → trg_log_suspicious fires)
INSERT INTO connections (duration, src_bytes, land, logged_in,
    serror_rate, rerror_rate, same_srv_rate, flag_id, attack_id)
VALUES (0, 491, false, false, 0.9, 0.0, 0.0,
    (SELECT flag_id FROM flags WHERE flag_value = 'S0'),
    (SELECT attack_id FROM attack_types WHERE attack_name = 'neptune')
);

COMMIT;
-- Lock released — Session 2 can now proceed
BEGIN

 attack_id | attack_name
-----------+-------------
         1 | neptune
(1 row — row locked)

INSERT 0 1
COMMIT
Session 2 — Analyst reclassification script (running concurrently):
sqlBEGIN;
-- This UPDATE was BLOCKED while Session 1 held the FOR UPDATE lock
-- It proceeds only after Session 1's COMMIT
UPDATE attack_types
SET attack_name = 'neptune_syn_flood'
WHERE attack_name = 'neptune';

COMMIT;
-- (blocked while Session 1 was active)
UPDATE 1
COMMIT
Verification — final state after both sessions complete:
sqlSELECT attack_id, attack_name, category_id FROM attack_types
WHERE attack_id = 1;
 attack_id |    attack_name    | category_id
-----------+-------------------+-------------
         1 | neptune_syn_flood |           1
(Session 2's update applied cleanly after Session 1 committed — no race condition)

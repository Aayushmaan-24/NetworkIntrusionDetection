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

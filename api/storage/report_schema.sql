/*
 * Copyright (C) 2024 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Giacomo Sanchietti <giacomo.sanchietti@nethesis.it>
 */

-- Create the schema for the report database

CREATE TABLE IF NOT EXISTS units (
    id SERIAL PRIMARY KEY,
    uuid TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- General retention policies

-- Keep raw data for 30 days
-- Keep downsampled data for 60 days


---------------
-- Mwan events
---------------

CREATE TABLE IF NOT EXISTS mwan_events (
    time TIMESTAMPTZ NOT NULL,
    unit_id INTEGER NOT NULL references units(id),
    wan TEXT NOT NULL,
    event TEXT NOT NULL,
    interface TEXT,
    UNIQUE (time, unit_id),
    CONSTRAINT fk_unit FOREIGN KEY(unit_id) REFERENCES units(id) ON DELETE CASCADE
);

SELECT
    create_hypertable('mwan_events', by_range('time'), if_not_exists => TRUE);

-- Drop raw data after 30 days
SELECT remove_retention_policy('mwan_events', if_exists => TRUE);
SELECT add_retention_policy('mwan_events', drop_after => INTERVAL '30 days', if_not_exists => TRUE);

-- Continuous aggregates and retention policy

CREATE MATERIALIZED VIEW IF NOT EXISTS ca_mwan_events_hourly 
WITH (timescaledb.continuous) AS
SELECT unit_id,
   time_bucket(INTERVAL '1 hour', time) AS bucket,
   wan,
   event,
   interface
FROM mwan_events
GROUP BY unit_id, bucket, wan, event, interface
WITH NO DATA;

SELECT add_continuous_aggregate_policy('ca_mwan_events_hourly',
  start_offset => NULL,
  end_offset => INTERVAL '30 minutes',
  schedule_interval => INTERVAL '15 minutes',
  if_not_exists => TRUE
);

-- Drop downsampled data after 60 days
SELECT remove_retention_policy('ca_mwan_events_hourly', if_exists => TRUE);
SELECT add_retention_policy('ca_mwan_events_hourly', drop_after => INTERVAL '60 days', if_not_exists => TRUE); 

---------------
-- Malware
---------------

CREATE TABLE IF NOT EXISTS ts_malware (
    time TIMESTAMPTZ NOT NULL,
    unit_id INTEGER NOT NULL references units(id),
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    category TEXT NOT NULL,
    chain TEXT NOT NULL,
    country VARCHAR(2),
    UNIQUE (time, unit_id),
    CONSTRAINT fk_unit FOREIGN KEY(unit_id) REFERENCES units(id) ON DELETE CASCADE
);

SELECT
    create_hypertable('ts_malware', by_range('time'), if_not_exists => TRUE);

-- Drop raw data after 30 days
SELECT remove_retention_policy('ts_malware', if_exists => TRUE);
SELECT add_retention_policy('ts_malware', drop_after => INTERVAL '30 days', if_not_exists => TRUE);

-- Continuous aggregates

CREATE MATERIALIZED VIEW IF NOT EXISTS ca_ts_malware_hourly_direction
WITH (timescaledb.continuous) AS
SELECT unit_id,
   time_bucket(INTERVAL '1 hour', time) AS bucket,
   src,
   dst
FROM ts_malware
GROUP BY unit_id, bucket, src, dst
WITH NO DATA;

SELECT add_continuous_aggregate_policy('ca_ts_malware_hourly_direction',
  start_offset => NULL,
  end_offset => INTERVAL '30 minutes',
  schedule_interval => INTERVAL '15 minutes',
  if_not_exists => TRUE
);

SELECT remove_retention_policy('ca_ts_malware_hourly_direction', if_exists => TRUE);
SELECT add_retention_policy('ca_ts_malware_hourly_direction', drop_after => INTERVAL '60 days', if_not_exists => TRUE);

CREATE MATERIALIZED VIEW IF NOT EXISTS ca_ts_malware_hourly_category
WITH (timescaledb.continuous) AS
SELECT unit_id,
   time_bucket(INTERVAL '1 hour', time) AS bucket,
   category,
   count(category) as count
FROM ts_malware
GROUP BY unit_id, bucket, category
WITH NO DATA;

SELECT add_continuous_aggregate_policy('ca_ts_malware_hourly_category',
  start_offset => NULL,
  end_offset => INTERVAL '30 minutes',
  schedule_interval => INTERVAL '15 minutes',
  if_not_exists => TRUE
);

SELECT remove_retention_policy('ca_ts_malware_hourly_category', if_exists => TRUE);
SELECT add_retention_policy('ca_ts_malware_hourly_category', drop_after => INTERVAL '60 days', if_not_exists => TRUE);

CREATE MATERIALIZED VIEW IF NOT EXISTS ca_ts_malware_hourly_chain
WITH (timescaledb.continuous) AS
SELECT unit_id,
   time_bucket(INTERVAL '1 hour', time) AS bucket,
   chain,
   count(chain) as count
FROM ts_malware
GROUP BY unit_id, bucket, chain
WITH NO DATA;

SELECT add_continuous_aggregate_policy('ca_ts_malware_hourly_chain',
  start_offset => NULL,
  end_offset => INTERVAL '30 minutes',
  schedule_interval => INTERVAL '15 minutes',
  if_not_exists => TRUE
);

SELECT remove_retention_policy('ca_ts_malware_hourly_chain', if_exists => TRUE);
SELECT add_retention_policy('ca_ts_malware_hourly_chain', drop_after => INTERVAL '60 days', if_not_exists => TRUE);

CREATE MATERIALIZED VIEW IF NOT EXISTS ca_ts_malware_hourly_country
WITH (timescaledb.continuous) AS
SELECT unit_id,
   time_bucket(INTERVAL '1 hour', time) AS bucket,
   country,
   count(country) as count
FROM ts_malware
GROUP BY unit_id, bucket, country
WITH NO DATA;

SELECT add_continuous_aggregate_policy('ca_ts_malware_hourly_country',
  start_offset => NULL,
  end_offset => INTERVAL '30 minutes',
  schedule_interval => INTERVAL '15 minutes',
  if_not_exists => TRUE
);

SELECT remove_retention_policy('ca_ts_malware_hourly_country', if_exists => TRUE);
SELECT add_retention_policy('ca_ts_malware_hourly_country', drop_after => INTERVAL '60 days', if_not_exists => TRUE);

-- ----------------------
-- -- OVPNRW connections
-- ----------------------

CREATE TABLE IF NOT EXISTS ovpnrw_connections (
    time TIMESTAMPTZ NOT NULL,
    unit_id INTEGER NOT NULL references units(id),
    instance TEXT NOT NULL,
    common_name TEXT NOT NULL,
    virtual_ip_addr TEXT NOT NULL,
    remote_ip_addr TEXT NOT NULL,
    start_time BIGINT NOT NULL,
    duration BIGINT,
    bytes_received BIGINT,
    bytes_sent BIGINT,
    country VARCHAR(2),
    UNIQUE (time, unit_id, instance, common_name),
    CONSTRAINT fk_unit FOREIGN KEY(unit_id) REFERENCES units(id) ON DELETE CASCADE
);

SELECT
    create_hypertable('ovpnrw_connections', by_range('time'), if_not_exists => TRUE);

-- Drop raw data after 30 days
SELECT remove_retention_policy('ovpnrw_connections', if_exists => TRUE);
SELECT add_retention_policy('ovpnrw_connections', drop_after => INTERVAL '30 days', if_not_exists => TRUE);

-- Continuous aggregates

CREATE MATERIALIZED VIEW IF NOT EXISTS ca_ovpnrw_connections_hourly_count
WITH (timescaledb.continuous) AS
SELECT unit_id,
   time_bucket(INTERVAL '1 hour', time) AS bucket,
   common_name,
   instance,
   count(common_name) as count
FROM ovpnrw_connections
GROUP BY unit_id, bucket, common_name, instance
WITH NO DATA;

SELECT add_continuous_aggregate_policy('ca_ovpnrw_connections_hourly_count',
  start_offset => NULL,
  end_offset => INTERVAL '30 minutes',
  schedule_interval => INTERVAL '15 minutes',
  if_not_exists => TRUE
);

SELECT remove_retention_policy('ca_ovpnrw_connections_hourly_count', if_exists => TRUE);
SELECT add_retention_policy('ca_ovpnrw_connections_hourly_count', drop_after => INTERVAL '60 days', if_not_exists => TRUE);

CREATE MATERIALIZED VIEW IF NOT EXISTS ca_ovpnrw_connections_hourly_bytes
WITH (timescaledb.continuous) AS
SELECT unit_id,
   time_bucket(INTERVAL '1 hour', time) AS bucket,
   common_name,
   instance,
   sum(bytes_received) as bytes_received,
   sum(bytes_sent) as bytes_sent
FROM ovpnrw_connections
GROUP BY unit_id, bucket, common_name, instance, bytes_received, bytes_sent
WITH NO DATA;

SELECT add_continuous_aggregate_policy('ca_ovpnrw_connections_hourly_bytes',
  start_offset => NULL,
  end_offset => INTERVAL '30 minutes',
  schedule_interval => INTERVAL '15 minutes',
  if_not_exists => TRUE
);

SELECT remove_retention_policy('ca_ovpnrw_connections_hourly_bytes', if_exists => TRUE);
SELECT add_retention_policy('ca_ovpnrw_connections_hourly_bytes', drop_after => INTERVAL '60 days', if_not_exists => TRUE);

----------------------
-- TS attacks
----------------------

CREATE TABLE IF NOT EXISTS ts_attacks (
    time TIMESTAMPTZ NOT NULL,
    unit_id INTEGER NOT NULL references units(id),
    ip TEXT NOT NULL,
    country VARCHAR(2),
    UNIQUE (time, unit_id, ip),
    CONSTRAINT fk_unit FOREIGN KEY(unit_id) REFERENCES units(id) ON DELETE CASCADE
);

SELECT
    create_hypertable('ts_attacks', by_range('time'), if_not_exists => TRUE);

-- Drop raw data after 30 days
SELECT remove_retention_policy('ts_attacks', if_exists => TRUE);
SELECT add_retention_policy('ts_attacks', drop_after => INTERVAL '30 days', if_not_exists => TRUE);

-- Continuous aggregates

CREATE MATERIALIZED VIEW IF NOT EXISTS ca_ts_attacks_hourly
WITH (timescaledb.continuous) AS
SELECT unit_id,
   time_bucket(INTERVAL '1 hour', time) AS bucket,
   count(ip) as count,
   country
FROM ts_attacks
GROUP BY unit_id, bucket, country
WITH NO DATA;

SELECT add_continuous_aggregate_policy('ca_ts_attacks_hourly',
  start_offset => NULL,
  end_offset => INTERVAL '30 minutes',
  schedule_interval => INTERVAL '15 minutes',
  if_not_exists => TRUE
);

SELECT remove_retention_policy('ca_ts_attacks_hourly', if_exists => TRUE);
SELECT add_retention_policy('ca_ts_attacks_hourly', drop_after => INTERVAL '60 days', if_not_exists => TRUE);

----------------------
-- DPI stats
----------------------

CREATE TABLE IF NOT EXISTS dpi_stats (
    time TIMESTAMPTZ NOT NULL,
    unit_id INTEGER NOT NULL references units(id),
    client_address TEXT NOT NULL,
    client_name TEXT,
    protocol TEXT,
    host TEXT,
    application TEXT,
    bytes BIGINT,
    UNIQUE (time, unit_id, client_address, protocol, host, application),
    CONSTRAINT fk_unit FOREIGN KEY(unit_id) REFERENCES units(id) ON DELETE CASCADE
);

SELECT
    create_hypertable('dpi_stats', by_range('time'), if_not_exists => TRUE);

-- Drop raw data after 30 days
SELECT remove_retention_policy('dpi_stats', if_exists => TRUE);
SELECT add_retention_policy('dpi_stats', drop_after => INTERVAL '30 days', if_not_exists => TRUE);

-- Continuous aggregates

CREATE MATERIALIZED VIEW IF NOT EXISTS ca_dpi_stats_hourly_bytes
WITH (timescaledb.continuous) AS
SELECT unit_id,
   time_bucket(INTERVAL '1 hour', time) AS bucket,
   sum(bytes) as bytes
FROM dpi_stats
GROUP BY unit_id, bucket
WITH NO DATA;

SELECT add_continuous_aggregate_policy('ca_dpi_stats_hourly_bytes',
  start_offset => NULL,
  end_offset => INTERVAL '30 minutes',
  schedule_interval => INTERVAL '15 minutes',
  if_not_exists => TRUE
);

SELECT remove_retention_policy('ca_dpi_stats_hourly_bytes', if_exists => TRUE);
SELECT add_retention_policy('ca_dpi_stats_hourly_bytes', drop_after => INTERVAL '60 days', if_not_exists => TRUE);

CREATE MATERIALIZED VIEW IF NOT EXISTS ca_dpi_stats_hourly_protocol
WITH (timescaledb.continuous) AS
SELECT unit_id,
   time_bucket(INTERVAL '1 hour', time) AS bucket,
   protocol,
   sum(bytes) as bytes
FROM dpi_stats
WHERE protocol != ''
GROUP BY unit_id, bucket, protocol
WITH NO DATA;

SELECT add_continuous_aggregate_policy('ca_dpi_stats_hourly_protocol',
  start_offset => NULL,
  end_offset => INTERVAL '30 minutes',
  schedule_interval => INTERVAL '15 minutes',
  if_not_exists => TRUE
);

SELECT remove_retention_policy('ca_dpi_stats_hourly_protocol', if_exists => TRUE);
SELECT add_retention_policy('ca_dpi_stats_hourly_protocol', drop_after => INTERVAL '60 days', if_not_exists => TRUE);

CREATE MATERIALIZED VIEW IF NOT EXISTS ca_dpi_stats_hourly_host
WITH (timescaledb.continuous) AS
SELECT unit_id,
   time_bucket(INTERVAL '1 hour', time) AS bucket,
   host,
   sum(bytes) as bytes
FROM dpi_stats
WHERE host != ''
GROUP BY unit_id, bucket, host
WITH NO DATA;

SELECT add_continuous_aggregate_policy('ca_dpi_stats_hourly_host',
  start_offset => NULL,
  end_offset => INTERVAL '30 minutes',
  schedule_interval => INTERVAL '15 minutes',
  if_not_exists => TRUE
);

SELECT remove_retention_policy('ca_dpi_stats_hourly_host', if_exists => TRUE);
SELECT add_retention_policy('ca_dpi_stats_hourly_host', drop_after => INTERVAL '60 days', if_not_exists => TRUE);

CREATE MATERIALIZED VIEW IF NOT EXISTS ca_dpi_stats_hourly_application
WITH (timescaledb.continuous) AS
SELECT unit_id,
   time_bucket(INTERVAL '1 hour', time) AS bucket,
   application,
   sum(bytes) as bytes
FROM dpi_stats
WHERE application != ''
GROUP BY unit_id, bucket, application
WITH NO DATA;

SELECT add_continuous_aggregate_policy('ca_dpi_stats_hourly_application',
  start_offset => NULL,
  end_offset => INTERVAL '30 minutes',
  schedule_interval => INTERVAL '15 minutes',
  if_not_exists => TRUE
);

SELECT remove_retention_policy('ca_dpi_stats_hourly_application', if_exists => TRUE);
SELECT add_retention_policy('ca_dpi_stats_hourly_application', drop_after => INTERVAL '60 days', if_not_exists => TRUE);

CREATE MATERIALIZED VIEW IF NOT EXISTS ca_dpi_stats_hourly_client
WITH (timescaledb.continuous) AS
SELECT unit_id,
   time_bucket(INTERVAL '1 hour', time) AS bucket,
   client_address,
   client_name,
   sum(bytes) as bytes
FROM dpi_stats
WHERE client_address != ''
GROUP BY unit_id, bucket, client_address, client_name
WITH NO DATA;

SELECT add_continuous_aggregate_policy('ca_dpi_stats_hourly_client',
  start_offset => NULL,
  end_offset => INTERVAL '30 minutes',
  schedule_interval => INTERVAL '15 minutes',
  if_not_exists => TRUE
);

SELECT remove_retention_policy('ca_dpi_stats_hourly_client', if_exists => TRUE);
SELECT add_retention_policy('ca_dpi_stats_hourly_client', drop_after => INTERVAL '60 days', if_not_exists => TRUE);
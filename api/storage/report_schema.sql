/*
 * Copyright (C) 2024 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Giacomo Sanchietti <giacomo.sanchietti@nethesis.it>
 */
CREATE TABLE IF NOT EXISTS units (
    id SERIAL PRIMARY KEY,
    uuid TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mwan_events (
    time TIMESTAMPTZ NOT NULL,
    unit_id INTEGER NOT NULL references units(id),
    wan TEXT NOT NULL,
    event TEXT NOT NULL,
    interface TEXT,
    UNIQUE (time, unit_id),
    CONSTRAINT fk_unit FOREIGN KEY(unit_id) REFERENCES units(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ts_malware (
    time TIMESTAMPTZ NOT NULL,
    unit_id INTEGER NOT NULL references units(id),
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    category TEXT NOT NULL,
    chain TEXT NOT NULL,
    UNIQUE (time, unit_id),
    CONSTRAINT fk_unit FOREIGN KEY(unit_id) REFERENCES units(id) ON DELETE CASCADE
);

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
    UNIQUE (time, unit_id, instance, common_name),
    CONSTRAINT fk_unit FOREIGN KEY(unit_id) REFERENCES units(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ts_attacks (
    time TIMESTAMPTZ NOT NULL,
    unit_id INTEGER NOT NULL references units(id),
    ip TEXT NOT NULL,
    UNIQUE (time, unit_id, ip),
    CONSTRAINT fk_unit FOREIGN KEY(unit_id) REFERENCES units(id) ON DELETE CASCADE
);

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
    create_hypertable('mwan_events', by_range('time'), if_not_exists => TRUE);

SELECT
    create_hypertable('ts_malware', by_range('time'), if_not_exists => TRUE);

SELECT
    create_hypertable('ovpnrw_connections', by_range('time'), if_not_exists => TRUE);

SELECT
    create_hypertable('ts_attacks', by_range('time'), if_not_exists => TRUE);

SELECT
    create_hypertable('dpi_stats', by_range('time'), if_not_exists => TRUE);
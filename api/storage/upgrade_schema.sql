/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Giacomo Sanchietti <giacomo.sanchietti@nethesis.it>
 */


ALTER TABLE units ADD COLUMN IF NOT EXISTS info JSONB;
ALTER TABLE units ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE units ADD COLUMN IF NOT EXISTS vpn_address TEXT;
ALTER TABLE units ADD COLUMN IF NOT EXISTS vpn_connected_since TIMESTAMP NULL;
/* Remove foreign key constraints: the cascade trigger causes very slow deletes */
ALTER TABLE openvpn_config
    DROP CONSTRAINT IF EXISTS openvpn_config_uuid_fkey,
    DROP CONSTRAINT IF EXISTS fk_unit;
ALTER TABLE wan_config
    DROP CONSTRAINT IF EXISTS wan_config_uuid_fkey,
    DROP CONSTRAINT IF EXISTS fk_unit;
ALTER TABLE mwan_events
    DROP CONSTRAINT IF EXISTS mwan_events_uuid_fkey,
    DROP CONSTRAINT IF EXISTS fk_unit;
ALTER TABLE ts_malware
    DROP CONSTRAINT IF EXISTS ts_malware_uuid_fkey,
    DROP CONSTRAINT IF EXISTS fk_unit;
ALTER TABLE ovpnrw_connections
    DROP CONSTRAINT IF EXISTS ovpnrw_connections_uuid_fkey,
    DROP CONSTRAINT IF EXISTS fk_unit;
ALTER TABLE ts_attacks
    DROP CONSTRAINT IF EXISTS ts_attacks_uuid_fkey,
    DROP CONSTRAINT IF EXISTS fk_unit;
ALTER TABLE dpi_stats
    DROP CONSTRAINT IF EXISTS dpi_stats_uuid_fkey,
    DROP CONSTRAINT IF EXISTS fk_unit;

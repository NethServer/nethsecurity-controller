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
/* Add missing constraints to existing tables */
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.table_constraints
        WHERE constraint_name = 'openvpn_config_uuid_fkey'
          AND table_name = 'openvpn_config'
    ) THEN
        ALTER TABLE openvpn_config
            DROP CONSTRAINT openvpn_config_uuid_fkey,
            ADD CONSTRAINT fk_unit FOREIGN KEY(uuid) REFERENCES units(uuid) ON DELETE CASCADE;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM information_schema.table_constraints
        WHERE constraint_name = 'wan_config_uuid_fkey'
          AND table_name = 'wan_config'
    ) THEN
        ALTER TABLE wan_config
            DROP CONSTRAINT wan_config_uuid_fkey,
            ADD CONSTRAINT fk_unit FOREIGN KEY(uuid) REFERENCES units(uuid) ON DELETE CASCADE;
    END IF;
END$$;
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
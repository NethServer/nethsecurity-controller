/*
 * Copyright (C) 2024 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Edoardo Spadoni <edoardo.spadoni@nethesis.it>
 */

CREATE TABLE accounts (
    `id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    `username` TEXT NOT NULL UNIQUE,
    `password` TEXT NOT NULL,
    `display_name` TEXT,
    `created` TIMESTAMP NOT NULL
);

CREATE TABLE units (
    `id` TEXT NOT NULL PRIMARY KEY,
    `name` TEXT NOT NULL UNIQUE,
    `version` TEXT NOT NULL,
    `system_id` TEXT,
    `subscription_type` TEXT,
    `created` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
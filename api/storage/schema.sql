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
    `locked` BOOLEAN NOT NULL,
    `created` TIMESTAMP NOT NULL
);

CREATE TABLE units (
    `id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    `name` TEXT NOT NULL,
    `label` TEXT NOT NULL,
    `created` TIMESTAMP NOT NULL
);

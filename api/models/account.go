/*
 * Copyright (C) 2024 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Edoardo Spadoni <edoardo.spadoni@nethesis.it>
 */

package models

import (
	"time"
)

type Account struct {
	ID          int       `json:"id" structs:"id"`
	Username    string    `json:"username" structs:"username" binding:"required"`
	Password    string    `json:"password" structs:"password" db:"-" binding:"required"`
	DisplayName string    `json:"display_name" structs:"display_name"`
	Locked      bool      `json:"locked" structs:"locked"`
	Created     time.Time `json:"created" structs:"created"`
}

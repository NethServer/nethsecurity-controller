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
	Username    string    `json:"username" structs:"username" binding:"required,excludesall= "`
	Password    string    `json:"password" structs:"password" db:"-" binding:"required"`
	DisplayName string    `json:"display_name" structs:"display_name"`
	Created     time.Time `json:"created" structs:"created"`
	TwoFA       bool      `json:"2fa" structs:"2fa"`
}

type AccountUpdate struct {
	Password    string `json:"password" structs:"password"`
	DisplayName string `json:"display_name" structs:"display_name"`
}

type PasswordChange struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

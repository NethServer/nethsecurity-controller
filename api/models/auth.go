/*
 * Copyright (C) 2024 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Edoardo Spadoni <edoardo.spadoni@nethesis.it>
 */

package models

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	Code   int    `json:"code" binding:"required"`
	Expire string `json:"expire" binding:"required"`
	Token  string `json:"token" binding:"required"`
}

type SSHGenerate struct {
	Passphrase string `json:"passphrase" binding:"required"`
}

type SSHConnect struct {
	UnitID     string `json:"unit_id" binding:"required"`
	Passphrase string `json:"passphrase" binding:"required"`
}

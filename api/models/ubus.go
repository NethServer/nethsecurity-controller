/*
 * Copyright (C) 2024 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Giacomo Sanchietti <giacomo.sanchietti@nethesis.it>
 */

package models

type UbusCommand struct {
	Path    string                 `json:"path" binding:"required"`
	Method  string                 `json:"method" binding:"required"`
	Payload map[string]interface{} `json:"payload" binding:"required"`
}

// Response example:
// {"code":200,"data":{"depends": "on the call"},"message":"ubus call action success"}
type UbusResponse[T any] struct {
	Code    int    `json:"code"`
	Data    T      `json:"data"`
	Message string `json:"message"`
}

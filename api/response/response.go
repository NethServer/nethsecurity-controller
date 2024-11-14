/*
 * Copyright (C) 2024 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-2.0-only
 */

package response

type StatusOK struct {
	Code    int         `json:"code" example:"200" structs:"code"`
	Message string      `json:"message" example:"Success" structs:"message"`
	Data    interface{} `json:"data" structs:"data"`
}

type StatusBadRequest struct {
	Code    int         `json:"code" example:"400" structs:"code"`
	Message string      `json:"message" example:"Bad request" structs:"message"`
	Data    interface{} `json:"data" structs:"data"`
}

type StatusNotFound struct {
	Code    int         `json:"code" example:"404" structs:"code"`
	Message string      `json:"message" example:"Not found" structs:"message"`
	Data    interface{} `json:"data" structs:"data"`
}

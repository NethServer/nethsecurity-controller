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
// {"code":200,"data":{"fqdn":"NethSec","ssh_port":22,"subscription_type":"","system_id":"","unit_name":"","version":""},"message":"ubus call action success"}
type UbusInfoResponse struct {
	Code    int      `json:"code"`
	Data    UnitInfo `json:"data"`
	Message string   `json:"message"`
}

type UnitInfo struct {
	UnitName         string `json:"unit_name"`
	Version          string `json:"version"`
	SubscriptionType string `json:"subscription_type"`
	SystemID         string `json:"system_id"`
	SSHPort          int    `json:"ssh_port"`
	FQDN             string `json:"fqdn"`
}

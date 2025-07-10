/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Giacomo Sanchietti <giacomo.sanchietti@nethesis.it>
 */

package models

type PlatformInfo struct {
	VpnPort              string `json:"vpn_port" structs:"vpn_port"`
	VpnNetwork           string `json:"vpn_network" structs:"vpn_network"`
	ControllerVersion    string `json:"controller_version" structs:"controller_version"`
	MetricsRetentionDays int    `json:"metrics_retention_days" structs:"metrics_retention_days"`
	LogsRetentionDays    int    `json:"logs_retention_days" structs:"logs_retention_days"`
}

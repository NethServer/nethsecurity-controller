/*
 * Copyright (C) 2024 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Giacomo Sanchietti <giacomo.sanchietti@nethesis.it>
 */

package models

type MwanEvent struct {
	Timestamp int64  `json:"timestamp" binding:"required"`
	Wan       string `json:"wan" binding:"required"`
	Interface string `json:"interface" binding:"required"`
	Event     string `json:"event" binding:"required"`
}

type MwanEvents []MwanEvent

type MwanEventRequest struct {
	Data MwanEvents `json:"data" binding:"required"`
}

type TsAttack struct {
	Timestamp int64  `json:"timestamp" binding:"required"`
	Ip        string `json:"ip" binding:"required"`
}

type TsAttacks []TsAttack

type TsAttackRequest struct {
	Data TsAttacks `json:"data" binding:"required"`
}

type TsMalware struct {
	Timestamp int64  `json:"timestamp" binding:"required"`
	Src       string `json:"src" binding:"required"`
	Dst       string `json:"dst" binding:"required"`
	Category  string `json:"category" binding:"required"`
	Chain     string `json:"chain" binding:"required"`
}

type TsMalwares []TsMalware

type TsMalwareRequest struct {
	Data TsMalwares `json:"data" binding:"required"`
}

type OvpnRwConnection struct {
	Timestamp     int64  `json:"timestamp" binding:"required"`
	Instance      string `json:"instance" binding:"required"`
	CommonName    string `json:"common_name" binding:"required"`
	VirtualIpAddr string `json:"virtual_ip_addr" binding:"required"`
	RemoteIpAddr  string `json:"remote_ip_addr" binding:"required"`
	StartTime     int64  `json:"start_time" binding:"required"`
	Duration      int64  `json:"duration" binding:"required"`
	BytesReceived int64  `json:"bytes_received" binding:"required"`
	BytesSent     int64  `json:"bytes_sent" binding:"required"`
}

type OvpnRwConnections []OvpnRwConnection

type OvpnRwConnectionsRequest struct {
	Data OvpnRwConnections `json:"data" binding:"required"`
}

type DpiStat struct {
	Timestamp     int64  `json:"timestamp" binding:"required"`
	ClientAddress string `json:"client_address" binding:"required"`
	ClientName    string `json:"client_name" binding:"required"`
	Protocol      string `json:"protocol"`
	Host          string `json:"host"`
	Application   string `json:"application"`
	Bytes         int64  `json:"bytes" binding:"required"`
}

type DpiStats []DpiStat

type DpiStatsRequest struct {
	Data DpiStats `json:"data" binding:"required"`
}

type UnitNameRequest struct {
	Name string `json:"name" binding:"required"`
}

type OpenVPNConfiguration struct {
	Instance string `json:"instance" binding:"required"`
	Name     string `json:"name" binding:"required"`
	Device   string `json:"device" binding:"required"`
	Type     string `json:"type"` // valid values are: rw (for roadwarrior), client (for tunnel client), server (for tunnel server)
}

type OpenVPNConfigurations []OpenVPNConfiguration

type UnitOpenVPNRWRequest struct {
	Data OpenVPNConfigurations `json:"data" binding:"required"`
}

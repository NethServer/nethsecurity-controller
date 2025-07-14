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

type AddRequest struct {
	UnitId string `json:"unit_id" binding:"required"`
}

type RegisterRequest struct {
	UnitId           string `json:"unit_id" binding:"required"`
	Username         string `json:"username" binding:"required"`
	Password         string `json:"password" binding:"required"`
	UnitName         string `json:"unit_name" binding:"required"`
	Version          string `json:"version"`
	SubscriptionType string `json:"subscription_type"`
	SystemId         string `json:"system_id"`
}

type Unit struct {
	ID               string    `json:"unit_id" structs:"id"`
	Name             string    `json:"unit_name" structs:"name"`
	Version          string    `json:"version" structs:"version"`
	SubscriptionType string    `json:"subscription_type" structs:"subscription_type"`
	SystemID         string    `json:"system_id" structs:"system_id"`
	Created          time.Time `json:"created" structs:"created"`
}

type UnitInfo struct {
	UnitName         string `json:"unit_name"`
	Version          string `json:"version"`
	VersionUpdate    string `json:"version_update"`
	ScheduledUpdate  int    `json:"scheduled_update"`
	SubscriptionType string `json:"subscription_type"`
	SystemID         string `json:"system_id"`
	SSHPort          int    `json:"ssh_port"`
	FQDN             string `json:"fqdn"`
	APIVersion       string `json:"api_version"`
	Description      string `json:"description"`
}

type CheckSystemUpdate struct {
	LastVersion    string `json:"lastVersion"`
	ScheduledAt    int    `json:"scheduledAt"`
	CurrentVersion string `json:"currentVersion"`
}

type UnitGroup struct {
	ID          int       `json:"id" structs:"id"`
	Name        string    `json:"name" structs:"name"`
	Description string    `json:"description" structs:"description"`
	Units       []string  `json:"units" structs:"units"`
	CreatedAt   time.Time `json:"created_at" structs:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" structs:"updated_at"`
	UsedBy      []string  `json:"used_by" structs:"used_by"`
}

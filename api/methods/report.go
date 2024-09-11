/*
 * Copyright (C) 2024 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Giacomo Sanchietti <giacomo.sanchietti@nethesis.it>
 */

package methods

import (
	"net"
	"net/http"
	"time"

	"github.com/NethServer/nethsecurity-api/response"
	"github.com/NethServer/nethsecurity-controller/api/logs"
	"github.com/NethServer/nethsecurity-controller/api/models"
	"github.com/NethServer/nethsecurity-controller/api/storage"
	"github.com/NethServer/nethsecurity-controller/api/utils"
	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
)

func SetUnitName(c *gin.Context) {
	// bind json
	var req models.UnitNameRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "Invalid request",
			Data:    err.Error(),
		}))
		return
	}
	unitId := c.MustGet("UnitId").(string)
	var id int
	dbpool, dbctx := storage.ReportInstance()
	// check if unit_id is valid
	err := dbpool.QueryRow(dbctx, "SELECT id FROM units WHERE uuid = $1", unitId).Scan(&id)
	if err != nil {
		// insert a new unit and return the id
		err := dbpool.QueryRow(dbctx, "INSERT INTO units (uuid, name) VALUES ($1, $2) RETURNING id", unitId, req.Name).Scan(&id)
		if err != nil {
			logs.Logs.Println("[ERR][UNITNAME] error inserting unit name: " + err.Error())
		}
	} else {
		// update the unit name
		_, err := dbpool.Exec(dbctx, "UPDATE units SET name = $1 WHERE uuid = $2", req.Name, unitId)
		if err != nil {
			logs.Logs.Println("[ERR][UNITNAME] error updating unit name: " + err.Error())
		}
	}
}

func getUnitId(unitId string) int {
	if unitId == "" {
		return -1
	}
	var id int
	dbpool, dbctx := storage.ReportInstance()

	// check if unit_id is valid
	err := dbpool.QueryRow(dbctx, "SELECT id FROM units WHERE uuid = $1", unitId).Scan(&id)
	if err != nil {
		// insert a new unit and return the id
		err := dbpool.QueryRow(dbctx, "INSERT INTO units (uuid) VALUES ($1) RETURNING id", unitId).Scan(&id)
		if err != nil {
			return -1
		}
	}

	return id
}

func UpdateMwanSeries(c *gin.Context) {
	// bind json
	var req models.MwanEventRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "Invalid request",
			Data:    err.Error(),
		}))
		return
	}

	unit_id := getUnitId(c.MustGet("UnitId").(string))
	if unit_id == -1 {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Message: "Unit not found",
			Data:    nil,
			Code:    404,
		}))
		return
	}

	dbpool, dbctx := storage.ReportInstance()
	// To prevent performance issues, do not use single insert
	// CopyFrom can't handle conflict resolution, so use batch insert instead
	batch := &pgx.Batch{}
	for _, event := range req.Data {
		// skip invalid objects
		if event.Timestamp == 0 || event.Wan == "" || event.Event == "" {
			logs.Logs.Println("[WARN][MWANEVENTS] skipping invalid object")
			continue
		}
		batch.Queue("INSERT INTO mwan_events (time, unit_id, wan, event, interface) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING", time.Unix(event.Timestamp, 0), unit_id, event.Wan, event.Event, event.Interface)
	}
	if batch.Len() != 0 {
		err := dbpool.SendBatch(dbctx, batch).Close()
		if err != nil {
			logs.Logs.Println("[ERR][MWANEVENTS] error inserting data: " + err.Error())
			c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
				Message: "Error inserting data",
				Data:    err.Error(),
				Code:    500,
			}))
			return
		}
	}

	// return ok
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "success",
		Data:    nil,
	}))
}

func UpdateTsAttacks(c *gin.Context) {
	// bind json
	var req models.TsAttackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "Invalid request: data field not found",
			Data:    err.Error(),
		}))
		return
	}

	unit_id := getUnitId(c.MustGet("UnitId").(string))
	if unit_id == -1 {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Message: "Unit not found",
			Data:    nil,
			Code:    404,
		}))
		return
	}

	dbpool, dbctx := storage.ReportInstance()
	// To prevent performance issues, do not use single insert
	// CopyFrom can't handle conflict resolution, so use batch insert instead
	batch := &pgx.Batch{}

	for _, attack := range req.Data {
		country := ""
		// skip invalid objects
		if attack.Timestamp == 0 || attack.Ip == "" {
			logs.Logs.Println("[WARN][TSATTACKS] skipping invalid object")
			continue
		}
		country = utils.GetCountryShort(attack.Ip)
		batch.Queue("INSERT INTO ts_attacks (time, unit_id, ip) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING", time.Unix(attack.Timestamp, 0), unit_id, attack.Ip, country)
	}
	if batch.Len() != 0 {
		err := dbpool.SendBatch(dbctx, batch).Close()
		if err != nil {
			logs.Logs.Println("[ERR][TSATTACKS] error inserting data: " + err.Error())
			c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
				Message: "Error inserting data",
				Data:    err.Error(),
				Code:    500,
			}))
			return
		}
	}

	// return ok
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "success",
		Data:    nil,
	}))
}

func UpdateTsMalware(c *gin.Context) {
	// bind json
	var req models.TsMalwareRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "Invalid request: data field not found",
			Data:    err.Error(),
		}))
		return
	}

	unit_id := getUnitId(c.MustGet("UnitId").(string))
	if unit_id == -1 {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Message: "Unit not found",
			Data:    nil,
			Code:    404,
		}))
		return
	}

	dbpool, dbctx := storage.ReportInstance()
	// To prevent performance issues, do not use single insert
	// CopyFrom can't handle conflict resolution, so use batch insert instead
	batch := &pgx.Batch{}
	for _, malware := range req.Data {
		country := ""
		// skip invalid objects
		if malware.Timestamp == 0 || malware.Src == "" || malware.Dst == "" || malware.Category == "" || malware.Chain == "" {
			logs.Logs.Println("[WARN][TSMALWARE] skipping invalid object")
			continue
		}

		// GeoIP info
		if malware.Chain == "inp-wan" {
			// Retrieve GeoIP country code for source when traffic is destined to the WAN
			country = utils.GetCountryShort(malware.Src)
		} else {
			// Retrieve GeoIP country code for non-private IP when traffic is forwarded
			if !net.ParseIP(malware.Dst).IsPrivate() {
				country = utils.GetCountryShort(malware.Dst)
			} else if !net.ParseIP(malware.Src).IsPrivate() {
				country = utils.GetCountryShort(malware.Src)
			}
		}

		batch.Queue("INSERT INTO ts_malware (time, unit_id, src, dst, category, chain, country) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING", time.Unix(malware.Timestamp, 0), unit_id, malware.Src, malware.Dst, malware.Category, malware.Chain, country)
	}
	if batch.Len() != 0 {
		err := dbpool.SendBatch(dbctx, batch).Close()
		if err != nil {
			logs.Logs.Println("[ERR][TSMALWARE] error inserting data: " + err.Error())
			c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
				Message: "Error inserting data",
				Data:    err.Error(),
				Code:    500,
			}))
			return
		}
	}

	// return ok
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "success",
		Data:    nil,
	}))
}

func UpdateOvpnConnections(c *gin.Context) {
	// bind json
	var req models.OvpnRwConnectionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "Invalid request: data field not found",
			Data:    err.Error(),
		}))
		return
	}

	unit_id := getUnitId(c.MustGet("UnitId").(string))
	if unit_id == -1 {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Message: "Unit not found",
			Data:    nil,
			Code:    404,
		}))
		return
	}

	dbpool, dbctx := storage.ReportInstance()
	// To prevent performance issues, do not use single insert
	// CopyFrom can't handle conflict resolution, so use batch insert instead
	batch := &pgx.Batch{}
	for _, connection := range req.Data {
		country := ""
		// skip invalid objects
		if connection.Timestamp == 0 || connection.Instance == "" || connection.CommonName == "" || connection.StartTime == 0 {
			logs.Logs.Println("[WARN][OVPNCONNECTIONS] skipping invalid object")
			continue
		}
		// GeoIP info for the remote IP
		country = utils.GetCountryShort(connection.RemoteIpAddr)
		batch.Queue("INSERT INTO ovpnrw_connections (time, unit_id, instance, common_name, virtual_ip_addr, remote_ip_addr, start_time, duration, bytes_received, bytes_sent, country) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT  (time, unit_id, instance, common_name) DO UPDATE SET duration=EXCLUDED.duration, bytes_received=EXCLUDED.bytes_received, bytes_sent=EXCLUDED.bytes_sent", time.Unix(connection.Timestamp, 0), unit_id, connection.Instance, connection.CommonName, connection.VirtualIpAddr, connection.RemoteIpAddr, connection.StartTime, connection.Duration, connection.BytesReceived, connection.BytesSent, country)
	}
	if batch.Len() != 0 {
		err := dbpool.SendBatch(dbctx, batch).Close()
		if err != nil {
			logs.Logs.Println("[ERR][OVPNCONNECTIONS] error inserting data: " + err.Error())
			c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
				Message: "Error inserting data",
				Data:    err.Error(),
				Code:    500,
			}))
			return
		}
	}

	// return ok
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "success",
		Data:    nil,
	}))
}

func UpdateDpiStats(c *gin.Context) {
	// bind json
	var req models.DpiStatsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "Invalid request: data field not found",
			Data:    err.Error(),
		}))
		return
	}

	unit_id := getUnitId(c.MustGet("UnitId").(string))
	if unit_id == -1 {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Message: "Unit not found",
			Data:    nil,
			Code:    404,
		}))
		return
	}

	dbpool, dbctx := storage.ReportInstance()
	// To prevent performance issues, do not use single insert
	// CopyFrom can't handle conflict resolution, so use batch insert instead
	// do not use CopyFrom
	batch := &pgx.Batch{}
	for _, dpi := range req.Data {
		// skip invalid objects
		if dpi.Timestamp == 0 || dpi.ClientAddress == "" || dpi.Bytes == 0 {
			logs.Logs.Println("[WARN][DPISTATS] skipping invalid object")
			continue
		}
		batch.Queue("INSERT INTO dpi_stats (time, unit_id, client_address, client_name, protocol, host, application, bytes) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (time, unit_id, client_address, protocol, host, application) DO UPDATE SET bytes = EXCLUDED.bytes", time.Unix(dpi.Timestamp, 0), unit_id, dpi.ClientAddress, dpi.ClientName, dpi.Protocol, dpi.Host, dpi.Application, dpi.Bytes)
	}
	if batch.Len() != 0 {
		err := dbpool.SendBatch(dbctx, batch).Close()
		if err != nil {
			logs.Logs.Println("[ERR][DPISTATS] error inserting data: " + err.Error())
			c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
				Message: "Error inserting data",
				Data:    err.Error(),
				Code:    500,
			}))
			return
		}
	}

	// return ok
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "success",
		Data:    nil,
	}))
}

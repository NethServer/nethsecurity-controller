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
	"context"
	"errors"
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
	"github.com/jackc/pgx/v5/pgxpool"
)

func setUnitName(dbpool *pgxpool.Pool, dbctx context.Context, c *gin.Context) (int, error) {
	// bind json
	var req models.UnitNameRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		return 400, errors.New("invalid request")
	}

	// check if uuid is valid
	unitId := c.MustGet("UnitId").(string)
	var uuid string
	err := dbpool.QueryRow(dbctx, "SELECT uuid FROM units WHERE uuid = $1", unitId).Scan(&uuid)
	if err != nil || uuid != unitId {
		// insert a new unit and return the id
		_, err := dbpool.Exec(dbctx, "INSERT INTO units (uuid, name) VALUES ($1, $2)", unitId, req.Name)
		if err != nil {
			return 500, errors.New("error inserting unit name: " + err.Error())
		}
	} else {
		// update the unit name
		_, err := dbpool.Exec(dbctx, "UPDATE units SET name = $1 WHERE uuid = $2", req.Name, unitId)
		if err != nil {
			return 500, errors.New("error updating unit name: " + err.Error())
		}
	}
	return 200, nil
}

func setUnitOvpnConfig(dbpool *pgxpool.Pool, dbctx context.Context, c *gin.Context) (int, error) {
	var req models.UnitOpenVPNRWRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		return 400, errors.New("invalid request")
	}

	// Remove all previous data
	_, err := dbpool.Exec(dbctx, "DELETE FROM openvpn_config WHERE uuid = $1", c.MustGet("UnitId").(string))
	if err != nil {
		logs.Logs.Println("[ERR][UNITOVPNCONFIG] error deleting previous data: " + err.Error())
		return 500, errors.New("error deleting previous data")
	}

	// insert inside OpenVPN table
	for _, server := range req.Data {
		_, err := dbpool.Exec(dbctx, "INSERT INTO openvpn_config (uuid, instance, name, device, type) VALUES ($1, $2, $3, $4, $5)", c.MustGet("UnitId").(string), server.Instance, server.Name, server.Device, server.Type)
		if err != nil {
			logs.Logs.Println("[ERR][UNITOVPNCONFIG] error inserting data: " + err.Error())
			return 500, errors.New("error inserting data")
		}
	}
	return 200, nil
}

func setUnitWan(dbpool *pgxpool.Pool, dbctx context.Context, c *gin.Context) (int, error) {
	// bind json
	var req models.UnitWanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		return 400, errors.New("invalid request")
	}

	// Remove all previous data
	_, err := dbpool.Exec(dbctx, "DELETE FROM wan_config WHERE uuid = $1", c.MustGet("UnitId").(string))
	if err != nil {
		logs.Logs.Println("[ERR][UNITWAN] error deleting previous data: " + err.Error())
		return 500, errors.New("error deleting previous data")
	}
	// Insert inside WAN table
	for _, wan := range req.Data {
		_, err := dbpool.Exec(dbctx, "INSERT INTO wan_config (uuid, interface, device, status) VALUES ($1, $2, $3, $4)", c.MustGet("UnitId").(string), wan.Interface, wan.Device, wan.Status)
		if err != nil {
			logs.Logs.Println("[ERR][UNITWAN] error inserting data: " + err.Error())
			return 500, errors.New("error inserting data")
		}
	}
	return 200, nil
}

func updateMwanSeries(dbpool *pgxpool.Pool, dbctx context.Context, c *gin.Context) (int, error) {
	// bind json
	var req models.MwanEventRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		return 400, errors.New("invalid request")
	}

	// To prevent performance issues, do not use single insert
	// CopyFrom can't handle conflict resolution, so use batch insert instead
	batch := &pgx.Batch{}
	for _, event := range req.Data {
		// skip invalid objects
		if event.Timestamp == 0 || event.Wan == "" || event.Event == "" {
			logs.Logs.Println("[WARN][MWANEVENTS] skipping invalid object")
			continue
		}
		batch.Queue("INSERT INTO mwan_events (time, uuid, wan, event, interface) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING", time.Unix(event.Timestamp, 0), c.MustGet("UnitId").(string), event.Wan, event.Event, event.Interface)
	}
	if batch.Len() != 0 {
		err := dbpool.SendBatch(dbctx, batch).Close()
		if err != nil {
			logs.Logs.Println("[ERR][MWANEVENTS] error inserting data: " + err.Error())
			return 500, errors.New("error inserting data")
		}
	}

	return 200, nil
}

func updateTsAttacks(dbpool *pgxpool.Pool, dbctx context.Context, c *gin.Context) (int, error) {
	// bind json
	var req models.TsAttackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		return 400, errors.New("invalid request")
	}

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
		batch.Queue("INSERT INTO ts_attacks (time, uuid, ip, country) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING", time.Unix(attack.Timestamp, 0), c.MustGet("UnitId").(string), attack.Ip, country)
	}
	if batch.Len() != 0 {
		err := dbpool.SendBatch(dbctx, batch).Close()
		if err != nil {
			logs.Logs.Println("[ERR][TSATTACKS] error inserting data: " + err.Error())
			return 500, errors.New("error inserting data")
		}
	}

	return 200, nil
}

func updateTsMalware(dbpool *pgxpool.Pool, dbctx context.Context, c *gin.Context) (int, error) {
	// bind json
	var req models.TsMalwareRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		return 400, errors.New("invalid request")
	}

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

		batch.Queue("INSERT INTO ts_malware (time, uuid, src, dst, category, chain, country) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING", time.Unix(malware.Timestamp, 0), c.MustGet("UnitId").(string), malware.Src, malware.Dst, malware.Category, malware.Chain, country)
	}
	if batch.Len() != 0 {
		err := dbpool.SendBatch(dbctx, batch).Close()
		if err != nil {
			logs.Logs.Println("[ERR][TSMALWARE] error inserting data: " + err.Error())
			return 500, errors.New("error inserting data")
		}
	}

	return 200, nil
}

func updateOvpnConnections(dbpool *pgxpool.Pool, dbctx context.Context, c *gin.Context) (int, error) {
	// bind json
	var req models.OvpnRwConnectionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		return 400, errors.New("invalid request")
	}

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
		batch.Queue("INSERT INTO ovpnrw_connections (time, uuid, instance, common_name, virtual_ip_addr, remote_ip_addr, start_time, duration, bytes_received, bytes_sent, country) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT  (time, uuid, instance, common_name) DO UPDATE SET duration=EXCLUDED.duration, bytes_received=EXCLUDED.bytes_received, bytes_sent=EXCLUDED.bytes_sent", time.Unix(connection.Timestamp, 0), c.MustGet("UnitId").(string), connection.Instance, connection.CommonName, connection.VirtualIpAddr, connection.RemoteIpAddr, connection.StartTime, connection.Duration, connection.BytesReceived, connection.BytesSent, country)
	}
	if batch.Len() != 0 {
		err := dbpool.SendBatch(dbctx, batch).Close()
		if err != nil {
			logs.Logs.Println("[ERR][OVPNCONNECTIONS] error inserting data: " + err.Error())
			return 500, errors.New("error inserting data")
		}
	}
	return 200, nil
}

func updateDpiStats(dbpool *pgxpool.Pool, dbctx context.Context, c *gin.Context) (int, error) {
	// bind json
	var req models.DpiStatsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		return 400, errors.New("invalid request")
	}

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
		batch.Queue("INSERT INTO dpi_stats (time, uuid, client_address, client_name, protocol, host, application, bytes) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (time, uuid, client_address, protocol, host, application) DO UPDATE SET bytes = EXCLUDED.bytes", time.Unix(dpi.Timestamp, 0), c.MustGet("UnitId").(string), dpi.ClientAddress, dpi.ClientName, dpi.Protocol, dpi.Host, dpi.Application, dpi.Bytes)
	}
	if batch.Len() != 0 {
		err := dbpool.SendBatch(dbctx, batch).Close()
		if err != nil {
			logs.Logs.Println("[ERR][DPISTATS] error inserting data: " + err.Error())
			return 500, errors.New("error inserting data")
		}
	}

	return 200, nil
}

func HandelMonitoring(c *gin.Context) {
	var err error
	var code int
	unitId := c.MustGet("UnitId").(string)

	dbpool, dbctx := storage.ReportInstance()

	firewall_api := c.Param("firewall_api")
	// setting unit name and creating a unit if it does not exist
	if firewall_api == "dump-nsplug-config" {
		code, err = setUnitName(dbpool, dbctx, c)
	} else {
		// for all other metrics, check if the unit exists
		var uuid string
		err = dbpool.QueryRow(dbctx, "SELECT uuid FROM units WHERE uuid = $1", unitId).Scan(&uuid)
		if err != nil {
			err = errors.New("unit not found")
			code = 404
		} else {
			// the unit exists, handle the metric
			switch firewall_api {
			case "dump-ovpn-config":
				code, err = setUnitOvpnConfig(dbpool, dbctx, c)
			case "dump-wan-config":
				code, err = setUnitWan(dbpool, dbctx, c)
			case "dump-ts-malware":
				code, err = updateTsMalware(dbpool, dbctx, c)
			case "dump-ts-attacks":
				code, err = updateTsAttacks(dbpool, dbctx, c)
			case "dump-mwan-events":
				code, err = updateMwanSeries(dbpool, dbctx, c)
			case "dump-dpi-stats":
				code, err = updateDpiStats(dbpool, dbctx, c)
			case "dump-ovpn-connections":
				code, err = updateOvpnConnections(dbpool, dbctx, c)
			default:
				code = 404
				err = errors.New("metric not found")
			}
		}
	}

	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    code,
			Message: err.Error(),
			Data:    nil,
		}))
	} else {
		c.JSON(http.StatusOK, structs.Map(response.StatusOK{
			Code:    code,
			Message: "success",
			Data:    nil,
		}))
	}
}

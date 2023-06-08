/*
 * Copyright (C) 2023 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Edoardo Spadoni <edoardo.spadoni@nethesis.it>
 */

package methods

import (
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/NethServer/nethsecurity-api/response"
	"github.com/NethServer/nethsecurity-controller/api/configuration"

	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"
)

func GetUnits(c *gin.Context) {
	// execute status command on openvpn socket
	out, err := exec.Command("bash", "-c", "echo status 3  | nc -U "+configuration.Config.OpenVPNMGMTSock+" | grep ^CLIENT_LIST | awk '{print $2,$3,$4,$5,$6,$9}'").Output()

	// check errors
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "unit list failed. openvpn status socket failed",
			Data:    err.Error(),
		}))
		return
	}

	// parse output
	var vpns map[string]gin.H
	vpns = make(map[string]gin.H)
	lines := strings.Split(string(out[:]), "\n")
	lines = lines[:len(lines)-1]

	// loop through lines
	for _, line := range lines {
		// get values from line
		parts := strings.Split(line, " ")

		// compose result
		vpns[parts[0]] = gin.H{
			"real_address":    parts[1],
			"virtual_address": parts[2],
			"bytes_rcvd":      parts[3],
			"bytes_sent":      parts[4],
			"connected_since": parts[5],
		}
	}

	// list file in OpenVPNCCDDir
	units, err := os.ReadDir(configuration.Config.OpenVPNCCDDir)
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "unit list failed. access CCD directory failed",
			Data:    err.Error(),
		}))
		return
	}

	// loop through units
	var results []gin.H
	for _, e := range units {
		// read unit file
		unitFile, err := os.ReadFile(configuration.Config.OpenVPNCCDDir + "/" + e.Name())
		if err != nil {
			c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
				Code:    400,
				Message: "unit list failed. openvpn client read failed",
				Data:    err.Error(),
			}))
		}

		// parse unit file
		parts := strings.Split(string(unitFile), "\n")
		parts = strings.Split(parts[0], " ")

		// compose result
		result := gin.H{
			"name":       e.Name(),
			"ipaddress":  parts[1],
			"netmask":    parts[2],
			"registered": true,
			"vpn":        vpns[e.Name()],
		}

		// append to array
		results = append(results, result)
	}

	// return 200 OK with data
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "units list success",
		Data:    results,
	}))

}

func GetUnit(c *gin.Context) {
	// return 200 OK with data
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "ubus call action success",
		Data:    "",
	}))
}

func GetToken(c *gin.Context) {
	// return 200 OK with data
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "ubus call action success",
		Data:    "",
	}))
}

func AddUnit(c *gin.Context) {
	// return 200 OK with data
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "ubus call action success",
		Data:    "",
	}))
}

func RegisterUnit(c *gin.Context) {
	// return 200 OK with data
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "ubus call action success",
		Data:    "",
	}))
}

func DeleteUnit(c *gin.Context) {
	// return 200 OK with data
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "ubus call action success",
		Data:    "",
	}))
}

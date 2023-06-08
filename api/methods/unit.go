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
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/NethServer/nethsecurity-api/response"
	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/NethServer/nethsecurity-controller/api/global"
	"github.com/NethServer/nethsecurity-controller/api/socket"

	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json: "password"`
}

type LoginResponse struct {
	Code   int    `json:"code"`
	Expire string `json:"expire"`
	Token  string `json:"token"`
}

func GetUnits(c *gin.Context) {
	// execute status command on openvpn socket
	var lines []string
	outSocket := socket.Write("status 3")

	// get only necessary lines
	rawLines := strings.Split(outSocket, "\n")
	for _, line := range rawLines {
		if strings.HasPrefix(line, "CLIENT_LIST") {
			lines = append(lines, line)
		}
	}

	// define vpns object
	var vpns map[string]gin.H
	vpns = make(map[string]gin.H)

	// loop through lines
	for _, line := range lines {

		// get values from line
		parts := strings.Split(line, "\t")

		// compose result
		vpns[parts[1]] = gin.H{
			"real_address":    parts[2],
			"virtual_address": parts[3],
			"bytes_rcvd":      parts[5],
			"bytes_sent":      parts[6],
			"connected_since": parts[8],
		}
	}

	// list file in OpenVPNCCDDir
	units, err := os.ReadDir(configuration.Config.OpenVPNCCDDir)
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "units list failed. access CCD directory failed",
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
				Message: "units list failed. openvpn client read failed",
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
		}

		// check if vpn data exists
		if vpns[e.Name()] != nil {
			result["vpn"] = vpns[e.Name()]
		} else {
			result["vpn"] = gin.H{}
		}

		// append to array
		results = append(results, result)
	}

	// list units in waiting state
	for name, _ := range global.WaitingList {
		result := gin.H{
			"name":       name,
			"ipaddress":  "",
			"netmask":    "",
			"registered": false,
		}

		// check if vpn data exists
		if vpns[name] != nil {
			result["vpn"] = vpns[name]
		} else {
			result["vpn"] = gin.H{}
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
	// get unit name
	unitId := c.Param("unit_id")

	// execute status command on openvpn socket
	var lines []string
	outSocket := socket.Write("status 3")

	// get only necessary lines
	rawLines := strings.Split(outSocket, "\n")
	for _, line := range rawLines {
		if strings.HasPrefix(line, "CLIENT_LIST\t"+unitId) {
			lines = append(lines, line)
		}
	}

	// define vpns object
	var vpn gin.H

	// loop through lines
	for _, line := range lines {

		// get values from line
		parts := strings.Split(line, "\t")

		// compose result
		vpn = gin.H{
			"real_address":    parts[2],
			"virtual_address": parts[3],
			"bytes_rcvd":      parts[5],
			"bytes_sent":      parts[6],
			"connected_since": parts[8],
		}
	}

	// read unit file
	unitFile, err := os.ReadFile(configuration.Config.OpenVPNCCDDir + "/" + unitId)
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
		"name":       unitId,
		"ipaddress":  parts[1],
		"netmask":    parts[2],
		"registered": true,
	}

	// check if vpn data exists
	if vpn != nil {
		result["vpn"] = vpn
	} else {
		result["vpn"] = gin.H{}
	}

	// return 200 OK with data
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "unit list success",
		Data:    result,
	}))
}

func GetToken(c *gin.Context) {
	// get unit name
	unitId := c.Param("unit_id")

	// read credentials
	var credentials LoginRequest
	body, err := ioutil.ReadFile(configuration.Config.CredentialsDir + "/" + unitId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Code:    500,
			Message: "cannot open credentials file for: " + unitId,
			Data:    err.Error(),
		}))
		return
	}

	// convert json string to struct
	json.Unmarshal(body, &credentials)

	// compose request URL
	postURL := "http://localhost:" + configuration.Config.ProxyPort + "/" + unitId + "/api/api/login"

	// create request action
	r, err := http.NewRequest("POST", postURL, bytes.NewBuffer(body))
	if err != nil {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Code:    500,
			Message: "cannot make request for: " + unitId,
			Data:    err.Error(),
		}))
		return
	}

	// set request header
	r.Header.Add("Content-Type", "application/json")

	// make request
	client := &http.Client{}
	res, err := client.Do(r)
	if err != nil {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Code:    500,
			Message: "request failed for: " + unitId,
			Data:    err.Error(),
		}))
		return
	}

	// close response
	defer res.Body.Close()

	// convert response to struct
	loginResponse := &LoginResponse{}
	err = json.NewDecoder(res.Body).Decode(loginResponse)
	if err != nil {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Code:    500,
			Message: "cannot convert response to struct for: " + unitId,
			Data:    err.Error(),
		}))
		return
	}

	// return 200 OK with data
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "ubus call action success",
		Data: gin.H{
			"token":  loginResponse.Token,
			"expire": loginResponse.Expire,
		},
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

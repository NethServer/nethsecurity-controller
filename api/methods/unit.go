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
	"os/exec"
	"strings"

	"github.com/NethServer/nethsecurity-api/response"
	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/NethServer/nethsecurity-controller/api/global"
	"github.com/NethServer/nethsecurity-controller/api/socket"
	"github.com/NethServer/nethsecurity-controller/api/utils"

	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"
)

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	Code   int    `json:"code" binding:"required"`
	Expire string `json:"expire" binding:"required"`
	Token  string `json:"token" binding:"required"`
}

type AddRequest struct {
	UnitId string `json:"unit_id" binding:"required"`
}

type RegisterRequest struct {
	UnitId   string `json:"unit_id" binding:"required"`
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
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
			Message: "access CCD directory failed",
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
				Message: "access CCD directory unit file failed",
				Data:    err.Error(),
			}))
		}

		// parse unit file
		parts := strings.Split(string(unitFile), "\n")
		parts = strings.Split(parts[0], " ")

		// compose result
		result := gin.H{
			"id":         e.Name(),
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
	for id, _ := range global.WaitingList {
		result := gin.H{
			"id":         id,
			"ipaddress":  "",
			"netmask":    "",
			"registered": false,
		}

		// check if vpn data exists
		if vpns[id] != nil {
			result["vpn"] = vpns[id]
		} else {
			result["vpn"] = gin.H{}
		}

		// append to array
		results = append(results, result)
	}

	// return 200 OK with data
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "units listed successfully",
		Data:    results,
	}))

}

func GetUnit(c *gin.Context) {
	// get unit id
	UnitId := c.Param("unit_id")

	// execute status command on openvpn socket
	var lines []string
	outSocket := socket.Write("status 3")

	// get only necessary lines
	rawLines := strings.Split(outSocket, "\n")
	for _, line := range rawLines {
		if strings.HasPrefix(line, "CLIENT_LIST\t"+UnitId) {
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
	unitFile, err := os.ReadFile(configuration.Config.OpenVPNCCDDir + "/" + UnitId)
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "access CCD directory unit file failed",
			Data:    err.Error(),
		}))
	}

	// parse unit file
	parts := strings.Split(string(unitFile), "\n")
	parts = strings.Split(parts[0], " ")

	// compose result
	result := gin.H{
		"id":         UnitId,
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
		Message: "unit listed successfully",
		Data:    result,
	}))
}

func GetToken(c *gin.Context) {
	// get unit id
	UnitId := c.Param("unit_id")

	// read credentials
	var credentials LoginRequest
	body, err := ioutil.ReadFile(configuration.Config.CredentialsDir + "/" + UnitId)
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "cannot open credentials file for: " + UnitId,
			Data:    err.Error(),
		}))
		return
	}

	// convert json string to struct
	json.Unmarshal(body, &credentials)

	// compose request URL
	postURL := configuration.Config.ProxyProtocol + configuration.Config.ProxyHost + ":" + configuration.Config.ProxyPort + "/" + UnitId + configuration.Config.LoginEndpoint

	// create request action
	r, err := http.NewRequest("POST", postURL, bytes.NewBuffer(body))
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "cannot make request for: " + UnitId,
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
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "request failed for: " + UnitId,
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
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "cannot convert response to struct for: " + UnitId,
			Data:    err.Error(),
		}))
		return
	}

	// check if token is not empty
	if len(loginResponse.Token) == 0 {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "invalid JWT token response for: " + UnitId,
			Data:    "token is invalid",
		}))
		return
	}

	// return 200 OK with data
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "unit token retrieved successfully",
		Data: gin.H{
			"token":  loginResponse.Token,
			"expire": loginResponse.Expire,
		},
	}))
}

func AddUnit(c *gin.Context) {
	// parse request fields
	var jsonRequest AddRequest
	if err := c.ShouldBindJSON(&jsonRequest); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "request fields malformed",
			Data:    err.Error(),
		}))
		return
	}

	// check duplicates
	if _, err := os.Stat(configuration.Config.OpenVPNCCDDir + "/" + jsonRequest.UnitId); err == nil {
		c.JSON(http.StatusConflict, structs.Map(response.StatusConflict{
			Code:    409,
			Message: "duplicated unit id",
			Data:    "",
		}))
		return
	}

	// get used ips
	var usedIPs []string

	units, err := os.ReadDir(configuration.Config.OpenVPNCCDDir)
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "access CCD directory failed",
			Data:    err.Error(),
		}))
		return
	}

	for _, e := range units {
		// read unit file
		unitFile, err := os.ReadFile(configuration.Config.OpenVPNCCDDir + "/" + e.Name())
		if err != nil {
			c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
				Code:    400,
				Message: "access CCD directory unit file failed",
				Data:    err.Error(),
			}))
			return
		}

		// parse unit file
		parts := strings.Split(string(unitFile), "\n")
		parts = strings.Split(parts[0], " ")

		// append to array
		usedIPs = append(usedIPs, parts[1])
	}

	// get free ip of a network
	freeIP := utils.GetFreeIP(configuration.Config.OpenVPNNetwork, configuration.Config.OpenVPNNetmask, usedIPs)

	if freeIP == "" {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "no IP available for new unit",
			Data:    err.Error(),
		}))
		return
	}

	// generate certificate request
	cmdGenerateGenReq := exec.Command(configuration.Config.EasyRSAPath, "gen-req", jsonRequest.UnitId, "nopass")
	cmdGenerateGenReq.Env = append(os.Environ(),
		"EASYRSA_BATCH=1",
		"EASYRSA_REQ_CN="+jsonRequest.UnitId,
		"EASYRSA_PKI="+configuration.Config.OpenVPNPKIDir,
	)
	if err := cmdGenerateGenReq.Run(); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "cannot generate request certificate for: " + jsonRequest.UnitId,
			Data:    err.Error(),
		}))
		return
	}

	// generate certificate sign
	cmdGenerateSignReq := exec.Command(configuration.Config.EasyRSAPath, "sign-req", "client", jsonRequest.UnitId)
	cmdGenerateSignReq.Env = append(os.Environ(),
		"EASYRSA_BATCH=1",
		"EASYRSA_REQ_CN="+jsonRequest.UnitId,
		"EASYRSA_PKI="+configuration.Config.OpenVPNPKIDir,
	)
	if err := cmdGenerateSignReq.Run(); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "cannot sign request certificate for: " + jsonRequest.UnitId,
			Data:    err.Error(),
		}))
		return
	}

	// write conf
	conf := "ifconfig-push " + freeIP + " " + configuration.Config.OpenVPNNetmask + "\n"
	errWrite := os.WriteFile(configuration.Config.OpenVPNCCDDir+"/"+jsonRequest.UnitId, []byte(conf), 0644)
	if errWrite != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "cannot write conf file for: " + jsonRequest.UnitId,
			Data:    errWrite.Error(),
		}))
		return
	}

	// get unit from waiting list and save credentials
	waiter := global.WaitingList[jsonRequest.UnitId]

	// check if unit was in waiting list
	if waiter != nil {
		// write new credentials
		newCredentials, _ := json.Marshal(waiter)
		errSave := os.WriteFile(configuration.Config.CredentialsDir+"/"+jsonRequest.UnitId, newCredentials, 0644)
		if errSave != nil {
			c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
				Code:    400,
				Message: "cannot write waiter credentials file for: " + jsonRequest.UnitId,
				Data:    errSave.Error(),
			}))
			return
		}

		// remove element from waiting list
		delete(global.WaitingList, jsonRequest.UnitId)
	}

	// return 200 OK with data
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "unit added successfully",
		Data: gin.H{
			"ipaddress": freeIP,
		},
	}))
}

func RegisterUnit(c *gin.Context) {
	// parse request fields
	var jsonRequest RegisterRequest
	if err := c.ShouldBindJSON(&jsonRequest); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "request fields malformed",
			Data:    err.Error(),
		}))
		return
	}

	// check openvpn conf exists
	if _, err := os.Stat(configuration.Config.OpenVPNPKIDir + "/issued/" + jsonRequest.UnitId + ".crt"); err == nil {
		// read ca
		ca, errCa := os.ReadFile(configuration.Config.OpenVPNPKIDir + "/" + "ca.crt")
		caS := strings.TrimSpace(string(ca[:]))

		// check error
		if errCa != nil {
			c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
				Code:    400,
				Message: "cannot retrieve openvpn config: ca.crt read failed",
				Data:    errCa.Error(),
			}))
			return
		}

		// read cert
		crt, errCrt := os.ReadFile(configuration.Config.OpenVPNPKIDir + "/issued/" + jsonRequest.UnitId + ".crt")
		crtS := strings.TrimSpace(string(crt[:]))

		// check error
		if errCrt != nil {
			c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
				Code:    400,
				Message: "cannot retrieve openvpn config: crt read failed",
				Data:    errCrt.Error(),
			}))
			return
		}

		// read key
		key, errKey := os.ReadFile(configuration.Config.OpenVPNPKIDir + "/private/" + jsonRequest.UnitId + ".key")
		keyS := strings.TrimSpace(string(key[:]))

		// check error
		if errKey != nil {
			c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
				Code:    400,
				Message: "cannot retrieve openvpn config: key read failed",
				Data:    errKey.Error(),
			}))
			return
		}

		// compose config
		config := gin.H{
			"host":             configuration.Config.FQDN,
			"port":             configuration.Config.OpenVPNUDPPort,
			"ca":               caS,
			"cert":             crtS,
			"key":              keyS,
			"promtail_address": configuration.Config.PromtailAddress,
			"promtail_port":    configuration.Config.PromtailPort,
		}

		// read credentials from request
		username := jsonRequest.Username
		password := jsonRequest.Password

		// read credentials from file
		var credentials LoginRequest
		jsonString, errRead := ioutil.ReadFile(configuration.Config.CredentialsDir + "/" + jsonRequest.UnitId)

		// credentials exists, update only if username matches
		if errRead == nil {
			// convert json string to struct
			json.Unmarshal(jsonString, &credentials)

			// check username
			if credentials.Username == username {
				credentials.Password = password
			}
		} else {
			// update credentials
			credentials.Username = username
			credentials.Password = password
		}

		// write new credentials
		newJsonString, _ := json.Marshal(credentials)
		errWrite := os.WriteFile(configuration.Config.CredentialsDir+"/"+jsonRequest.UnitId, newJsonString, 0644)
		if errWrite != nil {
			c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
				Code:    400,
				Message: "cannot write credentials file for: " + jsonRequest.UnitId,
				Data:    errWrite.Error(),
			}))
			return
		}

		// return 200 OK with data
		c.JSON(http.StatusOK, structs.Map(response.StatusOK{
			Code:    200,
			Message: "unit registered successfully",
			Data:    config,
		}))
	} else {
		// add to waiting list
		global.WaitingList[jsonRequest.UnitId] = gin.H{
			"username": jsonRequest.Username,
			"password": jsonRequest.Password,
		}

		// return forbidden state
		c.JSON(http.StatusForbidden, structs.Map(response.StatusForbidden{
			Code:    403,
			Message: "unit added to waiting list",
			Data:    "",
		}))
	}
}

func DeleteUnit(c *gin.Context) {
	// get unit id
	UnitId := c.Param("unit_id")

	// kill vpn connection
	_ = socket.Write("kill " + UnitId)

	// revoke certificate
	cmdRevoke := exec.Command(configuration.Config.EasyRSAPath, "revoke", UnitId)
	cmdRevoke.Env = append(os.Environ(),
		"EASYRSA_BATCH=1",
		"EASYRSA_PKI="+configuration.Config.OpenVPNPKIDir,
	)
	if err := cmdRevoke.Run(); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "cannot revoke certificate for: " + UnitId,
			Data:    err.Error(),
		}))
		return
	}

	// renew certificate revocation list
	cmdGen := exec.Command(configuration.Config.EasyRSAPath, "gen-crl")
	cmdGen.Env = append(os.Environ(),
		"EASYRSA_BATCH=1",
		"EASYRSA_PKI="+configuration.Config.OpenVPNPKIDir,
	)
	if err := cmdGen.Run(); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "cannot renew certificate revocation list (CLR)",
			Data:    err.Error(),
		}))
		return
	}

	// delete reservation/auth file
	if _, err := os.Stat(configuration.Config.OpenVPNCCDDir + "/" + UnitId); err == nil {
		errDeleteAuth := os.Remove(configuration.Config.OpenVPNCCDDir + "/" + UnitId)
		if errDeleteAuth != nil {
			c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
				Code:    403,
				Message: "error in deletion auth file for: " + UnitId,
				Data:    errDeleteAuth.Error(),
			}))
			return
		}
	}

	// delete traefik conf
	if _, err := os.Stat(configuration.Config.OpenVPNProxyDir + "/" + UnitId + ".yaml"); err == nil {
		errDeleteProxy := os.Remove(configuration.Config.OpenVPNProxyDir + "/" + UnitId + ".yaml")
		if errDeleteProxy != nil {
			c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
				Code:    403,
				Message: "error in deletion proxy file for: " + UnitId,
				Data:    errDeleteProxy.Error(),
			}))
			return
		}
	}

	// return 200 OK
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "unit deleted successfully",
		Data:    "",
	}))
}

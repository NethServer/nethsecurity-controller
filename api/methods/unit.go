/*
 * Copyright (C) 2024 Nethesis S.r.l.
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
	"errors"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/NethServer/nethsecurity-api/response"
	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/NethServer/nethsecurity-controller/api/logs"
	"github.com/NethServer/nethsecurity-controller/api/models"

	"github.com/NethServer/nethsecurity-controller/api/socket"
	"github.com/NethServer/nethsecurity-controller/api/storage"
	"github.com/NethServer/nethsecurity-controller/api/utils"
	jwt "github.com/appleboy/gin-jwt/v2"

	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"
)

func GetUnits(c *gin.Context) {
	// extract user from JWT claims
	user := jwt.ExtractClaims(c)["id"].(string)

	units, err := storage.ListUnits()
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "can't list units",
			Data:    err.Error(),
		}))
		return
	}

	// loop through units
	var results []gin.H
	for _, unit := range units {
		unitId, ok := unit["id"].(string)
		if !ok || !UserCanAccessUnit(user, unitId) {
			continue
		}
		// append to array
		results = append(results, unit)
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
	unitId := c.Param("unit_id")
	user := jwt.ExtractClaims(c)["id"].(string)
	if !UserCanAccessUnit(user, unitId) {
		c.JSON(http.StatusForbidden, structs.Map(response.StatusForbidden{
			Code:    403,
			Message: "user does not have access to this unit",
			Data:    nil,
		}))
		return
	}

	// parse unit file
	result, err := storage.GetUnit(unitId)

	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "can't get unit info for: " + unitId,
			Data:    err.Error(),
		}))
	} else {
		// return 200 OK with data
		c.JSON(http.StatusOK, structs.Map(response.StatusOK{
			Code:    200,
			Message: "unit listed successfully",
			Data:    result,
		}))
	}
}

func GetToken(c *gin.Context) {
	// get unit id
	unitId := c.Param("unit_id")

	token, expire, err := getUnitToken(unitId)

	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: err.Error(),
			Data:    "",
		}))
		return
	}

	// return 200 OK with data
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "unit token retrieved successfully",
		Data: gin.H{
			"token":  token,
			"expire": expire,
		},
	}))
}

func GetUnitInfo(c *gin.Context) {
	// extract user from JWT claims
	user := jwt.ExtractClaims(c)["id"].(string)

	// get unit id
	unitId := c.Param("unit_id")

	if !UserCanAccessUnit(user, unitId) {
		c.JSON(http.StatusForbidden, structs.Map(response.StatusForbidden{
			Code:    403,
			Message: "user does not have access to this unit",
			Data:    nil,
		}))
		return
	}

	// get unit info and store it
	info, err := GetRemoteInfo(unitId)

	// check errors
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "can't get unit info for: " + unitId,
			Data:    err.Error(),
		}))
		return
	}

	// return 200 OK
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "unit info retrieved successfully",
		Data:    info,
	}))

}

func AddInfo(c *gin.Context) {
	unitId := c.MustGet("UnitId").(string)
	var jsonRequest models.UnitInfo
	if err := c.ShouldBindJSON(&jsonRequest); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "request fields malformed",
			Data:    err.Error(),
		}))
		return
	}

	_, err := json.Marshal(jsonRequest)
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "can't marshal unit info for: " + unitId,
			Data:    err.Error(),
		}))
		return
	}
	storage.SetUnitInfo(unitId, jsonRequest)

	// return 200 OK
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "unit info retrieved successfully",
	}))
}

func AddUnit(c *gin.Context) {
	isAdmin := storage.IsAdmin(jwt.ExtractClaims(c)["id"].(string))
	if !isAdmin {
		c.JSON(http.StatusForbidden, structs.Map(response.StatusForbidden{
			Code:    403,
			Message: "can't access this resource",
			Data:    nil,
		}))
		return
	}

	// parse request fields
	var jsonRequest models.AddRequest
	if err := c.ShouldBindJSON(&jsonRequest); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "request fields malformed",
			Data:    err.Error(),
		}))
		return
	}

	// if the controller does not have a subscription, limit the number of units to 3
	if !configuration.Config.ValidSubscription {
		units, err := storage.ListUnits()
		if err != nil {
			c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
				Code:    400,
				Message: "can't list units",
				Data:    err.Error(),
			}))
			return
		}
		if len(units) >= 3 {
			c.JSON(http.StatusForbidden, structs.Map(response.StatusBadRequest{
				Code:    403,
				Message: "subscription limit reached",
				Data:    "",
			}))
			return
		}
	}

	// check duplicates
	_, err := storage.GetUnit(jsonRequest.UnitId)
	if err == nil {
		c.JSON(http.StatusConflict, structs.Map(response.StatusConflict{
			Code:    409,
			Message: "duplicated unit id",
			Data:    "",
		}))
		return
	}

	// get free ip of a network
	freeIP := storage.GetFreeIP()

	if freeIP == "" {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "no IP available for new unit",
			Data:    nil,
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

	// Print the executed command for debug
	cmdStr := configuration.Config.EasyRSAPath + " gen-req " + jsonRequest.UnitId + " nopass"
	logs.Logs.Println("[DEBUG][AddUnit] Executing command: " + cmdStr)

	// Capture stdout and stderr
	var stdout, stderr bytes.Buffer
	cmdGenerateGenReq.Stdout = &stdout
	cmdGenerateGenReq.Stderr = &stderr

	// Print stdout and stderr after execution
	if err := cmdGenerateGenReq.Run(); err != nil {
		logs.Logs.Println("[ERROR][AddUnit] Command execution failed: "+err.Error(), " Stdout: "+stdout.String(), " Stderr: "+stderr.String())
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

	// create record inside units table
	errCreate := storage.AddUnit(jsonRequest.UnitId, freeIP)
	if errCreate != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "cannot store unit record inside database for: " + jsonRequest.UnitId,
			Data:    errCreate.Error(),
		}))
		return
	}

	// return 200 OK with data
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "unit added successfully",
		Data: gin.H{
			"join_code": utils.GetJoinCode(jsonRequest.UnitId),
		},
	}))
}

func RegisterUnit(c *gin.Context) {
	token := c.GetHeader("RegistrationToken")

	// check if token exists
	if token == "" {
		c.JSON(http.StatusUnauthorized, structs.Map(response.StatusBadRequest{
			Code:    403,
			Message: "registration token required",
		}))
		return
	}

	// validate token
	if token != configuration.Config.RegistrationToken {
		c.JSON(http.StatusUnauthorized, structs.Map(response.StatusBadRequest{
			Code:    403,
			Message: "invalid registration token",
		}))
		return
	}

	// parse request fields
	var jsonRequest models.RegisterRequest
	if err := c.ShouldBindJSON(&jsonRequest); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "request fields malformed",
			Data:    err.Error(),
		}))
		return
	}

	// if the controller has a subscription, the unit must have a valid subscription too
	if configuration.Config.ValidSubscription && jsonRequest.SubscriptionType == "" {
		c.JSON(http.StatusForbidden, structs.Map(response.StatusBadRequest{
			Code:    403,
			Message: "subscription is required",
			Data:    "",
		}))
		return
	}

	// if the controller does not have a subscription, the unit must NOT have a valid subscription too
	if !configuration.Config.ValidSubscription && jsonRequest.SubscriptionType != "" {
		c.JSON(http.StatusForbidden, structs.Map(response.StatusBadRequest{
			Code:    403,
			Message: "subscription is not allowed",
			Data:    "",
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

		// extract API port from listen address
		addressParts := strings.Split(configuration.Config.ListenAddress[0], ":")
		apiPort := addressParts[len(addressParts)-1]
		// calculate server address from OpenVPNNetwork
		openvpnNetwork := strings.TrimSuffix(configuration.Config.OpenVPNNetwork, ".0")
		vpnAddress := openvpnNetwork + ".1"

		// compose config
		config := gin.H{
			"host":             configuration.Config.FQDN,
			"port":             configuration.Config.OpenVPNUDPPort,
			"ca":               caS,
			"cert":             crtS,
			"key":              keyS,
			"promtail_address": configuration.Config.PromtailAddress,
			"promtail_port":    configuration.Config.PromtailPort,
			"api_port":         apiPort,
			"vpn_address":      vpnAddress,
		}

		// read credentials from database
		curUsername, _, errRead := storage.GetUnitCredentials(jsonRequest.UnitId)

		var errWrite error
		// credentials exists, update only if username matches
		if errRead == nil {
			if curUsername == jsonRequest.Username {
				errWrite = storage.SetUnitCredentials(jsonRequest.UnitId, curUsername, jsonRequest.Password)
			}
		} else {
			// create credentials
			errWrite = storage.SetUnitCredentials(jsonRequest.UnitId, jsonRequest.Username, jsonRequest.Password)
		}

		// save new credentials
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
		// return forbidden state
		c.JSON(http.StatusForbidden, structs.Map(response.StatusForbidden{
			Code:    403,
			Message: "unit not allowed",
			Data:    "",
		}))
	}
}

func DeleteUnit(c *gin.Context) {
	isAdmin := storage.IsAdmin(jwt.ExtractClaims(c)["id"].(string))
	if !isAdmin {
		c.JSON(http.StatusForbidden, structs.Map(response.StatusForbidden{
			Code:    403,
			Message: "can't access this resource",
			Data:    nil,
		}))
		return
	}

	// get unit id
	unitId := c.Param("unit_id")

	// kill vpn connection
	_ = socket.Write("kill " + unitId)

	// revoke certificate
	cmdRevoke := exec.Command(configuration.Config.EasyRSAPath, "revoke", unitId)
	cmdRevoke.Env = append(os.Environ(),
		"EASYRSA_BATCH=1",
		"EASYRSA_PKI="+configuration.Config.OpenVPNPKIDir,
	)
	if err := cmdRevoke.Run(); err != nil {
		logs.Logs.Println("[ERROR][DeleteUnit] cannot revoke certificate for: " + unitId + " - " + err.Error())
	}

	// renew certificate revocation list
	cmdGen := exec.Command(configuration.Config.EasyRSAPath, "gen-crl")
	cmdGen.Env = append(os.Environ(),
		"EASYRSA_BATCH=1",
		"EASYRSA_PKI="+configuration.Config.OpenVPNPKIDir,
		"EASYRSA_CRL_DAYS=3650",
	)
	if err := cmdGen.Run(); err != nil {
		logs.Logs.Println("[ERROR][DeleteUnit] cannot renew certificate revocation list for: " + unitId + " - " + err.Error())
	}

	// delete traefik conf
	if _, err := os.Stat(configuration.Config.OpenVPNProxyDir + "/" + unitId + ".yaml"); err == nil {
		errDeleteProxy := os.Remove(configuration.Config.OpenVPNProxyDir + "/" + unitId + ".yaml")
		if errDeleteProxy != nil {
			logs.Logs.Println("[ERROR][DeleteUnit] cannot delete proxy file for: " + unitId + " - " + errDeleteProxy.Error())
		}
	}

	deleteError := storage.DeleteUnit(unitId)
	if deleteError != nil {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Code:    500,
			Message: "error in deletion unit record for: " + unitId,
			Data:    deleteError.Error(),
		}))
		return
	}

	// return 200 OK
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "unit deleted successfully",
		Data:    "",
	}))
}

func ListConnectedUnits() ([]string, error) {
	return storage.ListConnectedUnits()
}

func getUnitToken(unitId string) (string, string, error) {

	// read credentials
	username, password, err := storage.GetUnitCredentials(unitId)
	if err != nil {
		return "", "", errors.New("cannot read credentials for: " + unitId)
	}

	// compose request URL
	postURL := configuration.Config.ProxyProtocol + configuration.Config.ProxyHost + ":" + configuration.Config.ProxyPort + "/" + unitId + configuration.Config.LoginEndpoint

	// create request action
	credentials := models.LoginRequest{
		Username: username,
		Password: password,
	}
	body, err := json.Marshal(credentials)
	if err != nil {
		return "", "", errors.New("cannot marshal credentials for: " + unitId)
	}
	r, err := http.NewRequest("POST", postURL, bytes.NewBuffer(body))
	if err != nil {
		return "", "", errors.New("cannot make request for: " + unitId)
	}

	// set request header
	r.Header.Add("Content-Type", "application/json")

	// make request, 10 seconds timeout
	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.Do(r)
	if err != nil {
		return "", "", errors.New("request failed for: " + unitId)
	}

	// close response
	defer res.Body.Close()

	// convert response to struct
	loginResponse := &models.LoginResponse{}
	err = json.NewDecoder(res.Body).Decode(loginResponse)
	if err != nil {
		return "", "", errors.New("cannot convert response to struct for: " + unitId)
	}

	// check if token is not empty
	if len(loginResponse.Token) == 0 {
		return "", "", errors.New("invalid token response for: " + unitId)
	}

	return loginResponse.Token, loginResponse.Expire, nil
}

func GetRemoteInfo(unitId string) (models.UnitInfo, error) {
	// get the unit token and execute the request
	token, _, _ := getUnitToken(unitId)
	if token == "" {
		return models.UnitInfo{}, errors.New("error getting token")
	}

	// compose request URL
	postURL := configuration.Config.ProxyProtocol + configuration.Config.ProxyHost + ":" + configuration.Config.ProxyPort + "/" + unitId + "/api/ubus/call"
	payload := models.UbusCommand{
		Path:    "ns.controller",
		Method:  "info",
		Payload: map[string]interface{}{},
	}

	// convert payload to JSON byte array
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return models.UnitInfo{}, errors.New("error marshalling payload")
	}

	// create request action
	r, err := http.NewRequest("POST", postURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return models.UnitInfo{}, errors.New("error creating request")
	}

	// set request headers
	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Authorization", "Bearer "+token)

	// make request, with 10 seconds timeout
	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.Do(r)
	if err != nil {
		return models.UnitInfo{}, errors.New("error making request")
	}
	defer res.Body.Close()

	// convert response to struct
	unitInfo := &models.UbusResponse[models.UnitInfo]{}
	err = json.NewDecoder(res.Body).Decode(unitInfo)
	if err != nil {
		return models.UnitInfo{}, errors.New("error decoding response")
	}

	// ask additional info to the unit
	systemUpdatePayload := models.UbusCommand{
		Path:    "ns.update",
		Method:  "check-system-update",
		Payload: map[string]interface{}{},
	}

	// convert payload to JSON byte array
	systemUpdateBytes, _ := json.Marshal(systemUpdatePayload)
	systemUpdateRequest, err := http.NewRequest("POST", postURL, bytes.NewBuffer(systemUpdateBytes))
	if err != nil {
		return models.UnitInfo{}, errors.New("error creating request")
	}

	// set request headers
	systemUpdateRequest.Header.Add("Content-Type", "application/json")
	systemUpdateRequest.Header.Add("Authorization", "Bearer "+token)

	// make request, with 10 seconds timeout
	systemUpdateResponse, err := client.Do(systemUpdateRequest)
	if err != nil {
		return models.UnitInfo{}, errors.New("error making request")
	}
	defer systemUpdateResponse.Body.Close()

	// convert response to struct
	systemUpdateInfo := &models.UbusResponse[models.CheckSystemUpdate]{}
	err = json.NewDecoder(systemUpdateResponse.Body).Decode(systemUpdateInfo)
	if err != nil {
		return models.UnitInfo{}, errors.New("error decoding response")
	}

	unitInfo.Data.ScheduledUpdate = systemUpdateInfo.Data.ScheduledAt
	unitInfo.Data.VersionUpdate = systemUpdateInfo.Data.LastVersion

	// write json to database
	storage.SetUnitInfo(unitId, unitInfo.Data)

	return unitInfo.Data, nil
}

func AddUnitGroup(c *gin.Context) {
	isAdmin := storage.IsAdmin(jwt.ExtractClaims(c)["id"].(string))
	if !isAdmin {
		c.JSON(http.StatusForbidden, structs.Map(response.StatusForbidden{
			Code:    403,
			Message: "admin privileges required",
		}))
		return
	}

	var req models.UnitGroup
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "request fields malformed",
			Data:    err.Error(),
		}))
		return
	}

	id, err := storage.AddUnitGroup(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "cannot add unit group",
			Data:    err.Error(),
		}))
		return
	}

	c.JSON(http.StatusCreated, structs.Map(response.StatusCreated{
		Code:    201,
		Message: "unit group added successfully",
		Data:    gin.H{"id": id},
	}))
}

func UpdateUnitGroup(c *gin.Context) {
	isAdmin := storage.IsAdmin(jwt.ExtractClaims(c)["id"].(string))
	if !isAdmin {
		c.JSON(http.StatusForbidden, structs.Map(response.StatusForbidden{
			Code:    403,
			Message: "admin privileges required",
		}))
		return
	}

	groupId := c.Param("group_id")
	if groupId == "" {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "group_id is required",
		}))
		return
	}
	groupIntId, err := strconv.Atoi(groupId)
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "group_id must be an integer",
			Data:    err.Error(),
		}))
		return
	}

	var req models.UnitGroup
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "request fields malformed",
			Data:    err.Error(),
		}))
		return
	}

	for _, unit := range req.Units {
		exists, err := storage.UnitExists(unit)
		if err != nil {
			c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
				Code:    500,
				Message: "error checking unit existence",
				Data:    err.Error(),
			}))
			return
		}
		if !exists {
			c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
				Code:    400,
				Message: "unit does not exist",
				Data:    unit,
			}))
			return
		}
	}

	if err := storage.UpdateUnitGroup(groupIntId, req); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "cannot edit unit group",
			Data:    err.Error(),
		}))
		return
	}

	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "unit group edited successfully",
	}))
}

func DeleteUnitGroup(c *gin.Context) {
	isAdmin := storage.IsAdmin(jwt.ExtractClaims(c)["id"].(string))
	if !isAdmin {
		c.JSON(http.StatusForbidden, structs.Map(response.StatusForbidden{
			Code:    403,
			Message: "admin privileges required",
		}))
		return
	}

	groupId := c.Param("group_id")
	if groupId == "" {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "group_id is required",
		}))
		return
	}
	groupIdInt, err := strconv.Atoi(groupId)
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "group_id must be an integer",
			Data:    err.Error(),
		}))
		return
	}

	// check if the unit group is used
	used, err := storage.IsUnitGroupUsed(groupIdInt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Code:    500,
			Message: "error checking if unit group is used",
			Data:    err.Error(),
		}))
		return
	}
	if used {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "unit group is used and cannot be deleted",
		}))
		return
	}

	if err := storage.DeleteUnitGroup(groupIdInt); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "cannot delete unit group",
			Data:    err.Error(),
		}))
		return
	}

	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "unit group deleted successfully",
	}))
}

func ListUnitGroups(c *gin.Context) {
	isAdmin := storage.IsAdmin(jwt.ExtractClaims(c)["id"].(string))
	if !isAdmin {
		c.JSON(http.StatusForbidden, structs.Map(response.StatusForbidden{
			Code:    403,
			Message: "admin privileges required",
		}))
		return
	}

	groups, err := storage.ListUnitGroups()
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "cannot list unit groups",
			Data:    err.Error(),
		}))
		return
	}

	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "unit groups listed successfully",
		Data:    groups,
	}))
}

func GetUnitGroup(c *gin.Context) {
	isAdmin := storage.IsAdmin(jwt.ExtractClaims(c)["id"].(string))
	if !isAdmin {
		c.JSON(http.StatusForbidden, structs.Map(response.StatusForbidden{
			Code:    403,
			Message: "admin privileges required",
		}))
		return
	}

	groupId := c.Param("group_id")
	if groupId == "" {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "group_id is required",
		}))
		return
	}
	groupIdInt, err := strconv.Atoi(groupId)
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "group_id must be an integer",
			Data:    err.Error(),
		}))
		return
	}
	group, err := storage.GetUnitGroup(groupIdInt)
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "cannot get unit group",
			Data:    err.Error(),
		}))
		return
	}

	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "unit group retrieved successfully",
		Data:    group,
	}))
}

func GetPrometheusTargets(c *gin.Context) {
	// Get all units
	units, err := storage.ListUnits()
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "can't list units",
			Data:    err.Error(),
		}))
		return
	}

	// Create Prometheus target format
	// Format reference: https://prometheus.io/docs/prometheus/latest/http_sd/
	var targets []gin.H
	for _, unit := range units {
		unitId, ok1 := unit["id"].(string)
		unitIp, ok2 := unit["ipaddress"].(string)

		if ok1 && ok2 {
			target := gin.H{
				"targets": []string{unitIp + ":19999"},
				"labels": gin.H{
					"node":             unitIp,
					"unit":             unitId,
					"__metrics_path__": "/api/v1/allmetrics?format=prometheus&help=no"},
			}
			targets = append(targets, target)
		}
	}

	// Return targets in Prometheus HTTP SD format
	c.JSON(http.StatusOK, targets)
}

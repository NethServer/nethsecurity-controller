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
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/NethServer/nethsecurity-controller/api/configuration"
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
	SubscriptionType string `json:"subscription_type"`
	SystemID         string `json:"system_id"`
	SSHPort          int    `json:"ssh_port"`
	FQDN             string `json:"fqdn"`
}

// list unit name from files in OpenVPNCCDDir
func ListUnits() ([]string, error) {
	units := []string{}
	// list file in OpenVPNCCDDir
	files, err := os.ReadDir(configuration.Config.OpenVPNCCDDir)
	if err != nil {
		return nil, err
	}

	// loop through files
	for _, file := range files {
		units = append(units, file.Name())
	}

	return units, nil
}

func GetUnitToken(unitId string) (string, string, error) {

	// read credentials
	var credentials LoginRequest
	body, err := ioutil.ReadFile(configuration.Config.CredentialsDir + "/" + unitId)
	if err != nil {
		return "", "", errors.New("cannot open credentials file for: " + unitId)
	}

	// convert json string to struct
	json.Unmarshal(body, &credentials)

	// compose request URL
	postURL := configuration.Config.ProxyProtocol + configuration.Config.ProxyHost + ":" + configuration.Config.ProxyPort + "/" + unitId + configuration.Config.LoginEndpoint

	// create request action
	r, err := http.NewRequest("POST", postURL, bytes.NewBuffer(body))
	if err != nil {
		return "", "", errors.New("cannot make request for: " + unitId)
	}

	// set request header
	r.Header.Add("Content-Type", "application/json")

	// make request, 2 seconds timeout
	client := &http.Client{Timeout: 2 * time.Second}
	res, err := client.Do(r)
	if err != nil {
		return "", "", errors.New("request failed for: " + unitId)
	}

	// close response
	defer res.Body.Close()

	// convert response to struct
	loginResponse := &LoginResponse{}
	err = json.NewDecoder(res.Body).Decode(loginResponse)
	if err != nil {
		return "", "", errors.New("cannot convert response to struct for: " + unitId)
	}

	// check if token is not empty
	if len(loginResponse.Token) == 0 {
		return "", "", errors.New("invalid JWT token response for: " + unitId)
	}

	return loginResponse.Token, loginResponse.Expire, nil
}

func GetRemoteInfo(unitId string) (UnitInfo, error) {
	// get the unit token and execute the request
	token, _, _ := GetUnitToken(unitId)
	if token == "" {
		return UnitInfo{}, errors.New("error getting token")
	}

	// compose request URL
	postURL := configuration.Config.ProxyProtocol + configuration.Config.ProxyHost + ":" + configuration.Config.ProxyPort + "/" + unitId + "/api/ubus/call"
	// prepare the payload: {"path":"ns.don","method":"status","payload":{}}
	payload := UbusCommand{
		Path:    "ns.controller",
		Method:  "info",
		Payload: map[string]interface{}{},
	}

	// convert payload to JSON byte array
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return UnitInfo{}, errors.New("error marshalling payload")
	}

	// create request action
	r, err := http.NewRequest("POST", postURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return UnitInfo{}, errors.New("error creating request")
	}

	// set request headers
	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Authorization", "Bearer "+token)

	// make request, with 2 seconds timeout
	client := &http.Client{Timeout: 2 * time.Second}
	res, err := client.Do(r)
	if err != nil {
		return UnitInfo{}, errors.New("error making request")
	}
	defer res.Body.Close()

	// convert response to struct
	unitInfo := &UbusInfoResponse{}
	err = json.NewDecoder(res.Body).Decode(unitInfo)
	if err != nil {
		return UnitInfo{}, errors.New("error decoding response")
	}

	return unitInfo.Data, nil
}

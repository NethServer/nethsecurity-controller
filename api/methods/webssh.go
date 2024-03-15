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
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"

	"github.com/Jeffail/gabs/v2"
	"github.com/NethServer/nethsecurity-api/response"
	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/NethServer/nethsecurity-controller/api/models"
	"github.com/fatih/structs"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
)

func GetWebSSH(c *gin.Context) {
	// get request fields
	var jsonData models.SSHConnect
	if err := c.BindJSON(&jsonData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "request fields malformed", "error": err.Error()})
		return
	}

	// get unit id
	unitID := jsonData.UnitID

	// get unit file
	unitFile, vpn, errFile := readUnitFile(unitID)
	if errFile != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "access CCD directory unit file failed",
			Data:    errFile.Error(),
		}))
	}

	// parse unit file
	result := parseUnitFile(unitID, unitFile, vpn)

	// get ip address
	ipAddress := result["ipaddress"].(string)

	// get username
	username := jwt.ExtractClaims(c)["id"].(string)

	// get path for ssh keys
	keysPath := configuration.Config.DataDir + "/" + username + ".key"

	// read key
	keyPrivate, err := os.ReadFile(keysPath + "")
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "access ssh directory keys file failed",
			Data:    err.Error(),
		}))
	}

	// define webssh url
	webSSHURL := "http://localhost:" + configuration.Config.WebSSHPort

	// make get request for xsrf token
	resGet, errGet := http.Get(webSSHURL)

	// check error
	if errGet != nil {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Code:    500,
			Message: "error on XSRF token id",
			Data:    errGet.Error(),
		}))
	}

	// read cookies
	defer resGet.Body.Close()
	cookies := resGet.Cookies()

	// get _xsrf cookie token
	var xsrfToken string
	for _, cookie := range cookies {
		if cookie.Name == "_xsrf" {
			xsrfToken = cookie.Value
		}
	}

	// create cookie jar
	jar, _ := cookiejar.New(nil)

	// define cookies
	var cookiesPost []*http.Cookie
	cookie := &http.Cookie{
		Name:  "_xsrf",
		Value: xsrfToken,
		Path:  "/",
	}
	cookiesPost = append(cookiesPost, cookie)

	// add cookies to jar
	u, _ := url.Parse(webSSHURL)
	jar.SetCookies(u, cookiesPost)

	// add jar to client
	client := &http.Client{
		Jar: jar,
	}

	// make post request for websocket id
	resPost, errPost := client.PostForm(webSSHURL, url.Values{
		"hostname":   {ipAddress},
		"port":       {"22"},
		"username":   {"root"},
		"privatekey": {string(keyPrivate)},
		"passphrase": {jsonData.Passphrase},
		"term":       {"xterm-256color"},
		"_xsrf":      {xsrfToken},
	})

	// check error
	if errPost != nil {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Code:    500,
			Message: "error on getting websocket id",
			Data:    errPost.Error(),
		}))
	}

	// parse body response
	defer resPost.Body.Close()
	body, err := ioutil.ReadAll(resPost.Body)

	// check error
	if err != nil {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Code:    500,
			Message: "error parsing body for websocket id",
			Data:    err.Error(),
		}))
	}

	// parse body response
	jsonParsed, _ := gabs.ParseJSON(body)

	// check if id exists
	idFound, _ := jsonParsed.Path("id").Data().(string)
	if len(idFound) == 0 || idFound == "null" {
		// get status message
		message, _ := jsonParsed.Path("status").Data().(string)

		// return bad request
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "invalid connection",
			Data:    message,
		}))
		return
	}

	// return ok
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "success",
		Data:    jsonParsed,
	}))
}

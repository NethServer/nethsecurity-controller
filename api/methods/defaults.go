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
	"net/http"

	"github.com/NethServer/nethsecurity-api/response"
	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"
)

func GetDefaults(c *gin.Context) {
	// read and return defaults path
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "success",
		Data: gin.H{
			"fqdn":               configuration.Config.FQDN,
			"webssh_path":        configuration.Config.WebSSHPath,
			"grafana_path":       configuration.Config.GrafanaPath,
			"valid_subscription": configuration.Config.ValidSubscription,
		},
	}))
}

func GetPlatformInfo(c *gin.Context) {
	// read and return platform info
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "success",
		Data:    structs.Map(configuration.Config.PlatformInfo),
	}))
}

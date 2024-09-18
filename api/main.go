/*
 * Copyright (C) 2024 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Edoardo Spadoni <edoardo.spadoni@nethesis.it>
 */

package main

import (
	"io"
	"net/http"

	"github.com/fatih/structs"
	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"

	"github.com/NethServer/nethsecurity-api/response"
	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/NethServer/nethsecurity-controller/api/logs"
	"github.com/NethServer/nethsecurity-controller/api/methods"
	"github.com/NethServer/nethsecurity-controller/api/middleware"
	"github.com/NethServer/nethsecurity-controller/api/routines"
	"github.com/NethServer/nethsecurity-controller/api/socket"
	"github.com/NethServer/nethsecurity-controller/api/storage"
	"github.com/NethServer/nethsecurity-controller/api/utils"
)

// @title NethSecurity Controller API Server
// @version 1.0
// @description NethSecurity Controller API Server is used to manage multiple stand-alone NethSecurity instances
// @termsOfService https://nethserver.org/terms/

// @contact.name NethServer Developer Team
// @contact.url https://nethserver.org/support

// @license.name GNU GENERAL PUBLIC LICENSE

// @host localhost:5000
// @schemes http
// @BasePath /api

func main() {
	// init logs with syslog
	logs.Init("nethsecurity_controller")

	// init configuration
	configuration.Init()

	// init storage
	storage.Init()
	storage.InitReportDb()

	// init socket connection
	socket.Init()

	// init geoip
	utils.InitGeoIP()
	// start geoip refresh loop
	go routines.RefreshGeoIPDatabase()

	// starts remote info loop
	go routines.RefreshRemoteInfoLoop()

	// disable log to stdout when running in release mode
	if gin.Mode() == gin.ReleaseMode {
		gin.DefaultWriter = io.Discard
	}

	// init routers
	router := gin.Default()

	// add default compression
	router.Use(gzip.Gzip(gzip.DefaultCompression))

	// cors configuration only in debug mode GIN_MODE=debug (default)
	if gin.Mode() == gin.DebugMode {
		// gin gonic cors conf
		corsConf := cors.DefaultConfig()
		corsConf.AllowHeaders = []string{"Authorization", "Content-Type", "Accept"}
		corsConf.AllowAllOrigins = true
		router.Use(cors.New(corsConf))
	}

	// define api group
	api := router.Group("/")

	// define login and logout endpoint
	api.POST("/login", middleware.InstanceJWT().LoginHandler)
	api.POST("/logout", middleware.InstanceJWT().LogoutHandler)

	// define server registration
	api.POST("/units/register", methods.RegisterUnit)

	// define JWT middleware
	api.Use(middleware.InstanceJWT().MiddlewareFunc())
	{
		// refresh handler
		api.GET("/refresh", middleware.InstanceJWT().RefreshHandler)

		// accounts APIs
		accounts := api.Group("/accounts")
		{
			// accounts CRUD
			accounts.GET("", methods.GetAccounts)
			accounts.GET("/:account_id", methods.GetAccount)
			accounts.POST("", methods.AddAccount)
			accounts.PUT("/:account_id", methods.UpdateAccount)
			accounts.DELETE("/:account_id", methods.DeleteAccount)

			// account password change
			accounts.PUT("/password", methods.UpdatePassword)

			// ssh keys read and write
			accounts.GET("/ssh-keys", methods.GetSSHKeys)
			accounts.POST("/ssh-keys", methods.AddSSHKeys)
			accounts.DELETE("/ssh-keys", methods.DeleteSSHKeys)
		}

		// default APIs
		defaults := api.Group("/defaults")
		{
			defaults.GET("", methods.GetDefaults)
		}

		// units APIs
		units := api.Group("/units")
		{
			units.GET("", methods.GetUnits)
			units.GET("/:unit_id", methods.GetUnit)
			units.GET("/:unit_id/info", methods.GetUnitInfo)
			units.GET("/:unit_id/token", methods.GetToken)
			units.POST("", methods.AddUnit)
			units.DELETE("/:unit_id", methods.DeleteUnit)
		}
	}

	// report APIs
	reports := router.Group("/reports")
	reports.Use(middleware.ReportAuth())
	{
		reports.POST("/mwan-events", methods.UpdateMwanSeries)
		reports.POST("/ts-attacks", methods.UpdateTsAttacks)
		reports.POST("/ts-malware", methods.UpdateTsMalware)
		reports.POST("/ovpnrw-connections", methods.UpdateOvpnConnections)
		reports.POST("/dpi-stats", methods.UpdateDpiStats)
		reports.POST("/unit-name", methods.SetUnitName)
		reports.POST("/unit-openvpn", methods.SetUnitOpenVPNRW)
		reports.POST("/unit-wan", methods.SetUnitWan)
	}

	// handle missing endpoint
	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, structs.Map(response.StatusNotFound{
			Code:    404,
			Message: "API not found",
			Data:    nil,
		}))
	})

	// run server
	router.Run(configuration.Config.ListenAddress)
}

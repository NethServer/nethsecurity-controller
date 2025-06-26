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

func setup() *gin.Engine {
	// init logs with syslog
	logs.Init("nethsecurity_controller")

	// init configuration
	configuration.Init()

	// init storage
	storage.Init()

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

	// add trusted IP middleware globally
	router.Use(middleware.TrustedIPMiddleware())

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

	// define healthcheck endpoint
	api.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// 2FA APIs
	api.POST("/2fa/otp-verify", methods.OTPVerify)

	// define server registration
	api.POST("/units/register", methods.RegisterUnit)

	// define JWT middleware
	api.Use(middleware.InstanceJWT().MiddlewareFunc())
	{
		// refresh handler
		api.GET("/refresh", middleware.InstanceJWT().RefreshHandler)

		// 2FA APIs
		api.GET("/2fa", methods.Get2FAStatus)
		api.DELETE("/2fa", methods.Del2FAStatus)
		api.GET("/2fa/qr-code", methods.QRCode)

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

		// unit_groups APIs
		unitGroups := api.Group("/unit_groups")
		{
			unitGroups.GET("", methods.ListUnitGroups)
			unitGroups.GET("/:group_id", methods.GetUnitGroup)
			unitGroups.POST("", methods.AddUnitGroup)
			unitGroups.PUT("/:group_id", methods.UpdateUnitGroup)
			unitGroups.DELETE("/:group_id", methods.DeleteUnitGroup)
		}

		// platforms APIs
		api.GET("/platform", methods.GetPlatformInfo)
	}

	// Ingest APIs: receive data from firewalls
	authorized := router.Group("/ingest", middleware.BasicUnitAuth())
	authorized.POST("/info", methods.AddInfo)
	authorized.POST("/:firewall_api", methods.HandelMonitoring)

	// Forwarded authentication middleware
	forwarded := router.Group("/auth", middleware.BasicUserAuth())
	forwarded.GET("", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"auth": "ok"})
	})

	// handle missing endpoint
	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, structs.Map(response.StatusNotFound{
			Code:    404,
			Message: "API not found",
			Data:    nil,
		}))
	})

	return router
}

func main() {
	router := setup()
	// Listen on multiple addresses
	for _, addr := range configuration.Config.ListenAddress {
		go func(a string) {
			if err := router.Run(a); err != nil {
				logs.Logs.Println("[CRITICAL][API] Server failed to start on address: " + a)
			}
		}(addr)
	}

	// Prevent main from exiting
	select {}
}

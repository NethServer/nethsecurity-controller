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
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httputil"

	"github.com/fatih/structs"
	"github.com/gin-contrib/cors"
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

	//	unitTokens := map[string]string{}

	// proxypass APIs
	proxypass := api.Group("/proxypass/:unit_id")
	{
		proxypass.Any("/*proxyPath", func(c *gin.Context) {
			unitID := c.Param("unit_id")
			proxyPath := c.Param("proxyPath")

			unitToken, _, _ := methods.GetUnitToken(unitID)
			if unitToken == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: missing unit token"})
				logs.Logs.Printf("[ERROR] Missing unit token for unit ID: %s", unitID)
				return
			}
			logs.Logs.Printf("[DEBUG] Retrieved unit token for unit ID %s: %s", unitID, unitToken)

			// if unitTokens[unitID] == "" {
			// 	// Retrieve the unit's token from storage or configuration
			// 	token, _, _ := methods.GetUnitToken(unitID)
			// 	if token == "" {
			// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			// 		return
			// 	}
			// 	unitTokens[unitID] = token
			// }
			// unitToken := unitTokens[unitID]

			// Retrieve the unit's base URL from storage or configuration
			unitIPAddress := methods.GetUnitIPAddress(unitID)
			if unitIPAddress == "" {
				c.JSON(http.StatusNotFound, gin.H{"error": "Unit not found"})
				return
			}

			//unitBaseURL := "https://" + unitIPAddress + ":9090"

			// Create a reverse proxy
			proxy := &httputil.ReverseProxy{
				Director: func(req *http.Request) {
					req.URL.Scheme = "https"
					req.URL.Host = unitIPAddress + ":9090"
					req.URL.Path = proxyPath
					req.Header = c.Request.Header.Clone()
					// Remove existing Authorization headers
					req.Header.Del("Authorization")
					// Add Authorization header
					req.Header.Set("Authorization", "Bearer "+unitToken)
					// Debugging request
					logs.Logs.Printf("[DEBUG] Proxying request to: %s%s", req.URL.Host, req.URL.Path)
					logs.Logs.Printf("[DEBUG] Request Headers: %v", req.Header)
					logs.Logs.Printf("[DEBUG] Request Method: %s", req.Method)
					logs.Logs.Printf("[DEBUG] Request Body: %v", c.Request.Body)
				},
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}

			// Serve the proxied request
			proxy.ServeHTTP(c.Writer, c.Request)
		})
	}

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
		c.Status(http.StatusOK)
	})
	forwarded.GET("/:unit_id", func(c *gin.Context) {
		c.Status(http.StatusOK)
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

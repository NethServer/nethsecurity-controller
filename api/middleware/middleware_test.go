/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Giacomo Sanchietti <giacomo.sanchietti@nethesis.it>
 */

package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/NethServer/nethsecurity-controller/api/logs"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	logs.Init("test")
	os.Exit(m.Run())
}

func TestInitJWT(t *testing.T) {
	// Set required config
	configuration.Config.SecretJWT = "test_secret"

	mw := InitJWT()
	assert.NotNil(t, mw)
}

func TestInstanceJWT(t *testing.T) {
	// Set required config
	configuration.Config.SecretJWT = "test_secret"

	mw := InstanceJWT()
	assert.NotNil(t, mw)
}

func TestBasicUnitAuth(t *testing.T) {
	// Set required config
	configuration.Config.RegistrationToken = "test_token"
	configuration.Config.OpenVPNPKIDir = "/tmp" // Mock path

	r := gin.New()
	r.Use(BasicUnitAuth())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "ok"})
	})

	// Test missing auth
	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, 400, w.Code)

	// Test invalid token
	req.SetBasicAuth("unit1", "wrong_token")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, 401, w.Code)

	// Test valid token but invalid unit (no cert file)
	req.SetBasicAuth("unit1", "test_token")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, 401, w.Code)
}

func TestJWTLogin(t *testing.T) {
	// Set required config
	configuration.Config.SecretJWT = "test_secret"

	r := gin.New()
	r.POST("/login", InstanceJWT().LoginHandler)

	// Test login with invalid credentials (will fail due to storage)
	req, _ := http.NewRequest("POST", "/login", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(strings.NewReader(`{"username":"admin","password":"pass"}`))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	// Should return 401 since storage fails
	assert.Equal(t, 401, w.Code)
}

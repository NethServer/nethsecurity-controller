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
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"

	"github.com/NethServer/nethsecurity-controller/api/models"
	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/NethServer/nethsecurity-controller/api/logs"
	"github.com/NethServer/nethsecurity-controller/api/methods"
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

func generateTestToken(t *testing.T, username string) string {
	t.Helper()
	configuration.Config.SecretJWT = "test_secret"
	mw := InstanceJWT()

	token, _, err := mw.TokenGenerator(&models.UserAuthorizations{Username: username})
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Register the token as active
	methods.SetTokenValidation(username, token)

	return token
}

func TestBasicUserAuthCookie(t *testing.T) {
	token := generateTestToken(t, "testuser")

	r := gin.New()
	r.Use(BasicUserAuth())
	r.GET("/auth", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "ok"})
	})

	// Valid cookie returns 200 and sets X-Auth-User
	req, _ := http.NewRequest("GET", "/auth", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "testuser", w.Header().Get("X-Auth-User"))

	// Invalid cookie → 401 and cookie is cleared (Set-Cookie with Max-Age=-1)
	req, _ = http.NewRequest("GET", "/auth", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: "invalid.jwt.token"})
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, 401, w.Code)
	assert.Contains(t, w.Header().Get("Set-Cookie"), cookieName+"=;")

	// No cookie and no Basic Auth → 401
	req, _ = http.NewRequest("GET", "/auth", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, 401, w.Code)

	// Clean up
	methods.DelTokenValidation("testuser", token)
}

func TestBasicUserAuthCookieUnitAccess(t *testing.T) {
	token := generateTestToken(t, "limiteduser")

	r := gin.New()
	r.Use(BasicUserAuth())
	r.GET("/auth/:unit_id", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "ok"})
	})

	// Non-admin user with cookie accessing a unit → 403
	// (limiteduser is not in adminUsers and has no unit assignments)
	req, _ := http.NewRequest("GET", "/auth/unit-123", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, 403, w.Code)
	assert.Contains(t, w.Body.String(), "user does not have access to this unit")

	// Same user without unit_id param → 200 (no unit check needed)
	r2 := gin.New()
	r2.Use(BasicUserAuth())
	r2.GET("/auth", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "ok"})
	})
	req, _ = http.NewRequest("GET", "/auth", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
	w = httptest.NewRecorder()
	r2.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)

	// Clean up
	methods.DelTokenValidation("limiteduser", token)
}

func TestBodyLimit(t *testing.T) {
	r := gin.New()
	r.Use(BodyLimit(8))
	r.POST("/test", func(c *gin.Context) {
		_, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"message": "ok"})
	})

	// Body within limit is accepted
	req, _ := http.NewRequest("POST", "/test", strings.NewReader("1234567"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)

	// Body exceeding limit is rejected by the handler's read, not silently truncated
	req, _ = http.NewRequest("POST", "/test", strings.NewReader("123456789"))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)

	// Enforced on bytes actually read, independent of a spoofed Content-Length
	req, _ = http.NewRequest("POST", "/test", strings.NewReader("123456789"))
	req.ContentLength = 5
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

func TestRateLimiter(t *testing.T) {
	r := gin.New()
	r.Use(RateLimiter(rate.Every(time.Minute), 2))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "ok"})
	})

	newReq := func(remoteAddr string) *http.Request {
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = remoteAddr
		return req
	}

	// Burst of 2 is allowed for the same client IP
	w := httptest.NewRecorder()
	r.ServeHTTP(w, newReq("1.2.3.4:1111"))
	assert.Equal(t, 200, w.Code)

	w = httptest.NewRecorder()
	r.ServeHTTP(w, newReq("1.2.3.4:2222"))
	assert.Equal(t, 200, w.Code)

	// Third request from the same IP within the window is rejected
	w = httptest.NewRecorder()
	r.ServeHTTP(w, newReq("1.2.3.4:3333"))
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// A different client IP has its own independent bucket
	w = httptest.NewRecorder()
	r.ServeHTTP(w, newReq("5.6.7.8:1111"))
	assert.Equal(t, 200, w.Code)
}

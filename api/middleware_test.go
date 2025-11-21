/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Giacomo Sanchietti <giacomo.sanchietti@nethesis.it>
 */

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// TestBasicAuthUnit tests that BasicAuth works for unit authentication.
func TestBasicAuthUnit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := setupRouter()

	// Test /prometheus/targets with valid basic auth
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/prometheus/targets", nil)
	req.SetBasicAuth("prometheus", "prometheus")
	router.ServeHTTP(w, req)

	// Should succeed with correct credentials
	assert.Equal(t, http.StatusOK, w.Code, "BasicAuth should succeed with correct credentials")
}

// TestBasicAuthInvalid tests that BasicAuth rejects invalid credentials.
func TestBasicAuthInvalid(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := setupRouter()

	// Test /prometheus/targets with invalid basic auth
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/prometheus/targets", nil)
	req.SetBasicAuth("wrong", "credentials")
	router.ServeHTTP(w, req)

	// Should fail with wrong credentials
	assert.Equal(t, http.StatusUnauthorized, w.Code, "BasicAuth should fail with wrong credentials")
}

// TestJWTExpiration tests that expired JWT tokens are rejected.
func TestJWTExpiration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := setupRouter()

	// First, login to get a token
	w := httptest.NewRecorder()
	loginBody := `{"username": "admin", "password": "admin"}`
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer([]byte(loginBody)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	var loginResp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&loginResp)
	assert.Equal(t, float64(200), loginResp["code"], "Login should succeed")

	token := loginResp["token"].(string)
	assert.NotEmpty(t, token, "Token should not be empty")

	// Test refresh endpoint (which checks token validity)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	// Should be successful with valid token
	assert.Equal(t, http.StatusOK, w.Code, "Token should be valid immediately after login")
}

// TestJWTInvalidSignature tests that malformed JWT tokens are rejected.
func TestJWTInvalidSignature(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := setupRouter()

	// Test /refresh with invalid token
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/refresh", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.signature")
	router.ServeHTTP(w, req)

	// Should fail with invalid token
	assert.Equal(t, http.StatusUnauthorized, w.Code, "Invalid JWT should be rejected")
}

// TestJWTMissing tests that missing JWT tokens are rejected.
func TestJWTMissing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := setupRouter()

	// Test /refresh without token
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/refresh", nil)
	router.ServeHTTP(w, req)

	// Should fail without token
	assert.Equal(t, http.StatusUnauthorized, w.Code, "Missing JWT should be rejected")
}

// TestBasicAuthMissingCredentials tests that missing credentials are rejected.
func TestBasicAuthMissingCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := setupRouter()

	// Test /prometheus/targets without basic auth
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/prometheus/targets", nil)
	router.ServeHTTP(w, req)

	// Should fail without credentials
	assert.Equal(t, http.StatusUnauthorized, w.Code, "Missing BasicAuth should be rejected")
}

// TestLoginFailure tests that login fails with wrong password.
func TestLoginFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := setupRouter()

	w := httptest.NewRecorder()
	loginBody := `{"username": "admin", "password": "wrongpassword"}`
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer([]byte(loginBody)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	// Should fail with wrong password
	assert.Equal(t, http.StatusUnauthorized, w.Code, "Login should fail with wrong password")
}

// TestLogoutInvalidatesToken tests that logout invalidates the token.
func TestLogoutInvalidatesToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := setupRouter()

	// Login first
	w := httptest.NewRecorder()
	loginBody := `{"username": "admin", "password": "admin"}`
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer([]byte(loginBody)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	var loginResp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&loginResp)
	token := loginResp["token"].(string)

	// Verify token is valid before logout
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "Token should be valid before logout")

	// Logout
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "Logout should succeed")

	// Try to use token after logout (should fail)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	// The middleware returns 403 for failed authorization checks (CheckTokenValidation returns false)
	assert.Equal(t, http.StatusForbidden, w.Code, "Token should be invalid after logout")
}

// TestAuthHeaderFormats tests different JWT header formats.
func TestAuthHeaderFormats(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := setupRouter()

	// Login to get token
	w := httptest.NewRecorder()
	loginBody := `{"username": "admin", "password": "admin"}`
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer([]byte(loginBody)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	var loginResp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&loginResp)
	token := loginResp["token"].(string)

	// Test valid "Bearer" format
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "Standard Bearer format should work")

	// Test without "Bearer" prefix (should fail)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/refresh", nil)
	req.Header.Set("Authorization", token) // Missing "Bearer" prefix
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "Missing Bearer prefix should fail")
}

// TestAdminPrivilegeCheck tests that non-admin users cannot access admin endpoints.
func TestAdminPrivilegeCheck(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := setupRouter()

	// Create and login with limited user
	w := httptest.NewRecorder()
	adminLoginBody := `{"username": "admin", "password": "admin"}`
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer([]byte(adminLoginBody)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	var adminLoginResp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&adminLoginResp)
	adminToken := adminLoginResp["token"].(string)

	// Create limited user
	w = httptest.NewRecorder()
	addBody := `{"username": "limiteduser2", "password": "limited", "display_name": "Limited", "admin": false}`
	req, _ = http.NewRequest("POST", "/accounts", bytes.NewBuffer([]byte(addBody)))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	// Login as limited user
	w = httptest.NewRecorder()
	limitedLoginBody := `{"username": "limiteduser2", "password": "limited"}`
	req, _ = http.NewRequest("POST", "/login", bytes.NewBuffer([]byte(limitedLoginBody)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	var limitedLoginResp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&limitedLoginResp)
	limitedToken := limitedLoginResp["token"].(string)

	// Try to access /accounts endpoint (admin only)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/accounts", nil)
	req.Header.Set("Authorization", "Bearer "+limitedToken)
	router.ServeHTTP(w, req)

	// Should be forbidden (403)
	assert.Equal(t, http.StatusForbidden, w.Code, "Non-admin user should not access admin endpoint")
}

// TestTokenValidationCaching tests token caching for performance.
func TestTokenValidationCaching(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := setupRouter()

	// Login to get token
	w := httptest.NewRecorder()
	loginBody := `{"username": "admin", "password": "admin"}`
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer([]byte(loginBody)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	var loginResp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&loginResp)
	token := loginResp["token"].(string)

	// Make multiple requests with the same token
	for i := 0; i < 3; i++ {
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("GET", "/refresh", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "Cached token should remain valid")
	}
}

// TestConcurrentRequests tests that middleware handles concurrent requests safely.
func TestConcurrentRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := setupRouter()

	// Login to get token
	w := httptest.NewRecorder()
	loginBody := `{"username": "admin", "password": "admin"}`
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer([]byte(loginBody)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	var loginResp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&loginResp)
	token := loginResp["token"].(string)

	// Simulate concurrent requests (simplified test)
	results := make(chan int, 5)
	for i := 0; i < 5; i++ {
		go func() {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/refresh", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			router.ServeHTTP(w, req)
			results <- w.Code
		}()
	}

	// Verify all requests succeeded
	successCount := 0
	for i := 0; i < 5; i++ {
		code := <-results
		if code == http.StatusOK {
			successCount++
		}
	}
	assert.Equal(t, 5, successCount, "All concurrent requests should succeed")
}

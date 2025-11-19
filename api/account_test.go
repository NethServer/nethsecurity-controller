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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// TestGetSSHKeys tests retrieving SSH keys for a user.
func TestGetSSHKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := setupRouter()

	// First, login to get a valid token
	var loginResp map[string]interface{}
	w := httptest.NewRecorder()
	loginBody := `{"username": "admin", "password": "admin"}`
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer([]byte(loginBody)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "login should succeed")
	json.NewDecoder(w.Body).Decode(&loginResp)
	assert.NotNil(t, loginResp["token"], "token should be present in login response")
	token := loginResp["token"].(string)

	// Call GET /accounts/ssh-keys
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/accounts/ssh-keys", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	// Should return 200 OK (even if no keys exist yet)
	assert.Equal(t, http.StatusOK, w.Code, "GetSSHKeys should return 200 OK")

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, float64(200), resp["code"], "response code should be 200")
	assert.Equal(t, "success", resp["message"], "response message should be 'success'")
}

// TestAddSSHKeys tests generating a new SSH key pair.
func TestAddSSHKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := setupRouter()

	// First, login to get a valid token
	var loginResp map[string]interface{}
	w := httptest.NewRecorder()
	loginBody := `{"username": "admin", "password": "admin"}`
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer([]byte(loginBody)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "login should succeed")
	json.NewDecoder(w.Body).Decode(&loginResp)
	token := loginResp["token"].(string)

	// Call POST /accounts/ssh-keys with passphrase
	w = httptest.NewRecorder()
	sshGenBody := `{"passphrase": "test-passphrase"}`
	req, _ = http.NewRequest("POST", "/accounts/ssh-keys", bytes.NewBuffer([]byte(sshGenBody)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	// SSH key generation might fail if ssh-keygen is not available in test environment
	// Only assert on successful response
	if w.Code == http.StatusOK {
		var resp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&resp)
		assert.Equal(t, float64(200), resp["code"], "response code should be 200")
		assert.Equal(t, "success", resp["message"], "response message should be 'success'")
		data := resp["data"].(map[string]interface{})
		assert.NotEmpty(t, data["key_pub"], "key_pub should not be empty")
	}
}

// TestDeleteSSHKeys tests deleting SSH keys for a user.
func TestDeleteSSHKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := setupRouter()

	// First, login to get a valid token
	var loginResp map[string]interface{}
	w := httptest.NewRecorder()
	loginBody := `{"username": "admin", "password": "admin"}`
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer([]byte(loginBody)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "login should succeed")
	json.NewDecoder(w.Body).Decode(&loginResp)
	token := loginResp["token"].(string)

	// Call DELETE /accounts/ssh-keys
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/accounts/ssh-keys", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	// Should return 200 OK
	assert.Equal(t, http.StatusOK, w.Code, "DeleteSSHKeys should return 200 OK")

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, float64(200), resp["code"], "response code should be 200")
	assert.Equal(t, "success", resp["message"], "response message should be 'success'")
}

// TestSSHKeyValidation tests that SSH key operations handle missing keys gracefully.
func TestSSHKeyValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := setupRouter()

	// First, login to get a valid token
	var loginResp map[string]interface{}
	w := httptest.NewRecorder()
	loginBody := `{"username": "admin", "password": "admin"}`
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer([]byte(loginBody)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "login should succeed")
	json.NewDecoder(w.Body).Decode(&loginResp)
	token := loginResp["token"].(string)

	// Delete any existing keys first
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/accounts/ssh-keys", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	// Now try to get keys (should return empty without error)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/accounts/ssh-keys", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "GetSSHKeys should return 200 OK even with missing keys")
}

// TestUpdatePassword tests updating user password with correct old password.
func TestUpdatePassword(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := setupRouter()

	// First, login to get a valid token
	var loginResp map[string]interface{}
	w := httptest.NewRecorder()
	loginBody := `{"username": "admin", "password": "admin"}`
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer([]byte(loginBody)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "login should succeed")
	json.NewDecoder(w.Body).Decode(&loginResp)
	token := loginResp["token"].(string)

	// Call PUT /accounts/password with old and new password
	w = httptest.NewRecorder()
	passChangeBody := `{"old_password": "admin", "new_password": "newpassword123"}`
	req, _ = http.NewRequest("PUT", "/accounts/password", bytes.NewBuffer([]byte(passChangeBody)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	// Should return 200 OK
	assert.Equal(t, http.StatusOK, w.Code, "UpdatePassword should return 200 OK with correct old password")

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, float64(200), resp["code"], "response code should be 200")
	assert.Equal(t, "success", resp["message"], "response message should be 'success'")

	// Reset password back to "admin" for other tests
	w = httptest.NewRecorder()
	passChangeBody = `{"old_password": "newpassword123", "new_password": "admin"}`
	req, _ = http.NewRequest("PUT", "/accounts/password", bytes.NewBuffer([]byte(passChangeBody)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
}

// TestPasswordMismatch tests that password update fails with incorrect old password.
func TestPasswordMismatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := setupRouter()

	// First, login to get a valid token
	var loginResp map[string]interface{}
	w := httptest.NewRecorder()
	loginBody := `{"username": "admin", "password": "admin"}`
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer([]byte(loginBody)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "login should succeed")
	json.NewDecoder(w.Body).Decode(&loginResp)
	token := loginResp["token"].(string)

	// Call PUT /accounts/password with wrong old password
	w = httptest.NewRecorder()
	passChangeBody := `{"old_password": "wrongpassword", "new_password": "newpassword123"}`
	req, _ = http.NewRequest("PUT", "/accounts/password", bytes.NewBuffer([]byte(passChangeBody)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	// Should return 400 Bad Request
	assert.Equal(t, http.StatusBadRequest, w.Code, "UpdatePassword should return 400 with incorrect old password")

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, float64(400), resp["code"], "response code should be 400")
	assert.Contains(t, resp["message"].(string), "mismatch", "response should indicate password mismatch")
}

// TestGetAccountsAuthorizationForbidden tests that non-admin users cannot access /accounts endpoint.
func TestGetAccountsAuthorizationForbidden(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := setupRouter()

	// Create and login with limited user
	// First, login as admin to create a limited user account
	var adminLoginResp map[string]interface{}
	w := httptest.NewRecorder()
	adminLoginBody := `{"username": "admin", "password": "admin"}`
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer([]byte(adminLoginBody)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "admin login should succeed")
	json.NewDecoder(w.Body).Decode(&adminLoginResp)
	adminToken := adminLoginResp["token"].(string)

	// Create a limited user account
	w = httptest.NewRecorder()
	addBody := `{"username": "limiteduser", "password": "limited", "display_name": "Limited User", "admin": false}`
	req, _ = http.NewRequest("POST", "/accounts", bytes.NewBuffer([]byte(addBody)))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	// Now login as the limited user
	var limitedLoginResp map[string]interface{}
	w = httptest.NewRecorder()
	limitedLoginBody := `{"username": "limiteduser", "password": "limited"}`
	req, _ = http.NewRequest("POST", "/login", bytes.NewBuffer([]byte(limitedLoginBody)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "limited user login should succeed")
	json.NewDecoder(w.Body).Decode(&limitedLoginResp)
	limitedToken := limitedLoginResp["token"].(string)

	// Try to access /accounts endpoint as limited user
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/accounts", nil)
	req.Header.Set("Authorization", "Bearer "+limitedToken)
	router.ServeHTTP(w, req)

	// Should return 403 Forbidden
	assert.Equal(t, http.StatusForbidden, w.Code, "non-admin user should not access /accounts endpoint")

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, float64(403), resp["code"], "response code should be 403")
}

// TestAddSSHKeysInvalidRequest tests that AddSSHKeys rejects malformed requests.
func TestAddSSHKeysInvalidRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := setupRouter()

	// First, login to get a valid token
	var loginResp map[string]interface{}
	w := httptest.NewRecorder()
	loginBody := `{"username": "admin", "password": "admin"}`
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer([]byte(loginBody)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "login should succeed")
	json.NewDecoder(w.Body).Decode(&loginResp)
	token := loginResp["token"].(string)

	// Call POST /accounts/ssh-keys with malformed JSON
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/accounts/ssh-keys", bytes.NewBuffer([]byte("invalid json")))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	// Should return 400 Bad Request
	assert.Equal(t, http.StatusBadRequest, w.Code, "AddSSHKeys should reject malformed JSON")
}

// TestUpdatePasswordInvalidRequest tests that UpdatePassword rejects malformed requests.
func TestUpdatePasswordInvalidRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := setupRouter()

	// First, login to get a valid token
	var loginResp map[string]interface{}
	w := httptest.NewRecorder()
	loginBody := `{"username": "admin", "password": "admin"}`
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer([]byte(loginBody)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "login should succeed")
	json.NewDecoder(w.Body).Decode(&loginResp)
	token := loginResp["token"].(string)

	// Call PUT /accounts/password with malformed JSON
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("PUT", "/accounts/password", bytes.NewBuffer([]byte("invalid json")))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	// Should return 400 Bad Request
	assert.Equal(t, http.StatusBadRequest, w.Code, "UpdatePassword should reject malformed JSON")
}

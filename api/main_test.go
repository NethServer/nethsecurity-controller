package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	mathrand "math/rand"

	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/NethServer/nethsecurity-controller/api/methods"
	"github.com/NethServer/nethsecurity-controller/api/models"
	"github.com/NethServer/nethsecurity-controller/api/storage"
	"github.com/NethServer/nethsecurity-controller/api/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

var router *gin.Engine

// TestAESGCMEncryption tests AES-GCM encryption and decryption.
func TestAESGCMEncryption(t *testing.T) {
	key := []byte("12345678901234567890123456789012") // AES-256, 32 byte
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}
	plaintext := []byte("Hello, AES-GCM encryption!")

	ciphertext, err := utils.EncryptAESGCM(plaintext, key)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ciphertext should not match plaintext")
	}

	decrypted, err := utils.DecryptAESGCM(ciphertext, key)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted text does not match original. got: %s, want: %s", decrypted, plaintext)
	}

	// Test with wrong key
	wrongKey := make([]byte, 32)
	_, err = rand.Read(wrongKey)
	if err != nil {
		t.Fatalf("failed to generate wrong key: %v", err)
	}
	_, err = utils.DecryptAESGCM(ciphertext, wrongKey)
	if err == nil {
		t.Error("decryption should fail with wrong key")
	}
}

// TestAESGCMToString tests EncryptAESGCMToString and DecryptAESGCMFromString helpers.
func TestAESGCMToString(t *testing.T) {
	key := []byte("12345678901234567890123456789012") // 32 bytes

	plaintext := []byte("Store this in DB as base64!")

	ciphertextB64, err := utils.EncryptAESGCMToString(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptAESGCMToString failed: %v", err)
	}
	if ciphertextB64 == "" {
		t.Error("ciphertextB64 should not be empty")
	}

	decrypted, err := utils.DecryptAESGCMFromString(ciphertextB64, key)
	if err != nil {
		t.Fatalf("DecryptAESGCMFromString failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted text does not match original. got: %s, want: %s", decrypted, plaintext)
	}

	// Test with wrong key
	wrongKey := []byte("abcdefghabcdefghabcdefghabcdefgh") // 32 bytes
	_, err = utils.DecryptAESGCMFromString(ciphertextB64, wrongKey)
	if err == nil {
		t.Error("decryption should fail with wrong key")
	}
}

func TestMultipleListenAddresses(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router = setupRouter()

	// Start two servers on different listeners
	if len(configuration.Config.ListenAddress) < 2 {
		t.Fatalf("expected at least 2 listen addresses, got %d", len(configuration.Config.ListenAddress))
	}

	servers := make([]*httptest.Server, 0, len(configuration.Config.ListenAddress))
	for range configuration.Config.ListenAddress {
		// Use httptest.Server to simulate listening on multiple addresses
		ts := httptest.NewServer(router)
		servers = append(servers, ts)
	}
	defer func() {
		for _, ts := range servers {
			ts.Close()
		}
	}()

	// Test /health endpoint on all servers
	for i, ts := range servers {
		resp, err := http.Get(ts.URL + "/health")
		if err != nil {
			t.Fatalf("server %d: failed to GET /health: %v", i, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("server %d: expected status 200, got %d", i, resp.StatusCode)
		}
	}
}

// TestHealthEndpoint tests the /health endpoint.
func TestHealthEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router = setupRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("expected status 'ok', got %v", resp["status"])
	}
}

func TestMainEndpoints(t *testing.T) {
	// Tests assume to run on a clean database, otherwise 2FA tests will fail
	gin.SetMode(gin.TestMode)
	router = setupRouter()
	var token string

	t.Run("TestLoginEndpoint", func(t *testing.T) {
		// Remove 2FA config from previous tests
		os.RemoveAll(configuration.Config.SecretsDir + "/" + "admin")
		w := httptest.NewRecorder()
		var jsonResponse map[string]interface{}
		body := `{"username": "admin", "password": "admin"}`
		req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)
		json.NewDecoder(w.Body).Decode(&jsonResponse)
		token = jsonResponse["token"].(string)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.NotEmpty(t, token)
		assert.True(t, methods.CheckTokenValidation("admin", token))
	})

	t.Run("TestRefreshEndpoint", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/refresh", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("TestGet2FAStatusEndpoint", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/2fa", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("TestLogoutEndpoint", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/logout", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.False(t, methods.CheckTokenValidation("admin", token))
	})

	t.Run("TestGetAccountsEndpoint", func(t *testing.T) {
		// Login again
		var jsonResponse map[string]interface{}
		w := httptest.NewRecorder()
		body := `{"username": "admin", "password": "admin"}`
		req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)
		json.NewDecoder(w.Body).Decode(&jsonResponse)
		token = jsonResponse["token"].(string)

		req, _ = http.NewRequest("GET", "/accounts", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
		// response is: gin.H{"accounts": accounts, "total": len(accounts)},
		json.NewDecoder(w.Body).Decode(&jsonResponse)
		data := jsonResponse["data"].(map[string]interface{})
		assert.Equal(t, data["accounts"].([]interface{})[0].(map[string]interface{})["username"], "admin")
		assert.Equal(t, data["accounts"].([]interface{})[0].(map[string]interface{})["display_name"], "Administrator")
		assert.Equal(t, data["accounts"].([]interface{})[0].(map[string]interface{})["two_fa"], false)
	})

	t.Run("TestAddUpdateDeleteAccount", func(t *testing.T) {
		w := httptest.NewRecorder()
		// Add account
		addBody := `{"username": "testuser", "password": "testpass", "admin": false, "display_name": "Test User"}`
		addReq, _ := http.NewRequest("POST", "/accounts", bytes.NewBuffer([]byte(addBody)))
		addReq.Header.Set("Content-Type", "application/json")
		addReq.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(w, addReq)
		assert.Equal(t, http.StatusCreated, w.Code)
		var addResp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&addResp)
		id := fmt.Sprintf("%v", addResp["data"].(map[string]interface{})["id"])
		assert.NotEmpty(t, id)
		// Get accounts to find the new account's ID
		w = httptest.NewRecorder()
		getReq, _ := http.NewRequest("GET", "/accounts", nil)
		getReq.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(w, getReq)
		var getResp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&getResp)
		accounts := getResp["data"].(map[string]interface{})["accounts"].([]interface{})
		var testAccountID string
		for _, acc := range accounts {
			accMap := acc.(map[string]interface{})
			if accMap["username"] == "testuser" {
				testAccountID = fmt.Sprintf("%v", accMap["id"])
			}
		}
		assert.NotEmpty(t, testAccountID)
		// Update account display name
		updateBody := `{"display_name": "Updated User", "unit_groups": [], "admin": false}`
		updateReq, _ := http.NewRequest("PUT", "/accounts/"+testAccountID, bytes.NewBuffer([]byte(updateBody)))
		updateReq.Header.Set("Content-Type", "application/json")
		updateReq.Header.Set("Authorization", "Bearer "+token)
		w = httptest.NewRecorder()
		router.ServeHTTP(w, updateReq)
		assert.Equal(t, http.StatusOK, w.Code)
		// Get account and check display name
		w = httptest.NewRecorder()
		getOneReq, _ := http.NewRequest("GET", "/accounts/"+testAccountID, nil)
		getOneReq.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(w, getOneReq)
		var getOneResp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&getOneResp)
		accData := getOneResp["data"].(map[string]interface{})["account"].(map[string]interface{})
		assert.Equal(t, "Updated User", accData["display_name"])
		// Delete account
		w = httptest.NewRecorder()
		deleteReq, _ := http.NewRequest("DELETE", "/accounts/"+testAccountID, nil)
		deleteReq.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(w, deleteReq)
		assert.Equal(t, http.StatusOK, w.Code)
		// Ensure account is deleted
		w = httptest.NewRecorder()
		getOneReq, _ = http.NewRequest("GET", "/accounts/"+testAccountID, nil)
		getOneReq.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(w, getOneReq)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("TestRegisterUnitEndpoint", func(t *testing.T) {
		// create credentials directory
		if _, err := os.Stat(configuration.Config.CredentialsDir); os.IsNotExist(err) {
			if err := os.MkdirAll(configuration.Config.CredentialsDir, 0755); err != nil {
				t.Fatalf("failed to create directory: %v", err)
			}
		}
		// make sure configuration.Config.OpenVPNPKIDir does not exists
		os.RemoveAll(configuration.Config.OpenVPNPKIDir)
		unitID := "88860838-63bd-4717-a6c3-cbc351010843"
		body := `{"unit_id": "` + unitID + `", "username": "myuser", "unit_name": "myname", "password": "mypassword"}`
		req, _ := http.NewRequest("POST", "/units/register", bytes.NewBuffer([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("RegistrationToken", "1234")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code)

		// create OpenVPN directory
		if _, err := os.Stat(configuration.Config.OpenVPNPKIDir + "/issued"); os.IsNotExist(err) {
			if err := os.MkdirAll(configuration.Config.OpenVPNPKIDir+"/issued", 0755); err != nil {
				t.Fatalf("failed to create directory: %v", err)
			}
			if err := os.MkdirAll(configuration.Config.OpenVPNPKIDir+"/private", 0755); err != nil {
				t.Fatalf("failed to create directory: %v", err)
			}
		}
		// create fake certificate file and key file
		if _, err := os.Create(configuration.Config.OpenVPNPKIDir + "/issued/" + unitID + ".crt"); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}
		if _, err := os.Create(configuration.Config.OpenVPNPKIDir + "/private/" + unitID + ".key"); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}
		// create face ca.crt file
		if _, err := os.Create(configuration.Config.OpenVPNPKIDir + "/ca.crt"); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}
		req, _ = http.NewRequest("POST", "/units/register", bytes.NewBuffer([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("RegistrationToken", "1234")
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, w.Body.String())

		// Check password retrieval at lower level
		user, pass, err := storage.GetUnitCredentials(unitID) // should return empty credentials
		assert.NoError(t, err, "GetUnitCredentials should not return an error")
		assert.Equal(t, "myuser", user)
		assert.Equal(t, "mypassword", pass)
	})

	t.Run("TestNoRoute", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/nonexistent", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	// 2FA test: enable, verify with OTP, verify with recovery code, remove
	t.Run("Test2FAEnableVerifyRemove", func(t *testing.T) {
		w := httptest.NewRecorder()
		// Execute login to get token
		var jsonResponse map[string]interface{}
		body := `{"username": "admin", "password": "admin"}`
		req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)
		json.NewDecoder(w.Body).Decode(&jsonResponse)
		token = jsonResponse["token"].(string)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.NotEmpty(t, token)

		// Enable 2FA (get QR code and secret)
		qrReq, _ := http.NewRequest("GET", "/2fa/qr-code", nil)
		qrReq.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(w, qrReq)
		assert.Equal(t, http.StatusOK, w.Code)
		var qrResp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&qrResp)
		secret := qrResp["data"].(map[string]interface{})["key"].(string)
		assert.NotEmpty(t, secret)

		otp, err := totp.GenerateCode(secret, time.Now())
		assert.NoError(t, err)
		assert.NotEmpty(t, otp)

		// Verify 2FA login with OTP code
		otpBody := map[string]string{"username": "admin", "token": token, "otp": otp}
		otpBodyBytes, _ := json.Marshal(otpBody)
		otpReq, _ := http.NewRequest("POST", "/2fa/otp-verify", bytes.NewBuffer(otpBodyBytes))
		otpReq.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()
		router.ServeHTTP(w, otpReq)
		assert.Equal(t, http.StatusOK, w.Code)

		// Get recovery codes
		w = httptest.NewRecorder()
		statusReq, _ := http.NewRequest("GET", "/2fa", nil)
		statusReq.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(w, statusReq)
		assert.Equal(t, http.StatusOK, w.Code)
		var statusResp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&statusResp)
		recoveryCodes := statusResp["data"].(map[string]interface{})["recovery_codes"].([]interface{})
		assert.NotEmpty(t, recoveryCodes)
		recoveryCode := recoveryCodes[0].(string)

		// Verify 2FA login with recovery code
		recBody := map[string]string{"username": "admin", "token": token, "otp": recoveryCode}
		recBodyBytes, _ := json.Marshal(recBody)
		recReq, _ := http.NewRequest("POST", "/2fa/otp-verify", bytes.NewBuffer(recBodyBytes))
		recReq.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()
		router.ServeHTTP(w, recReq)
		assert.Equal(t, http.StatusOK, w.Code)

		// Remove 2FA
		w = httptest.NewRecorder()
		delReq, _ := http.NewRequest("DELETE", "/2fa", nil)
		delReq.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(w, delReq)
		assert.Equal(t, http.StatusOK, w.Code)

		// Check 2FA is disabled
		w = httptest.NewRecorder()
		statusReq, _ = http.NewRequest("GET", "/2fa", nil)
		statusReq.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(w, statusReq)
		assert.Equal(t, http.StatusOK, w.Code)
		var statusResp2fa map[string]interface{}
		json.NewDecoder(w.Body).Decode(&statusResp2fa)
		assert.Equal(t, false, statusResp2fa["data"].(map[string]interface{})["status"])
		// recovery codes should be empty
		assert.Equal(t, []interface{}{}, statusResp2fa["data"].(map[string]interface{})["recovery_codes"])
	})
}

func addUnit(t *testing.T) string {
	// Generate a UUID v4 and convert it to string using the uuid package
	unitID := uuid.New().String()

	if _, err := os.Stat(configuration.Config.CredentialsDir); os.IsNotExist(err) {
		os.MkdirAll(configuration.Config.CredentialsDir, 0755)
	}
	if _, err := os.Stat(configuration.Config.OpenVPNCCDDir); os.IsNotExist(err) {
		os.MkdirAll(configuration.Config.OpenVPNCCDDir, 0755)
	}
	if _, err := os.Stat(configuration.Config.OpenVPNPKIDir); os.IsNotExist(err) {
		os.MkdirAll(configuration.Config.OpenVPNPKIDir, 0755)
	}
	if _, err := os.Stat(configuration.Config.OpenVPNStatusDir); os.IsNotExist(err) {
		os.MkdirAll(configuration.Config.OpenVPNStatusDir, 0755)
	}

	// Create fake credentials, ccd and cr files, otherwise GetUnit will fail
	creds := map[string]string{"username": "testuser", "password": "testpass"}
	credsBytes, _ := json.Marshal(creds)
	werr := os.WriteFile(configuration.Config.CredentialsDir+"/"+unitID, credsBytes, 0644)
	assert.NoError(t, werr, "failed to write credentials file")
	conf := "ifconfig-push 10.10.10.2 255.255.255.0 \n"
	werr = os.WriteFile(configuration.Config.OpenVPNCCDDir+"/"+unitID, []byte(conf), 0644)
	assert.NoError(t, werr, "failed to write ccd file")
	if _, err := os.Stat(configuration.Config.OpenVPNPKIDir + "/issued/" + unitID + ".crt"); os.IsNotExist(err) {
		if _, err := os.Create(configuration.Config.OpenVPNPKIDir + "/issued/" + unitID + ".crt"); err != nil {
			t.Fatalf("failed to create certificate file: %v", err)
		}
	}
	// Manually add to the database: we can't call /units POST endpoint because
	// it requires the presence of easyrsa binary and configuration files
	newIp := storage.GetFreeIP()
	storage.AddUnit(unitID, newIp)

	return unitID
}

func TestAddInfoAndGetRemoteInfo(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router = setupRouter()

	// Simulate an add unit
	unitID := addUnit(t)

	// AddInfo: POST /ingest/info (simulate BasicAuth middleware)
	w := httptest.NewRecorder()
	info := models.UnitInfo{
		UnitName:         "my-test-unit",
		Version:          "1.0.0",
		VersionUpdate:    "1.0.1",
		ScheduledUpdate:  0,
		SubscriptionType: "test-subscription",
		SystemID:         "test-system-id",
		SSHPort:          22,
		FQDN:             "test.example.com",
		APIVersion:       "v1",
	}
	infoBytes, _ := json.Marshal(info)
	req := httptest.NewRequest("POST", "/ingest/info", bytes.NewBuffer(infoBytes))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(unitID, "1234")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "AddInfo should return 200 OK")

	w = httptest.NewRecorder()
	var jsonResponse map[string]interface{}
	body := `{"username": "admin", "password": "admin"}`
	req, _ = http.NewRequest("POST", "/login", bytes.NewBuffer([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	json.NewDecoder(w.Body).Decode(&jsonResponse)
	token := jsonResponse["token"].(string)

	// Call /units/:unit_id to retrieve unit info
	req = httptest.NewRequest("GET", "/units/"+unitID, nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	json.NewDecoder(w.Body).Decode(&jsonResponse)
	infoResp := jsonResponse["data"].(map[string]interface{})["info"].(map[string]interface{})
	assert.Equal(t, info.UnitName, infoResp["unit_name"])
	assert.Equal(t, info.Version, infoResp["version"])
	assert.Equal(t, info.VersionUpdate, infoResp["version_update"])
	assert.Equal(t, float64(info.ScheduledUpdate), infoResp["scheduled_update"])
	assert.Equal(t, info.SubscriptionType, infoResp["subscription_type"])
	assert.Equal(t, info.SystemID, infoResp["system_id"])
	assert.Equal(t, float64(info.SSHPort), infoResp["ssh_port"])
	assert.Equal(t, info.FQDN, infoResp["fqdn"])
	assert.Equal(t, info.APIVersion, infoResp["api_version"])
	ipaddress := jsonResponse["data"].(map[string]interface{})["ipaddress"].(string)
	assert.True(t, strings.HasPrefix(ipaddress, "172.21.0"), "ipaddress should start with 172.21.0, got: %v", ipaddress)
	netmask := jsonResponse["data"].(map[string]interface{})["netmask"].(string)
	assert.Equal(t, configuration.Config.OpenVPNNetmask, netmask, "OpenVPNNetmask should match the one in configuration, got: %v", netmask)
}

func TestForwardedAuthMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router = setupRouter()

	// Test with valid credentials
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/auth", nil)
	req.SetBasicAuth("admin", "admin") // Use BasicAuth for testing
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	// Check if X-Auth-User header is set
	authUser := w.Header().Get("X-Auth-User")
	assert.Equal(t, "admin", authUser, "X-Auth-User header should be set to 'admin'")

	// Test with invalid credentials
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/auth", nil)
	req.SetBasicAuth("admin", "wrongpassword") // Use BasicAuth for testing
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}

func TestGetPlatformInfo(t *testing.T) {
	router = setupRouter()

	// Step 1: Login and get token
	loginBody := []byte(`{"username":"admin","password":"admin"}`)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(loginBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var loginResp map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&loginResp)
	token, ok := loginResp["token"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, token)

	// Step 2: Call GET /platform with token
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/platform", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Step 3: Check response
	var resp map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, float64(200), resp["code"])
	assert.Equal(t, "success", resp["message"])
	data, ok := resp["data"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "1194", data["vpn_port"])
	assert.Equal(t, "192.168.100.0/24", data["vpn_network"])
	assert.Equal(t, "1.0.0", data["controller_version"])
	assert.Equal(t, float64(30), data["metrics_retention_days"])
	assert.Equal(t, float64(90), data["logs_retention_days"])
}

func TestUnitGroupsAPI(t *testing.T) {
	router = setupRouter()
	unitId_1 := addUnit(t)
	unitId_2 := addUnit(t)
	randCounter := fmt.Sprintf("%d", mathrand.New(mathrand.NewSource(time.Now().UnixNano())).Intn(10000))

	// Login to get token
	w := httptest.NewRecorder()
	loginBody := []byte(`{"username":"admin","password":"admin"}`)
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(loginBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var loginResp map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&loginResp)
	token, ok := loginResp["token"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, token)

	// Create an empty unit group
	w = httptest.NewRecorder()
	// generate a random group name composed by testgroups + random number from 1 to 1000
	groupName := fmt.Sprintf("testgroups%s", randCounter)
	groupBody := []byte(`{"name":"` + groupName + `","description":"desc"}`)
	req, _ = http.NewRequest("POST", "/unit_groups", bytes.NewBuffer(groupBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var groupResp map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&groupResp)
	groupData := groupResp["data"].(map[string]interface{})
	groupID := fmt.Sprintf("%v", groupData["id"])
	assert.NotEmpty(t, groupID)

	// Update the group with units
	w = httptest.NewRecorder()
	updateBody := []byte(`{"name":"` + groupName + `","description":"desc", "units":["` + unitId_1 + `", "` + unitId_2 + `"]}`)
	req, _ = http.NewRequest("PUT", "/unit_groups/"+groupID, bytes.NewBuffer([]byte(updateBody)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// List unit groups
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/unit_groups", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Get the created unit group
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/unit_groups/"+groupID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var getGroupResp map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&getGroupResp)
	groupData = getGroupResp["data"].(map[string]interface{})
	assert.Equal(t, groupName, groupData["name"])
	assert.Equal(t, "desc", groupData["description"])
	units := groupData["units"].([]interface{})
	assert.Len(t, units, 2)
	assert.Contains(t, units, unitId_1)
	assert.Contains(t, units, unitId_2)

	// Update the unit group
	w = httptest.NewRecorder()
	updateBody = []byte(`{"name":"updatedgroup` + randCounter + `","description":"updated desc", "units":["` + unitId_1 + `", "` + unitId_2 + `"]}}`)
	req, _ = http.NewRequest("PUT", "/unit_groups/"+groupID, bytes.NewBuffer(updateBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	// Get the updated unit group and check the new name and description
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/unit_groups/"+groupID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var updatedGroupResp map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&updatedGroupResp)
	updatedGroupData := updatedGroupResp["data"].(map[string]interface{})
	assert.Equal(t, "updatedgroup"+randCounter, updatedGroupData["name"])
	assert.Equal(t, "updated desc", updatedGroupData["description"])

	// Try to update the group with a non-existing unit, expect failure (400)
	w = httptest.NewRecorder()
	nonExistingUnitID := uuid.New().String()
	updateBody = []byte(`{"name":"` + groupName + `","description":"desc", "units":["` + unitId_1 + `", "` + nonExistingUnitID + `"]}`)
	req, _ = http.NewRequest("PUT", "/unit_groups/"+groupID, bytes.NewBuffer(updateBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code, "should fail when adding non-existing unit to group")

	// Add limited user account
	w = httptest.NewRecorder()
	limitedUserName := fmt.Sprintf("limited%s", randCounter)
	addBody := `{"username": "` + limitedUserName + `", "password": "limited", "display_name": "Limited user"}`
	addReq, _ := http.NewRequest("POST", "/accounts", bytes.NewBuffer([]byte(addBody)))
	addReq.Header.Set("Content-Type", "application/json")
	addReq.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, addReq)
	assert.Equal(t, http.StatusCreated, w.Code)
	var addUserResp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&addUserResp)
	testAccountID := fmt.Sprintf("%v", addUserResp["data"].(map[string]interface{})["id"])
	assert.NotEmpty(t, testAccountID)

	// Try to add a non-existing group ID to the user account, expect failure
	w = httptest.NewRecorder()
	nonExistingGroupID := "9999999"
	addUserBody := []byte(`{"username":"` + limitedUserName + `","unit_groups":[` + nonExistingGroupID + `]}`)
	req, _ = http.NewRequest("PUT", "/accounts/"+testAccountID, bytes.NewBuffer(addUserBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code, "should fail when adding non-existing group ID")

	// Add unit group to user account
	w = httptest.NewRecorder()
	addUserBody = []byte(`{"username":"` + limitedUserName + `","unit_groups":[` + groupID + `]}`)
	req, _ = http.NewRequest("PUT", "/accounts/"+testAccountID, bytes.NewBuffer(addUserBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// Delete the unit group: should fail because it is associated with an account
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/unit_groups/"+groupID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code, "should not allow deleting a group associated with an account")
	assert.True(t, w.Code == http.StatusBadRequest, "expected 400 when deleting a group in use")

	// Remove the group from the user account's unit_groups
	w = httptest.NewRecorder()
	removeGroupBody := []byte(`{"username":"` + limitedUserName + `","unit_groups":[]}`)
	req, _ = http.NewRequest("PUT", "/accounts/"+testAccountID, bytes.NewBuffer(removeGroupBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// Now delete the unit group again, should succeed
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/unit_groups/"+groupID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "should allow deleting a group not associated with any account")

	// Get the account again and check that unit_groups does not contain groupID
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/accounts/"+testAccountID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var getAccountAfterDeleteResp map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&getAccountAfterDeleteResp)
	accountAfterDeleteData := getAccountAfterDeleteResp["data"].(map[string]interface{})["account"].(map[string]interface{})
	unitGroups := accountAfterDeleteData["unit_groups"].([]interface{})
	for _, v := range unitGroups {
		assert.NotEqual(t, groupID, fmt.Sprintf("%.0f", v), "unit_groups should not contain deleted groupID")
	}

	// Create a new group and add unitId_1 to it
	w = httptest.NewRecorder()
	groupName2 := fmt.Sprintf("group2_%s", randCounter)
	groupBody2 := []byte(`{"name":"` + groupName2 + `","description":"desc2", "units":["` + unitId_1 + `"]}`)
	req, _ = http.NewRequest("POST", "/unit_groups", bytes.NewBuffer(groupBody2))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var group2Resp map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&group2Resp)
	group2Data := group2Resp["data"].(map[string]interface{})
	group2ID := fmt.Sprintf("%v", group2Data["id"])
	assert.NotEmpty(t, group2ID)

	// Get the group and check that unitId_1 is present
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/unit_groups/"+group2ID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var getGroup3Resp map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&getGroup3Resp)
	group2Data = getGroup3Resp["data"].(map[string]interface{})
	units2 := group2Data["units"].([]interface{})
	assert.Len(t, units2, 1, "group2 should contain exactly one unit")
	assert.Equal(t, unitId_1, fmt.Sprintf("%v", units2[0]), "unitId_1 should be present in group2")

	// DELETE "/units/"+unitId_1 can't be tested because it requires easy-rsa binary and configuration file
}

func TestUnitAuthorization(t *testing.T) {
	router = setupRouter()
	unitId_1 := addUnit(t)
	unitId_2 := addUnit(t)

	randCounter := fmt.Sprintf("%d", mathrand.New(mathrand.NewSource(time.Now().UnixNano())).Intn(10000))

	// Login to get token
	w := httptest.NewRecorder()
	loginBody := []byte(`{"username":"admin","password":"admin"}`)
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(loginBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var loginResp map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&loginResp)
	token, ok := loginResp["token"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, token)

	// Create unit group with unitId_1
	w = httptest.NewRecorder()
	groupName := fmt.Sprintf("authgroup%s", randCounter)
	groupBody := []byte(`{"name":"` + groupName + `","description":"auth test group", "units":["` + unitId_1 + `"]}`)
	req, _ = http.NewRequest("POST", "/unit_groups", bytes.NewBuffer(groupBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var groupResp map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&groupResp)
	groupData := groupResp["data"].(map[string]interface{})
	groupID := fmt.Sprintf("%v", groupData["id"])
	assert.NotEmpty(t, groupID)

	// Create limited account associated to the unit group
	w = httptest.NewRecorder()
	limitedUserName := fmt.Sprintf("limited%s", randCounter)
	addBody := `{"username": "` + limitedUserName + `", "password": "limited", "display_name": "Limited user", "unit_groups": [` + groupID + `]}`
	addReq, _ := http.NewRequest("POST", "/accounts", bytes.NewBuffer([]byte(addBody)))
	addReq.Header.Set("Content-Type", "application/json")
	addReq.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, addReq)
	assert.Equal(t, http.StatusCreated, w.Code)
	var addUserResp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&addUserResp)
	limitedAccountID := fmt.Sprintf("%v", addUserResp["data"].(map[string]interface{})["id"])
	assert.NotEmpty(t, limitedAccountID)

	// Test /auth/<unit_id_1> with limited user - should return 200 OK
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/auth/"+unitId_1, nil)
	req.SetBasicAuth(limitedUserName, "limited")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "limited user should have access to unitId_1")
	authUser := w.Header().Get("X-Auth-User")
	assert.Equal(t, limitedUserName, authUser, "X-Auth-User header should be set to limited user")

	// Test /auth/<unit_id_2> with limited user - should return 403 Forbidden
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/auth/"+unitId_2, nil)
	req.SetBasicAuth(limitedUserName, "limited")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code, "limited user should not have access to unitId_2")

	// Login with limited user to get their token
	w = httptest.NewRecorder()
	limitedLoginBody := []byte(`{"username":"` + limitedUserName + `","password":"limited"}`)
	req, _ = http.NewRequest("POST", "/login", bytes.NewBuffer(limitedLoginBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var limitedLoginResp map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&limitedLoginResp)
	limitedToken, ok := limitedLoginResp["token"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, limitedToken)

	// // Test GET /units/<unit_id_1> with limited user - should return 200 OK
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/units/"+unitId_1, nil)
	req.Header.Set("Authorization", "Bearer "+limitedToken)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "limited user should be able to get unitId_1")

	// Test GET /units/<unit_id_2> with limited user - should return 403 Forbidden
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/units/"+unitId_2, nil)
	req.Header.Set("Authorization", "Bearer "+limitedToken)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code, "limited user should not be able to get unitId_2")

	// Test GET /units with limited user - should only return unitId_1
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/units", nil)
	req.Header.Set("Authorization", "Bearer "+limitedToken)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var unitsResp map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&unitsResp)
	unitsData := unitsResp["data"].([]interface{})
	assert.Len(t, unitsData, 1, "limited user should only see one unit")
	unit := unitsData[0].(map[string]interface{})
	assert.Equal(t, unitId_1, unit["id"], "limited user should only see unitId_1")

	// Limited user tries to delete unitId_1 (should fail with 403)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/units/"+unitId_1, nil)
	req.Header.Set("Authorization", "Bearer "+limitedToken)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code, "limited user should not be able to delete unitId_1")

	// Limited user tries to add a new unit (should fail with 403)
	w = httptest.NewRecorder()
	addUnitBody := []byte(`{"unit_id":"shouldfail","username":"failuser","unit_name":"Should Fail Unit","password":"failpass"}`)
	req, _ = http.NewRequest("POST", "/units", bytes.NewBuffer(addUnitBody))
	req.Header.Set("Authorization", "Bearer "+limitedToken)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code, "limited user should not be able to add a unit")
}

func TestToCIDR(t *testing.T) {
	tests := []struct {
		ip      string
		mask    string
		want    string
		wantErr bool
	}{
		{"192.168.1.10", "255.255.255.0", "192.168.1.10/24", false},
		{"172.16.5.4", "255.255.0.0", "172.16.5.4/16", false},
		{"192.168.1.10", "255.255.255.255", "192.168.1.10/32", false},
		{"192.168.1.10", "255.255.0", "", true}, // invalid mask
		{"notanip", "255.255.255.0", "", true},  // invalid ip
	}
	for _, tt := range tests {
		got := utils.ToCIDR(tt.ip, tt.mask)
		if got == "" {
			assert.Error(t, fmt.Errorf("invalid input"), "expected error for input: %v/%v", tt.ip, tt.mask)
		} else {
			assert.Equal(t, tt.want, got, "unexpected CIDR for input: %v/%v", tt.ip, tt.mask)
		}
	}
}

func TestToIpMask(t *testing.T) {
	tests := []struct {
		cidr    string
		wantIP  string
		wantNet string
		wantErr bool
	}{
		{"192.168.1.10/24", "192.168.1.10", "255.255.255.0", false},
		{"172.16.5.4/16", "172.16.5.4", "255.255.0.0", false},
		{"10.0.0.1/32", "10.0.0.1", "255.255.255.255", false},
		{"192.168.1.10/33", "", "", true}, // invalid mask
		{"notanip/24", "", "", true},      // invalid ip
		{"", "", "", true},                // empty input
	}
	for _, tt := range tests {
		ip, mask := utils.ToIpMask(tt.cidr)
		if tt.wantErr {
			assert.Equal(t, "", ip, "expected empty ip for input: %v", tt.cidr)
			assert.Equal(t, "", mask, "expected empty mask for input: %v", tt.cidr)
		} else {
			assert.Equal(t, tt.wantIP, ip, "unexpected ip for input: %v", tt.cidr)
			assert.Equal(t, tt.wantNet, mask, "unexpected mask for input: %v", tt.cidr)
		}
	}
}

func setupRouter() *gin.Engine {
	// Singleton
	if router != nil {
		return router
	}
	os.Setenv("LISTEN_ADDRESS", "0.0.0.0:8000,127.0.0.1:5000")
	os.Setenv("ADMIN_USERNAME", "admin")
	// default password is "password"
	os.Setenv("ADMIN_PASSWORD", "admin")
	os.Setenv("SECRET_JWT", "secret")
	os.Setenv("CREDENTIALS_DIR", "./credentials")
	os.Setenv("PROMTAIL_ADDRESS", "127.0.0.1")
	os.Setenv("PROMTAIL_PORT", "6565")
	os.Setenv("PROMETHEUS_PATH", "/prometheus")
	os.Setenv("WEBSSH_PATH", "webssh")
	os.Setenv("GRAFANA_PATH", "/grafana")
	os.Setenv("REGISTRATION_TOKEN", "1234")
	os.Setenv("DATA_DIR", "./data")
	os.Setenv("OVPN_DIR", "./ovpn")
	os.Setenv("REPORT_DB_URI", "postgres://report:password@127.0.0.1:5432/report")
	os.Setenv("GRAFANA_POSTGRES_PASSWORD", "password")
	os.Setenv("ISSUER_2FA", "test")
	os.Setenv("SECRETS_DIR", "./secrets")
	os.Setenv("ENCRYPTION_KEY", "12345678901234567890123456789012")
	os.Setenv("PLATFORM_INFO", `{"vpn_port":"1194","vpn_network":"192.168.100.0/24", "controller_version":"1.0.0", "nethserver_version":"1.6.0", "nethserver_system_id":"1234567890", "metrics_retention_days":30, "logs_retention_days":90}`)

	// create directory configuration directory
	if _, err := os.Stat(os.Getenv("DATA_DIR")); os.IsNotExist(err) {
		if err := os.MkdirAll(os.Getenv("DATA_DIR"), 0755); err != nil {
			fmt.Printf("failed to create directory: %v\n", err)
			os.Exit(1)
		}
	}

	router := setup()

	return router
}

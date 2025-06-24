package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"crypto/rand"

	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/NethServer/nethsecurity-controller/api/models"
	"github.com/NethServer/nethsecurity-controller/api/storage"
	"github.com/NethServer/nethsecurity-controller/api/utils"
	"github.com/gin-gonic/gin"
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
	})

	t.Run("TestGetAccountsEndpoint", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/accounts", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		// response is: gin.H{"accounts": accounts, "total": len(accounts)},
		var jsonResponse map[string]interface{}
		json.NewDecoder(w.Body).Decode(&jsonResponse)
		data := jsonResponse["data"].(map[string]interface{})
		assert.Equal(t, int(data["total"].(float64)), 1)
		assert.Equal(t, data["accounts"].([]interface{})[0].(map[string]interface{})["username"], "admin")
		assert.Equal(t, data["accounts"].([]interface{})[0].(map[string]interface{})["display_name"], "Administrator")
		assert.Equal(t, data["accounts"].([]interface{})[0].(map[string]interface{})["two_fa"], false)
	})

	t.Run("TestAddUpdateDeleteAccount", func(t *testing.T) {
		w := httptest.NewRecorder()
		// Add account
		addBody := `{"username": "testuser", "password": "testpass", "display_name": "Test User"}`
		addReq, _ := http.NewRequest("POST", "/accounts", bytes.NewBuffer([]byte(addBody)))
		addReq.Header.Set("Content-Type", "application/json")
		addReq.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(w, addReq)
		assert.Equal(t, http.StatusCreated, w.Code)
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
		updateBody := `{"display_name": "Updated User"}`
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
		body := `{"unit_id": "11", "username": "aa", "unit_name": "bbb", "password": "ccc"}`
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
		if _, err := os.Create(configuration.Config.OpenVPNPKIDir + "/issued/" + "11" + ".crt"); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}
		if _, err := os.Create(configuration.Config.OpenVPNPKIDir + "/private/" + "11" + ".key"); err != nil {
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
		assert.Equal(t, http.StatusOK, w.Code)
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

// TestTrustedIPMiddleware tests the TrustedIPMiddleware for allowed and denied
func TestTrustedIPMiddleware(t *testing.T) {
	os.Setenv("TRUSTED_IPS", "127.0.0.1,192.168.1.0/24")
	os.Setenv("TRUSTED_IP_EXCLUDE_PATHS", "/units/register")
	gin.SetMode(gin.TestMode)
	restricted_router := setup()

	// Allowed: 127.0.0.1
	req := httptest.NewRequest("GET", "/health", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	restricted_router.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("expected 200 for allowed IP, got %d", w.Code)
	}

	// Denied: 10.0.0.1
	req = httptest.NewRequest("GET", "/health", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	w = httptest.NewRecorder()
	restricted_router.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Errorf("expected 403 for denied IP, got %d", w.Code)
	}

	// Allowed: /units/register endpoint should be unrestricted
	body := `{"unit_id": "11", "username": "aa", "unit_name": "bbb", "password": "ccc"}`
	req = httptest.NewRequest("POST", "/units/register", bytes.NewBuffer([]byte(body)))
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("RegistrationToken", "1234")
	w = httptest.NewRecorder()
	restricted_router.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("expected 200 for /units/register endpoint, got %d", w.Code)
	}
}

func TestAddInfoAndGetRemoteInfo(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router = setupRouter()

	// Prepare: create a credentials file for the unit
	unitID := "457c2b94-13be-48c9-b4aa-c7d677c85ee8"
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
	storage.AddUnit(unitID)

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
	os.Setenv("TOKENS_DIR", "./tokens")
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

	// create directory configuration directory
	if _, err := os.Stat(os.Getenv("DATA_DIR")); os.IsNotExist(err) {
		if err := os.MkdirAll(os.Getenv("DATA_DIR"), 0755); err != nil {
			fmt.Printf("failed to create directory: %v\n", err)
			os.Exit(1)
		}
	}
	// create tokens directory
	if _, err := os.Stat(os.Getenv("TOKENS_DIR")); os.IsNotExist(err) {
		if err := os.MkdirAll(os.Getenv("TOKENS_DIR"), 0755); err != nil {
			fmt.Printf("failed to create directory: %v\n", err)
			os.Exit(1)
		}
	}

	router := setup()

	return router
}

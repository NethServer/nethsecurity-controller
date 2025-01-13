package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestMainEndpoints(t *testing.T) {

	gin.SetMode(gin.TestMode)
	router := setupRouter()
	var token string

	t.Run("TestLoginEndpoint", func(t *testing.T) {
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
}

func setupRouter() *gin.Engine {
	os.Setenv("LISTEN_ADDRESS", "0.0.0.0:8000")
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
	os.Setenv("DATA_DIR", "data")
	os.Setenv("OVPN_DIR", "ovpn")
	os.Setenv("REPORT_DB_URI", "postgres://report:password@127.0.0.1:5432/report")
	os.Setenv("GRAFANA_POSTGRES_PASSWORD", "password")
	os.Setenv("ISSUER_2FA", "test")
	os.Setenv("SECRETS_DIR", "data")

	router := setup()

	return router
}

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NethServer/nethsecurity-controller/api/models"
	"github.com/stretchr/testify/assert"
)

// These tests exercise the /ingest/* endpoints and require a database.
// Set REPORT_DB_URI environment variable before running tests.

func TestIngestUnitName(t *testing.T) {
	ginRouter := setupRouter()

	unitID := addUnit(t)

	payload := models.UnitNameRequest{Name: "test-unit-name"}
	b, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/ingest/dump-nsplug-config", bytes.NewBuffer(b))
	req.SetBasicAuth(unitID, "1234")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ginRouter.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "set unit name should return 200")
}

func TestIngestWanConfig(t *testing.T) {
	ginRouter := setupRouter()
	unitID := addUnit(t)

	reqBody := `{"data":[{"interface":"wan","device":"eth0","status":"up"},{"interface":"wan2","device":"eth1","status":"down"}]}`
	req := httptest.NewRequest("POST", "/ingest/dump-wan-config", bytes.NewBufferString(reqBody))
	req.SetBasicAuth(unitID, "1234")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ginRouter.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "set wan config should return 200")
}

func TestIngestOvpnConfig(t *testing.T) {
	ginRouter := setupRouter()
	unitID := addUnit(t)

	reqBody := `{"data":[{"instance":"server1","name":"srv","device":"tun0","type":"server"}]}`
	req := httptest.NewRequest("POST", "/ingest/dump-ovpn-config", bytes.NewBufferString(reqBody))
	req.SetBasicAuth(unitID, "1234")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ginRouter.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "set ovpn config should return 200")
}

func TestIngestMwanEvents(t *testing.T) {
	ginRouter := setupRouter()
	unitID := addUnit(t)

	reqBody := `{"data":[{"timestamp":1600000000,"wan":"wan","event":"up","interface":"eth0"},{"timestamp":1600000001,"wan":"wan2","event":"down","interface":"eth1"}]}`
	req := httptest.NewRequest("POST", "/ingest/dump-mwan-events", bytes.NewBufferString(reqBody))
	req.SetBasicAuth(unitID, "1234")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ginRouter.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "update mwan events should return 200")
}

func TestIngestTsAttacksAndDpiAndOvpnConnections(t *testing.T) {
	ginRouter := setupRouter()
	unitID := addUnit(t)

	// TS attacks
	attacks := `{"data":[{"timestamp":1600000000,"ip":"8.8.8.8"}]}`
	req := httptest.NewRequest("POST", "/ingest/dump-ts-attacks", bytes.NewBufferString(attacks))
	req.SetBasicAuth(unitID, "1234")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ginRouter.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "update ts attacks should return 200")

	// DPI stats
	dpi := `{"data":[{"timestamp":1600000000,"client_address":"10.0.0.1","bytes":1234,"client_name":"host","protocol":"tcp","host":"example.com","application":"http"}]}`
	req = httptest.NewRequest("POST", "/ingest/dump-dpi-stats", bytes.NewBufferString(dpi))
	req.SetBasicAuth(unitID, "1234")
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	ginRouter.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "update dpi stats should return 200")

	// OVPN connections
	ovpn := `{"data":[{"timestamp":1600000000,"instance":"server1","common_name":"cn","virtual_ip_addr":"10.8.0.2","remote_ip_addr":"1.2.3.4","start_time":1600000000,"duration":60,"bytes_received":100,"bytes_sent":200}]}`
	req = httptest.NewRequest("POST", "/ingest/dump-ovpn-connections", bytes.NewBufferString(ovpn))
	req.SetBasicAuth(unitID, "1234")
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	ginRouter.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "update ovpn connections should return 200")
}

func TestIngestInvalidData(t *testing.T) {
	// This test does not need DB; send malformed JSON or missing required fields to ensure handler returns 400
	ginRouter := setupRouter()
	unitID := addUnit(t)

	// malformed JSON
	req := httptest.NewRequest("POST", "/ingest/dump-dpi-stats", bytes.NewBufferString("{notjson"))
	req.SetBasicAuth(unitID, "1234")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ginRouter.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code, "malformed JSON should return 400")
}

func TestIngestUnauthorized(t *testing.T) {
	// wrong credentials should be unauthorized
	ginRouter := setupRouter()
	unitID := addUnit(t)

	req := httptest.NewRequest("POST", "/ingest/dump-wan-config", bytes.NewBufferString(`{"data":[]}`))
	req.SetBasicAuth(unitID, "wrongtoken")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ginRouter.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "wrong basic auth should return 401")
}

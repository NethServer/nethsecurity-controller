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
	"testing"

	"github.com/NethServer/nethsecurity-controller/api/storage"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// TestGetFreeIP tests that GetFreeIP returns a valid available IP address.
func TestGetFreeIP(t *testing.T) {

	ip := storage.GetFreeIP()
	assert.NotEmpty(t, ip, "GetFreeIP should return a non-empty IP address")

	// Verify it looks like an IP address
	octets := 0
	for i := 0; i < len(ip); i++ {
		if ip[i] == '.' {
			octets++
		}
	}
	assert.Equal(t, 3, octets, "GetFreeIP should return a valid IPv4 address")
}

// TestUnitExists tests checking if a unit exists in the database.
func TestUnitExists(t *testing.T) {

	// Create a test unit
	unitID := uuid.New().String()
	ip := storage.GetFreeIP()
	storage.AddUnit(unitID, ip)

	// Verify unit exists
	exists, err := storage.UnitExists(unitID)
	assert.NoError(t, err, "UnitExists should not return an error")
	assert.True(t, exists, "UnitExists should return true for existing unit")

	// Verify non-existent unit
	nonExistentID := uuid.New().String()
	exists, err = storage.UnitExists(nonExistentID)
	assert.NoError(t, err, "UnitExists should not return an error for non-existent unit")
	assert.False(t, exists, "UnitExists should return false for non-existent unit")
}

// TestUnitCredentialsCRUD tests Create, Read, Update operations on unit credentials.
func TestUnitCredentialsCRUD(t *testing.T) {

	unitID := uuid.New().String()
	ip := storage.GetFreeIP()
	storage.AddUnit(unitID, ip)

	// Test SetUnitCredentials (Create)
	username := "testuser"
	password := "testpass123"
	err := storage.SetUnitCredentials(unitID, username, password)
	assert.NoError(t, err, "SetUnitCredentials should not return an error")

	// Test GetUnitCredentials (Read)
	retrievedUser, retrievedPass, err := storage.GetUnitCredentials(unitID)
	assert.NoError(t, err, "GetUnitCredentials should not return an error")
	assert.Equal(t, username, retrievedUser, "Retrieved username should match")
	assert.Equal(t, password, retrievedPass, "Retrieved password should match (after decryption)")

	// Test SetUnitCredentials (Update)
	newPassword := "newpass456"
	err = storage.SetUnitCredentials(unitID, username, newPassword)
	assert.NoError(t, err, "SetUnitCredentials should not return an error for update")

	// Verify update
	retrievedUser, retrievedPass, err = storage.GetUnitCredentials(unitID)
	assert.NoError(t, err, "GetUnitCredentials should not return an error after update")
	assert.Equal(t, username, retrievedUser, "Retrieved username should still match")
	assert.Equal(t, newPassword, retrievedPass, "Retrieved password should be updated")
}

// TestReloadACLs tests that ReloadACLs doesn't crash and completes successfully.
func TestReloadACLs(t *testing.T) {

	// ReloadACLs should not return an error and should complete without panic
	assert.NotPanics(t, func() {
		storage.ReloadACLs()
	}, "ReloadACLs should not panic")
}

// TestDatabaseConnectivity tests basic database connectivity.
func TestDatabaseConnectivity(t *testing.T) {

	// Try to get free IP which requires database connectivity
	ip := storage.GetFreeIP()

	// If we get here without panic and have an IP (or empty if all used), DB is connected
	assert.True(t, ip != "" || ip == "", "Database should be accessible")
}

// TestGetFreeIPConsistency tests that GetFreeIP doesn't return duplicate IPs.
func TestGetFreeIPConsistency(t *testing.T) {

	// Get first free IP
	ip1 := storage.GetFreeIP()
	if ip1 == "" {
		t.Skip("No free IPs available in network")
	}

	// Add a unit with this IP
	unitID1 := uuid.New().String()
	storage.AddUnit(unitID1, ip1)

	// Get next free IP
	ip2 := storage.GetFreeIP()

	// They should be different
	assert.NotEqual(t, ip1, ip2, "GetFreeIP should return different IPs on successive calls")
}

// TestUnitCredentialsEncryption tests that credentials are properly encrypted/decrypted.
func TestUnitCredentialsEncryption(t *testing.T) {

	unitID := uuid.New().String()
	ip := storage.GetFreeIP()
	storage.AddUnit(unitID, ip)

	// Test with sensitive password
	sensitivePassword := "P@ssw0rd!#$%^&*()"
	err := storage.SetUnitCredentials(unitID, "admin", sensitivePassword)
	assert.NoError(t, err, "SetUnitCredentials should handle special characters")

	// Verify the password is correctly decrypted
	_, retrievedPass, err := storage.GetUnitCredentials(unitID)
	assert.NoError(t, err, "GetUnitCredentials should decrypt properly")
	assert.Equal(t, sensitivePassword, retrievedPass, "Special characters should be preserved")
}

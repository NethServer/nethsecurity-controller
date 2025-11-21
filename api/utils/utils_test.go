/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Giacomo Sanchietti <giacomo.sanchietti@nethesis.it>
 */

package utils

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/stretchr/testify/assert"
) // TestAESGCMEncryption tests AES-GCM encryption and decryption.
func TestAESGCMEncryption(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	assert.NoError(t, err)

	plaintext := []byte("Hello, AES-GCM encryption!")
	ciphertext, err := EncryptAESGCM(plaintext, key)
	assert.NoError(t, err)
	assert.NotNil(t, ciphertext)
	assert.False(t, bytes.Equal(ciphertext, plaintext))

	decrypted, err := DecryptAESGCM(ciphertext, key)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	wrongKey := make([]byte, 32)
	_, err = rand.Read(wrongKey)
	assert.NoError(t, err)
	_, err = DecryptAESGCM(ciphertext, wrongKey)
	assert.Error(t, err)
}

// TestAESGCMToString tests base64 string conversion helpers.
func TestAESGCMToString(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	assert.NoError(t, err)

	plaintext := []byte("Store this in DB as base64!")
	ciphertextB64, err := EncryptAESGCMToString(plaintext, key)
	assert.NoError(t, err)
	assert.NotEmpty(t, ciphertextB64)

	decrypted, err := DecryptAESGCMFromString(ciphertextB64, key)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	wrongKey := []byte("abcdefghabcdefghabcdefghabcdefgh")
	_, err = DecryptAESGCMFromString(ciphertextB64, wrongKey)
	assert.Error(t, err)

	_, err = DecryptAESGCMFromString("not-valid-base64!!!", key)
	assert.Error(t, err)
}

// TestPasswordHashing tests password hashing security.
func TestPasswordHashing(t *testing.T) {
	password := "TestPassword123!"
	hash1 := HashPassword(password)
	hash2 := HashPassword(password)

	assert.NotEqual(t, hash1, hash2)
	assert.True(t, CheckPasswordHash(password, hash1))
	assert.True(t, CheckPasswordHash(password, hash2))

	wrongPassword := "WrongPassword123!"
	assert.False(t, CheckPasswordHash(wrongPassword, hash1))
	assert.False(t, CheckPasswordHash(wrongPassword, hash2))
}

// TestToCIDR tests IP/netmask to CIDR conversion.
func TestToCIDR(t *testing.T) {
	testCases := []struct {
		name    string
		ip      string
		mask    string
		want    string
		isValid bool
	}{
		{"C/24", "192.168.1.10", "255.255.255.0", "192.168.1.10/24", true},
		{"B/16", "172.16.5.4", "255.255.0.0", "172.16.5.4/16", true},
		{"Single/32", "192.168.1.10", "255.255.255.255", "192.168.1.10/32", true},
		{"BadMask", "192.168.1.10", "255.255.0", "", false},
		{"BadIP", "notanip", "255.255.255.0", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := ToCIDR(tc.ip, tc.mask)
			if tc.isValid {
				assert.Equal(t, tc.want, got)
			} else {
				assert.Equal(t, "", got)
			}
		})
	}
}

// TestToIpMask tests CIDR to IP/netmask conversion.
func TestToIpMask(t *testing.T) {
	testCases := []struct {
		name    string
		cidr    string
		wantIP  string
		wantNet string
		isValid bool
	}{
		{"C/24", "192.168.1.10/24", "192.168.1.10", "255.255.255.0", true},
		{"B/16", "172.16.5.4/16", "172.16.5.4", "255.255.0.0", true},
		{"Single/32", "10.0.0.1/32", "10.0.0.1", "255.255.255.255", true},
		{"BadPrefix", "192.168.1.10/33", "", "", false},
		{"BadIP", "notanip/24", "", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ip, mask := ToIpMask(tc.cidr)
			if tc.isValid {
				assert.Equal(t, tc.wantIP, ip)
				assert.Equal(t, tc.wantNet, mask)
			} else {
				assert.Equal(t, "", ip)
				assert.Equal(t, "", mask)
			}
		})
	}
}

// TestListIPs tests ListIPs with various network sizes.
func TestListIPs(t *testing.T) {
	testCases := []struct {
		name     string
		ip       string
		netmask  string
		minCount int
	}{
		{"30", "192.168.1.0", "255.255.255.252", 2},
		{"28", "192.168.1.0", "255.255.255.240", 14},
		{"29", "10.0.0.0", "255.255.255.248", 6}, // Smaller than /24 to avoid large allocations
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ips, err := ListIPs(tc.ip, tc.netmask)
			assert.NoError(t, err)
			assert.GreaterOrEqual(t, len(ips), tc.minCount)

			for _, ip := range ips {
				assert.NotEmpty(t, ip)
				octets := 0
				for i := 0; i < len(ip); i++ {
					if ip[i] == '.' {
						octets++
					}
				}
				assert.Equal(t, 3, octets)
			}
		})
	}
}

// TestListIPsEdgeCases tests edge cases for ListIPs.
func TestListIPsEdgeCases(t *testing.T) {
	testCases := []struct {
		name    string
		ip      string
		netmask string
		want    int
	}{
		{"32", "192.168.1.1", "255.255.255.255", 1},
		{"31", "192.168.1.0", "255.255.255.254", 0},
		{"30", "192.168.1.0", "255.255.255.252", 2},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ips, err := ListIPs(tc.ip, tc.netmask)
			assert.NoError(t, err)
			assert.Equal(t, tc.want, len(ips))
		})
	}
}

// TestContains tests the Contains helper.
func TestContains(t *testing.T) {
	testCases := []struct {
		name   string
		val    string
		slice  []string
		expect bool
	}{
		{"Start", "apple", []string{"apple", "banana", "cherry"}, true},
		{"Middle", "banana", []string{"apple", "banana", "cherry"}, true},
		{"End", "cherry", []string{"apple", "banana", "cherry"}, true},
		{"NotFound", "grape", []string{"apple", "banana", "cherry"}, false},
		{"Empty", "apple", []string{}, false},
		{"EmptyStr", "", []string{"apple", "banana"}, false},
		{"PartialMatch", "app", []string{"apple"}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := Contains(tc.val, tc.slice)
			assert.Equal(t, tc.expect, got)
		})
	}
}

// TestRemove tests the Remove helper.
func TestRemove(t *testing.T) {
	testCases := []struct {
		name    string
		val     string
		slice   []string
		wantLen int
	}{
		{"Middle", "banana", []string{"apple", "banana", "cherry"}, 2},
		{"Start", "apple", []string{"apple", "banana", "cherry"}, 2},
		{"End", "cherry", []string{"apple", "banana", "cherry"}, 2},
		{"NotFound", "grape", []string{"apple", "banana", "cherry"}, 3},
		{"Single", "apple", []string{"apple"}, 0},
		{"Empty", "apple", []string{}, 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := Remove(tc.val, tc.slice)
			assert.Equal(t, tc.wantLen, len(got))
		})
	}
}

// TestIncViaListIPs tests the inc() function behavior indirectly via ListIPs.
func TestIncViaListIPs(t *testing.T) {
	ips, err := ListIPs("192.168.1.0", "255.255.255.252")
	assert.NoError(t, err)
	assert.Len(t, ips, 2)
	assert.Equal(t, "192.168.1.1", ips[0])
	assert.Equal(t, "192.168.1.2", ips[1])
}

// TestGetJoinCode tests GetJoinCode function.
func TestGetJoinCode(t *testing.T) {
	// Set up config
	originalToken := configuration.Config.RegistrationToken
	originalFQDN := configuration.Config.FQDN
	defer func() {
		configuration.Config.RegistrationToken = originalToken
		configuration.Config.FQDN = originalFQDN
	}()

	configuration.Config.RegistrationToken = "test-token"
	configuration.Config.FQDN = "test.example.com"

	unitId := "unit-123"
	joinCode := GetJoinCode(unitId)

	assert.NotEmpty(t, joinCode)

	// Decode and verify
	decoded, err := base64.StdEncoding.DecodeString(joinCode)
	assert.NoError(t, err)

	var data map[string]interface{}
	err = json.Unmarshal(decoded, &data)
	assert.NoError(t, err)

	assert.Equal(t, unitId, data["unit_id"])
	assert.Equal(t, "test-token", data["token"])
	assert.Equal(t, "test.example.com", data["fqdn"])
}

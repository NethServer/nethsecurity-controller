/*
 * Copyright (C) 2024 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Edoardo Spadoni <edoardo.spadoni@nethesis.it>
 */

package utils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func Contains(a string, values []string) bool {
	for _, b := range values {
		if b == a {
			return true
		}
	}
	return false
}

func GetFreeIP(ip string, netmask string, usedIPs []string) string {
	// get all ips
	IPs, _ := ListIPs(ip, netmask)

	// remove first ip used for tun
	IPs = IPs[1:]

	// loop all IPs
	for _, ip := range IPs {
		if !Contains(ip, usedIPs) {
			return ip
		}
	}

	return ""
}

func ListIPs(ipArg string, netmaskArg string) ([]string, error) {
	// convert netmask to prefix
	prefixMask, _ := net.IPMask(net.ParseIP(netmaskArg).To4()).Size()

	// create network
	ip, ipnet, err := net.ParseCIDR(ipArg + "/" + strconv.Itoa(prefixMask))
	if err != nil {
		return nil, err
	}

	// loop all ips in network
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// remove network address and broadcast address
	lenIPs := len(ips)
	switch {
	case lenIPs < 2:
		return ips, nil

	default:
		return ips[1 : len(ips)-1], nil
	}
}

func HashPassword(password string) string {
	bytes, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes)
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// generate join code
// the join code is a JSON encoded in base64 with the following fields:
// - unit_id
// - registration token
// - fqdn
func GetJoinCode(unitId string) string {
	// compose join code
	joinCode := gin.H{
		"unit_id": unitId,
		"token":   configuration.Config.RegistrationToken,
		"fqdn":    configuration.Config.FQDN,
	}

	// encode in base64
	joinCodeString, _ := json.Marshal(joinCode)
	return base64.StdEncoding.EncodeToString([]byte(joinCodeString))
}

func Remove(a string, values []string) []string {
	for i, v := range values {
		if v == a {
			return append(values[:i], values[i+1:]...)
		}
	}
	return values
}

// EncryptAESGCM encrypts plaintext using AES-GCM with the provided key.
func EncryptAESGCM(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// EncryptAESGCMToString encrypts plaintext and returns a base64 string for DB storage.
func EncryptAESGCMToString(plaintext, key []byte) (string, error) {
	ciphertext, err := EncryptAESGCM(plaintext, key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptAESGCMFromString decodes base64 string and decrypts using AES-GCM.
func DecryptAESGCMFromString(ciphertextB64 string, key []byte) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, err
	}
	plaintext, err := DecryptAESGCM(ciphertext, key)
	if err == nil {
		return plaintext, nil
	}
	return []byte(""), err
}

// DecryptAESGCM decrypts ciphertext using AES-GCM with the provided key.
func DecryptAESGCM(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, io.ErrUnexpectedEOF
	}
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// ToCIDR converts an IPv4 address and a netmask string into CIDR notation.
// It returns an empty string if the input IP or mask is invalid.
// For example, given "192.168.0.1" and "255.255.255.0", it returns "192.168.0.1/24".
func ToCIDR(ipStr, maskStr string) string {
	// Parse the IP address string.
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	// The function works with IPv4 addresses, so we ensure it's a 4-byte representation.
	ipv4 := ip.To4()
	if ipv4 == nil {
		return ""
	}
	// Parse the netmask string as an IP address.
	maskIP := net.ParseIP(maskStr)
	if maskIP == nil {
		return ""
	}
	// Convert the parsed netmask IP to a 4-byte representation.
	maskIPv4 := maskIP.To4()
	if maskIPv4 == nil {
		return ""
	}
	// Create an IPMask type from the 4-byte mask.
	mask := net.IPMask(maskIPv4)
	// Get the prefix size (the number of leading '1's in the mask).
	// The second return value is the total number of bits, which is always 32 for IPv4.
	prefixSize, _ := mask.Size()
	return fmt.Sprintf("%s/%d", ipStr, prefixSize)
}

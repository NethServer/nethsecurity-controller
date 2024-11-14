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
	"net"
	"os"
	"strconv"
	"strings"

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

func GetUserStatus(username string) (string, error) {
	status, err := os.ReadFile(configuration.Config.SecretsDir + "/" + username + "/status")
	statusS := strings.TrimSpace(string(status[:]))

	return statusS, err
}

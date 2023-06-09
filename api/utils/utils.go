/*
 * Copyright (C) 2023 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Edoardo Spadoni <edoardo.spadoni@nethesis.it>
 */

package utils

import (
	"net"
	"strconv"
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

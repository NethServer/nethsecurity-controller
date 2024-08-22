/*
 * Copyright (C) 2024 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Giacomo Sanchietti <giacomo.sanchietti@nethesis.it>
 */

package utils

import (
	"log"
	"net"

	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/NethServer/nethsecurity-controller/api/logs"
	"github.com/oschwald/geoip2-golang"
)

var db *geoip2.Reader

func InitGeoIP() error {
	var err error
	// open geoip db, path from config, name is always the same: GeoLite2-Country.mmdb
	db, err = geoip2.Open(configuration.Config.GeoIPDbDir + "/GeoLite2-Country.mmdb")

	if err != nil {
		logs.Logs.Println("[ERR][GEOIP] error reading geoip db file :" + err.Error())
		return err
	} else {
		logs.Logs.Println("[INFO][GEOIP] geoip db file loaded")
	}

	return nil
}

func GetCountryShort(ip string) string {
	if ip == "" || db == nil {
		return ""
	}

	// If you are using strings that may be invalid, check that ip is not nil
	record, err := db.City(net.ParseIP(ip))
	if err != nil {
		log.Fatal(err)
	}

	return record.Country.IsoCode
}

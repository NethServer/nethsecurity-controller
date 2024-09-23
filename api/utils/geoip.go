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
	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/NethServer/nethsecurity-controller/api/logs"
	"github.com/oschwald/geoip2-golang"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

var db *geoip2.Reader

func InitGeoIP() error {
	// try to download the GeoLite2-Country.mmdb file
	err := DownloadGeoIpDatabase()
	if err != nil {
		logs.Logs.Println("[ERR][GEOIP] error downloading geoip db file")
		return err
	}
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

func DownloadGeoIpDatabase() error {
	databaseFile, err := os.Stat(configuration.Config.GeoIPDbDir + "/GeoLite2-Country.mmdb")
	if err == nil && time.Since(databaseFile.ModTime()).Hours() < 72 {
		logs.Logs.Println("[INFO][GEOIP] geoip db file is up to date")
		return nil
	}
	cmd := exec.Command(
		"curl",
		"-L",
		"--fail",
		"--silent",
		"--show-error",
		"--retry", "5",
		"--retry-max-time", "120",
		"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key="+configuration.Config.MaxmindLicense+"&suffix=tar.gz",
		"-o", configuration.Config.GeoIPDbDir+"/GeoLite2-Country.tar.gz",
	)
	var out strings.Builder
	cmd.Stderr = &out
	err = cmd.Run()
	if err != nil {
		logs.Logs.Println("[ERR][GEOIP] error downloading geoip db file: " + out.String())
		return err
	}
	cmd = exec.Command(
		"tar",
		"xzf",
		configuration.Config.GeoIPDbDir+"/GeoLite2-Country.tar.gz",
		"--strip-components=1",
	)
	cmd.Stderr = &out
	err = cmd.Run()
	if err != nil {
		logs.Logs.Println("[ERR][GEOIP] error extracting geoip db file: " + out.String())
		return err
	}

	return nil
}

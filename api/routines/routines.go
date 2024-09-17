/*
 * Copyright (C) 2024 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Edoardo Spadoni <edoardo.spadoni@nethesis.it>
 */

package routines

import (
	"github.com/NethServer/nethsecurity-controller/api/utils"
	"time"

	"github.com/NethServer/nethsecurity-controller/api/logs"
	"github.com/NethServer/nethsecurity-controller/api/methods"
)

func RefreshRemoteInfoLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
		// load all units info into cache
		units, err := methods.ListConnectedUnits()
		if err != nil {
			return
		}

		for _, unit := range units {
			_, err := methods.GetRemoteInfo(unit)
			if err != nil {
				logs.Logs.Println("[ERR][ROUTINE] loop for remote info failed: " + err.Error())
			}
		}
	}
}

func RefreshGeoIPDatabase() {
	ticker := time.NewTicker(24 * time.Hour)
	for range ticker.C {
		err := utils.InitGeoIP()
		if err != nil {
			logs.Logs.Println("[ERR][ROUTINE] loop for geoip database failed: " + err.Error())
		}
	}
}

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
	"time"

	"github.com/NethServer/nethsecurity-controller/api/logs"
	"github.com/NethServer/nethsecurity-controller/api/methods"
)

func RefreshRemoteInfoLoop() {
	// TODO change
	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		// load all units info into cache
		units, err := methods.ListUnits()
		if err != nil {
			return
		}

		for _, unit := range units {
			err := methods.GetRemoteInfo(unit)
			if err != nil {
				logs.Logs.Println("[ERR][ROUTINE] loop for remote info failed: " + err.Error())
			}
		}
	}
}

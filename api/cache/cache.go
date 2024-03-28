/*
 * Copyright (C) 2024 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Giacomo Sanchietti <giacomo.sanchietti@nethesis.it>
 */

package cache

import (
	"strconv"
	"time"

	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/jellydator/ttlcache/v3"
)

var Cache *ttlcache.Cache[string, string]

func Init() {
	value, err := strconv.Atoi(configuration.Config.CacheTTL)
	if err != nil {
		value = 3600
	}

	Cache = ttlcache.New[string, string](
		ttlcache.WithTTL[string, string](time.Duration(value) * time.Second),
	)
	go Cache.Start() // starts automatic expired item deletion
}

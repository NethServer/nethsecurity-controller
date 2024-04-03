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
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/NethServer/nethsecurity-controller/api/models"
	"github.com/jellydator/ttlcache/v3"
)

var Cache *ttlcache.Cache[string, string]

func Init() {
	value, err := strconv.Atoi(configuration.Config.CacheTTL)
	if err != nil {
		value = 3600
	}

	Cache = ttlcache.New(
		ttlcache.WithTTL[string, string](time.Duration(value) * time.Second),
	)
	go Cache.Start() // starts automatic expired item deletion
}

func SetUnitInfo(unitId string, unitInfo models.UnitInfo) {
	value, err := strconv.Atoi(configuration.Config.CacheTTL)
	if err != nil {
		value = 60
	}
	b, err := json.Marshal(unitInfo)
	if err == nil {
		Cache.Set(unitId, string(b), time.Duration(value)*time.Second)
	}
}

func GetUnitInfo(unitId string) (models.UnitInfo, error) {
	if Cache.Has(unitId) {
		data := models.UnitInfo{}
		item := Cache.Get(unitId)
		json.Unmarshal([]byte(item.Value()), &data)
		return data, nil
	} else {
		return models.UnitInfo{}, errors.New("unit info not found in cache")
	}
}

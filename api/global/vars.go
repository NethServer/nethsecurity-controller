/*
 * Copyright (C) 2024 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Edoardo Spadoni <edoardo.spadoni@nethesis.it>
 */

package global

import (
	"github.com/gin-gonic/gin"
)

var WaitingList map[string]gin.H

func Init() {
	// init global var
	WaitingList = make(map[string]gin.H)
}

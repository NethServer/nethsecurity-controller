/*
 * Copyright (C) 2024 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Edoardo Spadoni <edoardo.spadoni@nethesis.it>
 */

package socket

import (
	"testing"

	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/NethServer/nethsecurity-controller/api/logs"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	logs.Init("test")
	// Set config
	configuration.Config.OpenVPNMGMTSock = "/tmp/nonexistent.sock"
	m.Run()
}

func TestInit(t *testing.T) {
	// Test that Init doesn't panic even if socket doesn't exist
	assert.NotPanics(t, func() {
		Init()
	})
	// Socket should be nil since connection fails
	assert.Nil(t, Socket)
}

func TestWrite(t *testing.T) {
	// Test Write when Socket is nil
	result := Write("test")
	assert.Equal(t, "", result)
}

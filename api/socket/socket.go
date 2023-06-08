/*
 * Copyright (C) 2023 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Edoardo Spadoni <edoardo.spadoni@nethesis.it>
 */

package socket

import (
	"net"

	"github.com/NethServer/nethsecurity-api/logs"
	"github.com/NethServer/nethsecurity-controller/api/configuration"
)

var Socket net.Conn

func Init() {
	//establish connection
	connection, err := net.Dial("unix", configuration.Config.OpenVPNMGMTSock)

	// check error
	if err != nil {
		logs.Logs.Err("[ERR][OPENVPN SOCKET] can't connect to openvpn socket: " + configuration.Config.OpenVPNMGMTSock)
	}

	// assign object
	Socket = connection
}

func Write(message string) string {
	// compose message
	_, err := Socket.Write([]byte(message + "\n"))

	// check write error
	if err != nil {
		logs.Logs.Err("[ERR][OPENVPN SOCKET] can't write to openvpn socket: " + configuration.Config.OpenVPNMGMTSock + ". error: " + err.Error())
	}

	// compose buffer
	buffer := make([]byte, 4096)
	bLen, err := Socket.Read(buffer)

	// check read error
	if err != nil {
		logs.Logs.Err("[ERR][OPENVPN SOCKET] can't read from openvpn socket: " + configuration.Config.OpenVPNMGMTSock + ". error: " + err.Error())
	}

	// return string
	return string(buffer[:bLen])
}

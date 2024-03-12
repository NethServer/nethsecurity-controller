/*
 * Copyright (C) 2024 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Edoardo Spadoni <edoardo.spadoni@nethesis.it>
 */

package methods

import (
	"io/ioutil"
	"os"
	"strings"

	"github.com/NethServer/nethsecurity-controller/api/configuration"
)

func CheckTokenValidation(username string, token string) bool {
	// read whole file
	secrestListB, err := ioutil.ReadFile(configuration.Config.TokensDir + "/" + username)
	if err != nil {
		return false
	}
	secrestList := string(secrestListB)

	// //check whether s contains substring text
	return strings.Contains(secrestList, token)
}

func SetTokenValidation(username string, token string) bool {
	// open file
	f, _ := os.OpenFile(configuration.Config.TokensDir+"/"+username, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	defer f.Close()

	// write file with tokens
	_, err := f.WriteString(token + "\n")

	// check error
	if err != nil {
		return false
	}

	return true
}

func DelTokenValidation(username string, token string) bool {
	// read whole file
	secrestListB, errR := ioutil.ReadFile(configuration.Config.TokensDir + "/" + username)
	if errR != nil {
		return false
	}
	secrestList := string(secrestListB)

	// match token to remove
	res := strings.Replace(secrestList, token, "", 1)

	// open file
	f, _ := os.OpenFile(configuration.Config.TokensDir+"/"+username, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	defer f.Close()

	// write file with tokens
	_, err := f.WriteString(strings.TrimSpace(res) + "\n")

	// check error
	if err != nil {
		return false
	}

	return true

}

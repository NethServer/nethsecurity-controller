/*
 * Copyright (C) 2024 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Edoardo Spadoni <edoardo.spadoni@nethesis.it>
 */

package storage

import (
	"database/sql"
	_ "embed"
	"os"
	"time"

	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/NethServer/nethsecurity-controller/api/logs"
	"github.com/NethServer/nethsecurity-controller/api/models"
	"github.com/NethServer/nethsecurity-controller/api/utils"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB
var err error

//go:embed schema.sql
var schemaSQL string

func Instance() *sql.DB {
	if db == nil {
		db = Init()
	}
	return db
}

func Init() *sql.DB {
	// check if file exists
	initSchema := false
	if _, err := os.Stat(configuration.Config.DataDir + "/db.sqlite"); os.IsNotExist(err) {
		initSchema = true
	}

	// try connection
	db, err = sql.Open("sqlite3", configuration.Config.DataDir+"/db.sqlite")
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE] error in storage db file creation:" + err.Error())
		os.Exit(1)
	}

	// check connectivity
	err = db.Ping()
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE] error in storage db connection:" + err.Error())
		os.Exit(1)
	}

	// init schema if true
	if initSchema {
		// execute create tables
		_, errExecute := db.Exec(schemaSQL)
		if errExecute != nil {
			logs.Logs.Println("[ERR][STORAGE] error in storage file schema init:" + errExecute.Error())
		}
	}

	// check if user admin exists
	results, _ := GetAccount(configuration.Config.AdminUsername)
	exists := len(results) > 0

	// add admin account, if not exists
	if !exists {
		// define admin account
		admin := models.Account{
			ID:          1,
			Username:    configuration.Config.AdminUsername,
			Password:    configuration.Config.AdminPassword,
			DisplayName: "Super Admin user",
			Created:     time.Now(),
		}

		// add admin account
		_ = AddAccount(admin)
	}

	return db
}

func AddAccount(account models.Account) error {
	// get db
	db := Instance()

	// hash account password
	password := utils.HashPassword(account.Password)

	// admin password is already hashed
	if account.ID == 1 {
		password = account.Password
	}

	// define query
	_, err := db.Exec(
		"INSERT INTO accounts (id, username, password, display_name, created) VALUES (null, ?, ?, ?, ?)",
		account.Username,
		password,
		account.DisplayName,
		account.Created.Format(time.RFC3339),
	)

	// check error
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][ADD_ACCOUNT] error in insert accounts query: " + err.Error())
	}

	return err
}

func UpdateAccount(accountID string, account models.AccountUpdate) error {
	// get db
	db := Instance()

	// define error
	var err error

	// check props
	if len(account.Password) > 0 {
		// define and execute query
		query := "UPDATE accounts set password = ? WHERE id = ?"
		_, err = db.Exec(
			query,
			utils.HashPassword(account.Password),
			accountID,
		)
	}
	if len(account.DisplayName) > 0 {
		// define and execute query
		query := "UPDATE accounts set display_name = ? WHERE id = ?"
		_, err = db.Exec(
			query,
			account.DisplayName,
			accountID,
		)
	}

	// check error
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][UPDATE_ACCOUNT] error in insert accounts query: " + err.Error())
	}

	return err
}

func IsAdmin(accountUsername string) (bool, string) {
	// get db
	db := Instance()

	// define query
	var id string
	query := "SELECT id FROM accounts where username = ? LIMIT 1"
	err := db.QueryRow(query, accountUsername).Scan(&id)

	// check error
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][GET_PASSWORD] error in query execution:" + err.Error())
	}

	// check if user is admin or other user
	return id == "1", id
}

func GetAccounts() ([]models.Account, error) {
	// get db
	db := Instance()

	// define query
	query := "SELECT id, username, display_name, created FROM accounts"
	rows, err := db.Query(query)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][GET_ACCOUNTS] error in query execution:" + err.Error())
	}
	defer rows.Close()

	// loop rows
	var results []models.Account
	for rows.Next() {
		var accountRow models.Account
		if err := rows.Scan(&accountRow.ID, &accountRow.Username, &accountRow.DisplayName, &accountRow.Created); err != nil {
			logs.Logs.Println("[ERR][STORAGE][GET_ACCOUNTS] error in query row extraction" + err.Error())
		}

		// append results
		results = append(results, accountRow)
	}

	// return results
	return results, err
}

func GetAccount(accountID string) ([]models.Account, error) {
	// get db
	db := Instance()

	// define query
	query := "SELECT id, username, display_name, created FROM accounts where id = ?"
	rows, err := db.Query(query, accountID)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][GET_ACCOUNT] error in query execution:" + err.Error())
	}
	defer rows.Close()

	// loop rows
	var results []models.Account
	for rows.Next() {
		var accountRow models.Account
		if err := rows.Scan(&accountRow.ID, &accountRow.Username, &accountRow.DisplayName, &accountRow.Created); err != nil {
			logs.Logs.Println("[ERR][STORAGE][GET_ACCOUNT] error in query row extraction" + err.Error())
		}

		// append results
		results = append(results, accountRow)
	}

	// return results
	return results, err
}

func GetPassword(accountUsername string) string {
	// get db
	db := Instance()

	// define query
	var password string
	query := "SELECT password FROM accounts where username = ? LIMIT 1"
	err := db.QueryRow(query, accountUsername).Scan(&password)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][GET_PASSWORD] error in query execution:" + err.Error())
	}

	// return password
	return password
}

func DeleteAccount(accountID string) error {
	// get db
	db := Instance()

	// define query
	query := "DELETE FROM accounts where id = ?"
	_, err = db.Exec(query, accountID)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][DELETE_ACCOUNT] error in query execution:" + err.Error())
	}

	return err
}

func UpdatePassword(accountUsername string, newPassword string) error {
	// get db
	db := Instance()

	// define query
	query := "UPDATE accounts set password = ? WHERE username = ?"
	_, err = db.Exec(
		query,
		utils.HashPassword(newPassword),
		accountUsername,
	)

	return err
}

func AddOrUpdateUnit(unitID string, unitName string, version string, subscriptionType string, systemID string) error {
	// get db
	db := Instance()

	// define query
	_, err := db.Exec(
		"REPLACE INTO units (id, name, version, subscription_type, system_id) VALUES (?, ?, ?, ?, ?)",
		unitID,
		unitName,
		version,
		subscriptionType,
		systemID,
	)

	// check error
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][ADD_OR_UPDATE_UNIT] error in insert units query: " + err.Error())
	}

	return err
}

func GetUnit(unitId string) (models.Unit, error) {
	// get db
	db := Instance()

	// define query
	query := "SELECT id, name, version, subscription_type, system_id, created FROM units where id = ?"
	rows, err := db.Query(query, unitId)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][GET_UNIT] error in query execution:" + err.Error())
	}
	defer rows.Close()

	// loop rows
	var result models.Unit
	for rows.Next() {
		if err := rows.Scan(&result.ID, &result.Name, &result.Version, &result.SubscriptionType, &result.SystemID, &result.Created); err != nil {
			logs.Logs.Println("[ERR][STORAGE][GET_UNIT] error in query row extraction" + err.Error())
		}
	}

	// return results
	return result, err
}

func GetUnits() ([]models.Unit, error) {
	// get db
	db := Instance()

	// define query
	query := "SELECT id, name, version, subscription_type, system_id, created FROM units"
	rows, err := db.Query(query)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][GET_UNITS] error in query execution:" + err.Error())
	}
	defer rows.Close()

	// loop rows
	var results []models.Unit
	for rows.Next() {
		var unitRow models.Unit
		if err := rows.Scan(&unitRow.ID, &unitRow.Name, &unitRow.Version, &unitRow.SubscriptionType, &unitRow.SystemID, &unitRow.Created); err != nil {
			logs.Logs.Println("[ERR][STORAGE][GET_UNITS] error in query row extraction" + err.Error())
		}

		// append results
		results = append(results, unitRow)
	}

	// return results
	return results, err
}

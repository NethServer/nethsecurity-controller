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
	if _, err := os.Stat(configuration.Config.StorageFile); os.IsNotExist(err) {
		initSchema = true
	}

	// try connection
	db, err = sql.Open("sqlite3", configuration.Config.StorageFile)
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

		// define default user
		defaultUser := models.Account{
			Username:    configuration.Config.AdminUsername,
			Password:    configuration.Config.AdminPassword,
			DisplayName: "Default User",
			Locked:      true,
			Created:     time.Now(),
		}

		// insert default user
		_ = AddAccount(defaultUser)
	}

	return db
}

func AddAccount(account models.Account) error {
	// get db
	db := Instance()

	// define query
	_, err := db.Exec(
		"INSERT INTO accounts (id, username, password, display_name, locked, created) VALUES (null, ?, ?, ?, ?, ?)",
		account.Username,
		utils.HashPassword(account.Password),
		account.DisplayName,
		account.Locked,
		account.Created.Format(time.RFC3339),
	)

	// check error
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][ADD ACCOUNT] error in insert accounts query: " + err.Error())
	}

	return err
}

func UpdateAccount(account models.Account) error {
	// get db
	db := Instance()

	// define query
	_, err := db.Exec(
		"UPDATE accounts set password = ?, display_name = ? WHERE id = ?",
		utils.HashPassword(account.Password),
		account.DisplayName,
		account.ID,
	)

	// check error
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][UPDATE ACCOUNT] error in insert accounts query: " + err.Error())
	}

	return err
}

func GetAccounts() ([]models.Account, error) {
	// get db
	db := Instance()

	// define query
	query := "SELECT id, username, display_name, locked, created FROM accounts"
	rows, err := db.Query(query)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][GET ACCOUNTS] error in query execution:" + err.Error())
	}
	defer rows.Close()

	// loop rows
	var results []models.Account
	for rows.Next() {
		var accountRow models.Account
		if err := rows.Scan(&accountRow.ID, &accountRow.Username, &accountRow.DisplayName, &accountRow.Locked, &accountRow.Created); err != nil {
			logs.Logs.Panicln("[ERR][STORAGE][GET ACCOUNTS] error in query row extraction" + err.Error())
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
	query := "SELECT id, username, display_name, locked, created FROM accounts where id = ?"
	rows, err := db.Query(query, accountID)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][GET ACCOUNT] error in query execution:" + err.Error())
	}
	defer rows.Close()

	// loop rows
	var results []models.Account
	for rows.Next() {
		var accountRow models.Account
		if err := rows.Scan(&accountRow.ID, &accountRow.Username, &accountRow.DisplayName, &accountRow.Locked, &accountRow.Created); err != nil {
			logs.Logs.Panicln("[ERR][STORAGE][GET ACCOUNT] error in query row extraction" + err.Error())
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
		logs.Logs.Println("[ERR][STORAGE][GET PASSWORD] error in query execution:" + err.Error())
	}

	// return password
	return password
}

func DeleteAccount(accountID string) error {
	// get db
	db := Instance()

	// define query
	query := "DELETE FROM accounts where id = ? AND locked == 0"
	_, err = db.Exec(query, accountID)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][DELETE ACCOUNT] error in query execution:" + err.Error())
	}

	return err
}

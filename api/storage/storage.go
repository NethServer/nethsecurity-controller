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
	"bytes"
	"context"
	"database/sql"
	_ "embed"
	"github.com/NethServer/nethsecurity-controller/api/methods"
	"html/template"
	"os"
	"time"

	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/NethServer/nethsecurity-controller/api/logs"
	"github.com/NethServer/nethsecurity-controller/api/models"
	"github.com/NethServer/nethsecurity-controller/api/utils"
	"github.com/jackc/pgx/v5/pgxpool"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB
var dbpool *pgxpool.Pool
var dbctx context.Context
var err error

//go:embed schema.sql
var schemaSQL string

//go:embed report_schema.sql.tmpl
var reportSchemaSQL string

//go:embed grafana_user.sql.tmpl
var grafanaUserSQL string

var reportDbIsInitialized = false

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
			DisplayName: "Administrator",
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

	// define query
	_, err := db.Exec(
		"INSERT INTO accounts (id, username, password, display_name, created) VALUES (null, ?, ?, ?, ?)",
		account.Username,
		utils.HashPassword(account.Password),
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

		accountStatus, err := methods.GetUserStatus(accountRow.Username)
		if err != nil {
			logs.Logs.Println("[ERR][STORAGE][GET_ACCOUNTS] error in query row extraction" + err.Error())
		}

		accountStatus

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

func loadReportSchema(*pgxpool.Pool, context.Context) bool {
	// execute create tables
	logs.Logs.Println("[INFO][STORAGE] creating report tables")
	reportTemplate, _ := template.New("report_schema").Parse(reportSchemaSQL)
	var executedReportTemplate bytes.Buffer
	errExecute := reportTemplate.Execute(&executedReportTemplate, configuration.Config)
	if errExecute != nil {
		logs.Logs.Println("[ERR][STORAGE] error in storage file schema init:" + errExecute.Error())
		return false
	}
	_, errExecute = dbpool.Exec(dbctx, executedReportTemplate.String())
	if errExecute != nil {
		logs.Logs.Println("[ERR][STORAGE] error in storage file schema init:" + errExecute.Error())
		return false
	}

	logs.Logs.Println("[INFO][STORAGE] creating grafana user")
	grafanaUserTemplate, _ := template.New("grafana_user").Parse(grafanaUserSQL)
	var executedGrafanaUserReport bytes.Buffer
	errExecute = grafanaUserTemplate.Execute(&executedGrafanaUserReport, configuration.Config)
	if errExecute != nil {
		logs.Logs.Println("[ERR][STORAGE] error in storage file schema init:" + errExecute.Error())
		return false
	}
	_, errExecute = dbpool.Exec(dbctx, executedGrafanaUserReport.String())
	if errExecute != nil {
		logs.Logs.Println("[ERR][STORAGE] error in storage file schema init:" + errExecute.Error())
		return false
	}
	return true
}

func InitReportDb() (*pgxpool.Pool, context.Context) {
	dbctx = context.Background()
	dbpool, err = pgxpool.New(dbctx, configuration.Config.ReportDbUri)
	if err != nil {
		logs.Logs.Println("[WARN][DB] error in db connection:" + err.Error())
	}

	err = dbpool.Ping(dbctx)
	if err != nil {
		logs.Logs.Println("[WARN][DB] error in db connection:" + err.Error())
	}

	reportDbIsInitialized = loadReportSchema(dbpool, dbctx)

	return dbpool, dbctx
}

func ReportInstance() (*pgxpool.Pool, context.Context) {
	if dbpool == nil {
		dbpool, dbctx = InitReportDb()

	}
	if !reportDbIsInitialized {
		// check if 'units' table exists, if not call initialization
		query := `SELECT EXISTS (
				SELECT FROM information_schema.tables
				WHERE  table_schema = 'schema_name'
				AND    table_name   = 'units'
			)`
		dbpool.QueryRow(dbctx, query).Scan(&reportDbIsInitialized)
		if !reportDbIsInitialized {
			reportDbIsInitialized = loadReportSchema(dbpool, dbctx)
		}
	}
	return dbpool, dbctx
}

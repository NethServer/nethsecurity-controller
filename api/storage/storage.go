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

var dbpool *pgxpool.Pool
var dbctx context.Context
var err error

//go:embed report_schema.sql.tmpl
var reportSchemaSQL string

//go:embed grafana_user.sql.tmpl
var grafanaUserSQL string

var reportDbIsInitialized = false

func Init() *pgxpool.Pool {
	// Initialize PostgreSQL connection and schema
	dbpool, dbctx = InitReportDb()

	// Migrate users from SQLite to Postgres if needed
	MigrateUsersFromSqliteToPostgres()

	// Initialize PostgreSQL connection
	dbctx = context.Background()
	dbpool, err = pgxpool.New(dbctx, configuration.Config.ReportDbUri)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE] error in Postgres db connection:" + err.Error())
		os.Exit(1)
	}

	err = dbpool.Ping(dbctx)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE] error in Postgres db ping:" + err.Error())
		os.Exit(1)
	}

	// Check if admin user exists
	var exists bool
	err = dbpool.QueryRow(dbctx, "SELECT EXISTS (SELECT 1 FROM accounts WHERE username = $1)", configuration.Config.AdminUsername).Scan(&exists)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE] error checking admin user: " + err.Error())
		os.Exit(1)
	}
	if !exists {
		admin := models.Account{
			Username:    configuration.Config.AdminUsername,
			Password:    configuration.Config.AdminPassword,
			DisplayName: "Administrator",
			Created:     time.Now(),
		}
		_ = AddAccount(admin)
	}

	return dbpool
}

// MigrateUsersFromSqliteToPostgres migrates users from SQLite to PostgreSQL if needed
func MigrateUsersFromSqliteToPostgres() {
	// 1. Check if SQLite DB exists
	sqlitePath := configuration.Config.DataDir + "/db.sqlite"
	if _, err := os.Stat(sqlitePath); os.IsNotExist(err) {
		return // No SQLite DB, nothing to migrate
	}

	// 2. Open SQLite DB
	sqliteDB, err := sql.Open("sqlite3", sqlitePath)
	if err != nil {
		logs.Logs.Println("[ERR][MIGRATION] cannot open SQLite DB: " + err.Error())
		return
	}
	defer sqliteDB.Close()

	// 3. Check if SQLite has users
	rows, err := sqliteDB.Query("SELECT id, username, password, display_name, created FROM accounts")
	if err != nil {
		logs.Logs.Println("[ERR][MIGRATION] cannot query SQLite accounts: " + err.Error())
		return
	}
	defer rows.Close()
	var users []models.Account
	for rows.Next() {
		var acc models.Account
		var createdStr string
		if err := rows.Scan(&acc.ID, &acc.Username, &acc.Password, &acc.DisplayName, &createdStr); err != nil {
			logs.Logs.Println("[ERR][MIGRATION] error scanning SQLite user: " + err.Error())
			continue
		}
		acc.Created, _ = time.Parse(time.RFC3339, createdStr)
		users = append(users, acc)
	}
	if len(users) == 0 {
		return // No users to migrate
	}

	// 4. Check if admin user exists in Postgres
	pgpool, pgctx := ReportInstance()
	var adminExists bool
	err = pgpool.QueryRow(pgctx, `SELECT EXISTS (SELECT 1 FROM accounts WHERE username = $1)`, configuration.Config.AdminUsername).Scan(&adminExists)
	if err != nil {
		logs.Logs.Println("[ERR][MIGRATION] error checking admin user in Postgres: " + err.Error())
		return
	}
	if adminExists {
		return // Admin user exists, nothing to do
	}

	// 5. Create accounts table in Postgres
	_, err = pgpool.Exec(pgctx, `CREATE TABLE IF NOT EXISTS accounts (
		id SERIAL PRIMARY KEY,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		display_name TEXT,
		created TIMESTAMP NOT NULL
	)`)
	if err != nil {
		logs.Logs.Println("[ERR][MIGRATION] error creating accounts table in Postgres: " + err.Error())
		return
	}

	// 6. Insert users into Postgres
	for _, acc := range users {
		_, err := pgpool.Exec(pgctx, `INSERT INTO accounts (username, password, display_name, created) VALUES ($1, $2, $3, $4) ON CONFLICT (username) DO NOTHING`,
			acc.Username, acc.Password, acc.DisplayName, acc.Created)
		if err != nil {
			logs.Logs.Println("[ERR][MIGRATION] error inserting user into Postgres: " + err.Error())
		}
	}
	logs.Logs.Println("[INFO][MIGRATION] migrated", len(users), "users from SQLite to Postgres")

	// 7. Rename SQLite DB to avoid future migrations
	err = os.Rename(sqlitePath, sqlitePath+".bak")
	if err != nil {
		logs.Logs.Println("[ERR][MIGRATION] error renaming SQLite DB: " + err.Error())
	}
}

// Refactored user functions to use PostgreSQL
func AddAccount(account models.Account) error {
	pgpool, pgctx := ReportInstance()
	_, err := pgpool.Exec(pgctx,
		"INSERT INTO accounts (username, password, display_name, created) VALUES ($1, $2, $3, $4)",
		account.Username,
		utils.HashPassword(account.Password),
		account.DisplayName,
		account.Created,
	)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][ADD_ACCOUNT] error in insert accounts query: " + err.Error())
	}
	return err
}

func UpdateAccount(accountID string, account models.AccountUpdate) error {
	pgpool, pgctx := ReportInstance()
	var err error
	if len(account.Password) > 0 {
		_, err = pgpool.Exec(pgctx,
			"UPDATE accounts set password = $1 WHERE id = $2",
			utils.HashPassword(account.Password),
			accountID,
		)
	}
	if len(account.DisplayName) > 0 {
		_, err = pgpool.Exec(pgctx,
			"UPDATE accounts set display_name = $1 WHERE id = $2",
			account.DisplayName,
			accountID,
		)
	}
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][UPDATE_ACCOUNT] error in update accounts query: " + err.Error())
	}
	return err
}

func IsAdmin(accountUsername string) (bool, string) {
	pgpool, pgctx := ReportInstance()
	var id int
	err := pgpool.QueryRow(pgctx, "SELECT id FROM accounts where username = $1 LIMIT 1", accountUsername).Scan(&id)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][GET_PASSWORD] error in query execution:" + err.Error())
	}
	return id == 1, string(rune(id))
}

func GetAccounts() ([]models.Account, error) {
	pgpool, pgctx := ReportInstance()
	rows, err := pgpool.Query(pgctx, "SELECT id, username, display_name, created FROM accounts")
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][GET_ACCOUNTS] error in query execution:" + err.Error())
	}
	defer rows.Close()
	var results []models.Account
	for rows.Next() {
		var accountRow models.Account
		if err := rows.Scan(&accountRow.ID, &accountRow.Username, &accountRow.DisplayName, &accountRow.Created); err != nil {
			logs.Logs.Println("[ERR][STORAGE][GET_ACCOUNTS] error in query row extraction" + err.Error())
		}
		accountStatus, _ := utils.GetUserStatus(accountRow.Username)
		accountRow.TwoFA = accountStatus == "1"
		results = append(results, accountRow)
	}
	return results, err
}

func GetAccount(accountID string) ([]models.Account, error) {
	pgpool, pgctx := ReportInstance()
	rows, err := pgpool.Query(pgctx, "SELECT id, username, display_name, created FROM accounts where id = $1", accountID)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][GET_ACCOUNT] error in query execution:" + err.Error())
	}
	defer rows.Close()
	var results []models.Account
	for rows.Next() {
		var accountRow models.Account
		if err := rows.Scan(&accountRow.ID, &accountRow.Username, &accountRow.DisplayName, &accountRow.Created); err != nil {
			logs.Logs.Println("[ERR][STORAGE][GET_ACCOUNT] error in query row extraction" + err.Error())
		}
		results = append(results, accountRow)
	}
	return results, err
}

func GetPassword(accountUsername string) string {
	pgpool, pgctx := ReportInstance()
	var password string
	err := pgpool.QueryRow(pgctx, "SELECT password FROM accounts where username = $1 LIMIT 1", accountUsername).Scan(&password)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][GET_PASSWORD] error in query execution:" + err.Error())
	}
	return password
}

func DeleteAccount(accountID string) error {
	pgpool, pgctx := ReportInstance()
	_, err := pgpool.Exec(pgctx, "DELETE FROM accounts where id = $1", accountID)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][DELETE_ACCOUNT] error in query execution:" + err.Error())
	}
	return err
}

func UpdatePassword(accountUsername string, newPassword string) error {
	pgpool, pgctx := ReportInstance()
	_, err := pgpool.Exec(pgctx,
		"UPDATE accounts set password = $1 WHERE username = $2",
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

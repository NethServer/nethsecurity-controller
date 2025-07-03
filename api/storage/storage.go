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
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"strconv"
	"strings"
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

//go:embed upgrade_schema.sql
var upgradeSchemaSQL string

//go:embed grafana_user.sql.tmpl
var grafanaUserSQL string

// userUnits is a map that holds the units for each user.
var userUnits = make(map[string][]string)

// adminUsers is a list of user names that has the admin flag
var adminUsers = make([]string, 0)

func Init() *pgxpool.Pool {
	// Initialize PostgreSQL connection and schema
	dbpool, dbctx = InitReportDb()

	// Migrate unit info from file to Postgres if needed
	migrated_units := MigrateUnitInfoFromFileToPostgres()

	// Migrate users from SQLite to Postgres if needed
	MigrateUsersFromSqliteToPostgres(migrated_units)

	ReloadACLs()

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
			Admin:       true,
			DisplayName: "Administrator",
			Created:     time.Now(),
		}
		_, _ = AddAccount(admin)
	}

	return dbpool
}

// MigrateUsersFromSqliteToPostgres migrates users from SQLite to PostgreSQL if needed
func MigrateUsersFromSqliteToPostgres(units []string) {
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
		acc.Admin = true
		users = append(users, acc)
	}
	if len(users) == 0 {
		return // No users to migrate
	}

	// 4. Check if admin user exists in Postgres
	pgpool, pgctx := ReportInstance()
	var adminExists bool
	err = pgpool.QueryRow(pgctx, `SELECT EXISTS (SELECT 1 FROM accounts WHERE admin = true)`).Scan(&adminExists)
	if err != nil {
		logs.Logs.Println("[ERR][MIGRATION] error checking admin user in Postgres: " + err.Error())
		return
	}
	if adminExists {
		return // Admin user exists, nothing to do
	}

	// 5. Create a unit_group with all units
	groupID := -1
	var groupErr error
	if len(units) > 0 {
		group := models.UnitGroup{
			Name:        "Migrated",
			Description: "All units migrated from old release",
			Units:       units,
		}
		groupID, groupErr = AddUnitGroup(group)
		// Create a unit group for the migrated units
		if groupErr != nil {
			logs.Logs.Println("[ERR][MIGRATION] error creating unit group in Postgres: " + err.Error())
		}
	}

	// 6. Insert users into Postgres
	for _, acc := range users {
		// Read OTP secret
		otp_secret := ""
		secret, serr := os.ReadFile(configuration.Config.SecretsDir + "/" + acc.Username + "/secret")
		if serr == nil {
			otp_secret = string(secret[:])
		}

		// Read recovery codes
		recoveryCodes := ""
		codesB, rerr := os.ReadFile(configuration.Config.SecretsDir + "/" + acc.Username + "/codes")
		if rerr == nil {
			recoveryCodes = strings.ReplaceAll(strings.TrimSpace(string(codesB[:])), "\n", "|")
		}
		// remove acc.Username directory
		os.RemoveAll(configuration.Config.SecretsDir + "/" + acc.Username)
		if groupID > 0 {
			acc.UnitGroups = []int{groupID} // Set unit group for the user
		}
		// Insert user into Postgres
		_, accountError := AddAccount(acc) // Use AddAccount to handle password hashing and other logic
		if accountError != nil {
			logs.Logs.Println("[ERR][MIGRATION] error migrating user to Postgres: " + accountError.Error())
		}
		// Set the password directly using a raw query
		_, rawPasswordError := pgpool.Exec(pgctx, "UPDATE accounts SET password = $1 WHERE username = $2", acc.Password, acc.Username)
		if rawPasswordError != nil {
			logs.Logs.Println("[ERR][MIGRATION] error setting raw password for user", acc.Username, ":", rawPasswordError.Error())
		}

		// Set OTP secret
		if err := SetUserOtpSecret(acc.Username, otp_secret); err != nil {
			logs.Logs.Println("[ERR][MIGRATION] error mirating OTP secret for user", acc.Username, ":", err.Error())
		}
		if err := SetUserRecoveryCodes(acc.Username, strings.Split(recoveryCodes, "|")); err != nil {
			logs.Logs.Println("[ERR][MIGRATION] error mirating recovery codes for user", acc.Username, ":", err.Error())
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
func AddAccount(account models.Account) (int, error) {
	pgpool, pgctx := ReportInstance()
	var id int
	err := pgpool.QueryRow(pgctx,
		"INSERT INTO accounts (username, password, admin, display_name, unit_groups, created_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
		account.Username,
		utils.HashPassword(account.Password),
		account.Admin,
		account.DisplayName,
		account.UnitGroups,
		account.Created,
	).Scan(&id)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][ADD_ACCOUNT] error in insert accounts query: " + err.Error())
	}

	ReloadACLs()

	return id, err
}

func UpdateAccount(accountID string, account models.AccountUpdate) error {
	pgpool, pgctx := ReportInstance()
	var err error
	// Set unit_groups array
	unitGroupsStrs := make([]string, len(account.UnitGroups))
	for i, v := range account.UnitGroups {
		unitGroupsStrs[i] = strconv.Itoa(v)
	}
	unitGroupsArray := "{" + strings.Join(unitGroupsStrs, ",") + "}"
	_, err = pgpool.Exec(pgctx,
		`UPDATE accounts 
		 SET unit_groups = $1::int[], 
			 display_name = $2, 
			 admin = $3, 
			 updated_at = NOW() 
		 WHERE id = $4`,
		unitGroupsArray,
		account.DisplayName,
		account.Admin,
		accountID,
	)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][UPDATE_ACCOUNT] error in update accounts query: " + err.Error())
		return err
	}

	ReloadACLs()

	return err
}

func IsAdmin(accountUsername string) bool {
	for _, admin := range adminUsers {
		if admin == accountUsername {
			return true
		}
	}
	return false
}

func GetAccounts() ([]models.Account, error) {
	pgpool, pgctx := ReportInstance()
	rows, err := pgpool.Query(pgctx, "SELECT id, username, display_name, admin, unit_groups, created_at, updated_at FROM accounts ORDER BY id ASC")
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][GET_ACCOUNTS] error in query execution:" + err.Error())
	}
	defer rows.Close()
	var results []models.Account
	for rows.Next() {
		var accountRow models.Account
		if err := rows.Scan(&accountRow.ID, &accountRow.Username, &accountRow.DisplayName, &accountRow.Admin, &accountRow.UnitGroups, &accountRow.Created, &accountRow.Updated); err != nil {
			logs.Logs.Println("[ERR][STORAGE][GET_ACCOUNTS] error in query row extraction" + err.Error())
		}
		accountRow.TwoFA = Is2FAEnabled(accountRow.Username)
		results = append(results, accountRow)
	}
	return results, err
}

func GetAccount(accountID string) ([]models.Account, error) {
	pgpool, pgctx := ReportInstance()
	rows, err := pgpool.Query(pgctx, "SELECT id, username, display_name, admin, unit_groups, created_at, updated_at FROM accounts where id = $1", accountID)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][GET_ACCOUNT] error in query execution:" + err.Error())
	}
	defer rows.Close()
	var results []models.Account
	for rows.Next() {
		var accountRow models.Account
		if err := rows.Scan(&accountRow.ID, &accountRow.Username, &accountRow.DisplayName, &accountRow.Admin, &accountRow.UnitGroups, &accountRow.Created, &accountRow.Updated); err != nil {
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

	ReloadACLs()

	return err
}

func UpdatePassword(accountUsername string, newPassword string) error {
	pgpool, pgctx := ReportInstance()
	_, err := pgpool.Exec(pgctx,
		"UPDATE accounts set password = $1 WHERE username = $2",
		utils.HashPassword(newPassword),
		accountUsername,
	)
	if err == nil {
		// Update the updated_at timestamp
		_, err = pgpool.Exec(pgctx, "UPDATE accounts SET updated_at = NOW() WHERE username = $1", accountUsername)
		if err != nil {
			logs.Logs.Println("[ERR][STORAGE][UPDATE_PASSWORD] error in updating updated_at timestamp: " + err.Error())
		}
	} else {
		logs.Logs.Println("[ERR][STORAGE][UPDATE_PASSWORD] error during update password: " + err.Error())
	}
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

	// execute upgrade schema
	logs.Logs.Println("[INFO][STORAGE] upgrading report schema")
	_, errExecute = dbpool.Exec(dbctx, upgradeSchemaSQL)
	if errExecute != nil {
		logs.Logs.Println("[ERR][STORAGE] error in storage file schema upgrade:" + errExecute.Error())
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

	loadReportSchema(dbpool, dbctx)

	return dbpool, dbctx
}

func ReportInstance() (*pgxpool.Pool, context.Context) {
	if dbpool == nil {
		dbpool, dbctx = InitReportDb()

	}

	return dbpool, dbctx
}

func GetUserOtpSecret(username string) string {
	pgpool, pgctx := ReportInstance()
	var otp_secret string
	err := pgpool.QueryRow(pgctx, "SELECT otp_secret FROM accounts where username = $1 LIMIT 1", username).Scan(&otp_secret)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][GET_USER_SECRET] error in query execution:" + err.Error())
		return ""
	}
	decrypted, err := utils.DecryptAESGCMFromString(otp_secret, []byte(configuration.Config.EncryptionKey))
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][DECRYPT_USER_SECRET] error in decryption:" + err.Error())
		return ""
	}
	return string(decrypted)
}

func GetRecoveryCodes(username string) []string {
	pgpool, pgctx := ReportInstance()
	var otp_recovery_codes string
	err := pgpool.QueryRow(pgctx, "SELECT otp_recovery_codes FROM accounts where username = $1 LIMIT 1", username).Scan(&otp_recovery_codes)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][GET_RECOVERY_CODES] error in query execution:" + err.Error())
		return []string{}
	}
	return strings.Split(otp_recovery_codes, "|")
}

func Is2FAEnabled(username string) bool {
	pgpool, pgctx := ReportInstance()
	var status sql.NullString
	err := pgpool.QueryRow(pgctx, "SELECT otp_secret FROM accounts where username = $1 LIMIT 1", username).Scan(&status)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][GET_2FA_STATUS] error in query execution:" + err.Error())
	}
	return status.Valid && status.String != ""
}

func SetUserOtpSecret(username string, secret string) error {
	pgpool, pgctx := ReportInstance()
	var otp_secret string
	if len(secret) > 0 {
		otp_secret, _ = utils.EncryptAESGCMToString([]byte(secret), []byte(configuration.Config.EncryptionKey))
	} else {
		otp_secret = ""
	}
	_, err := pgpool.Exec(pgctx, "UPDATE accounts set otp_secret = $1 WHERE username = $2", otp_secret, username)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][SET_USER_OTP_SECRET] error in query execution:" + err.Error())
	}
	return err
}

func SetUserRecoveryCodes(username string, codes []string) error {
	pgpool, pgctx := ReportInstance()
	_, err := pgpool.Exec(pgctx, "UPDATE accounts set otp_recovery_codes = $1 WHERE username = $2", strings.Join(codes, "|"), username)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][SET_USER_RECOVERY_CODES] error in query execution:" + err.Error())
	}
	return err
}

func AddUnit(uuid string, ipaddr string) error {
	pgpool, pgctx := ReportInstance()
	// Try to insert the unit; if it already exists, return an error
	_, err := pgpool.Exec(pgctx, `
		INSERT INTO units (uuid, vpn_address, created_at, updated_at)
		VALUES ($1, $2, NOW(), NOW())
		ON CONFLICT (uuid) DO NOTHING
	`, uuid, ipaddr)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][ADD_UNIT] error in query execution:" + err.Error())
	}
	return err
}

func SetUnitInfo(uuid string, info models.UnitInfo) error {
	pgpool, pgctx := ReportInstance()
	// Try to update the unit; if no rows are affected, return an error
	res, err := pgpool.Exec(pgctx, `
		UPDATE units SET name = $2, info = $3::jsonb, updated_at = NOW()
		WHERE uuid = $1
	`, uuid, info.UnitName, info)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][SET_UNIT_INFO] error in query execution:" + err.Error())
		return err
	}
	if res.RowsAffected() == 0 {
		logs.Logs.Println("[WARN][STORAGE][SET_UNIT_INFO] unit with uuid " + uuid + " does not exist")
	}
	return err
}

func GetUnitInfo(uuid string) map[string]interface{} {
	pgpool, pgctx := ReportInstance()
	var infoStr string
	err := pgpool.QueryRow(pgctx, `
		SELECT info::text FROM units WHERE uuid = $1
	`, uuid).Scan(&infoStr)
	if err != nil {
		// No info found for this unit, return nil
		return nil
	}
	var info map[string]interface{}
	if err := json.Unmarshal([]byte(infoStr), &info); err != nil {
		logs.Logs.Println("[ERR][STORAGE][GET_UNIT_INFO] error unmarshalling info:" + err.Error())
		return nil
	}
	return info
}

func loadUnitIP(unitId string) string {
	unitFile, err := os.ReadFile(configuration.Config.OpenVPNCCDDir + "/" + unitId)
	if err != nil {
		return ""
	}

	// parse ccd dir file content
	parts := strings.Split(string(unitFile), "\n")
	parts = strings.Split(parts[0], " ")

	return parts[1]
}

func MigrateUnitInfoFromFileToPostgres() []string {
	ret := make([]string, 0)
	// Search for all *.info file inside Config.OpenVPNStatusDir
	// If the dir does not exists, just return
	if _, err := os.Stat(configuration.Config.OpenVPNStatusDir); os.IsNotExist(err) {
		return ret
	}
	files, err := os.ReadDir(configuration.Config.OpenVPNCCDDir)
	if err != nil {
		logs.Logs.Println("[WARNING][MIGRATION] error reading OpenVPN status directory: " + err.Error())
		return ret
	}
	for _, file := range files {
		if !file.IsDir() {
			uuid := file.Name()
			infoFile := configuration.Config.OpenVPNStatusDir + "/" + uuid + ".info"
			vpnFile := configuration.Config.OpenVPNCCDDir + "/" + uuid + ".vpn"
			ipaddr := loadUnitIP(uuid)

			// Check if the unit already exists in Postgres
			exists, err := UnitExists(uuid)
			if err != nil {
				logs.Logs.Println("[WARNING][MIGRATION] error checking if unit exists in Postgres:", err.Error())
				continue
			}
			if exists {
				logs.Logs.Println("[INFO][MIGRATION] unit", uuid, "already exists in Postgres, skipping migration")
				continue
			}
			// ignore the error
			addUnitErr := AddUnit(uuid, ipaddr)
			if addUnitErr != nil {
				logs.Logs.Println("[WARNING][MIGRATION] error adding unit to Postgres:", uuid, addUnitErr.Error())
				continue
			}
			connected_since := 0
			statusFile, err := os.ReadFile(vpnFile)
			if err == nil {
				connected_since, _ = strconv.Atoi(string(statusFile))
			}
			if connected_since > 0 {
				// Update the unit with the connected_since timestamp
				UpdateUnitVpnStatus(uuid, connected_since)
			}
			if _, err := os.Stat(infoFile); err == nil {
				// read file, parse as JSON and then call AddUnit
				data, err := os.ReadFile(infoFile)
				if err != nil {
					logs.Logs.Println("[WARNING][MIGRATION] error reading file:", infoFile, err.Error())
					continue
				}
				var info models.UnitInfo
				if err := json.Unmarshal(data, &info); err != nil {
					logs.Logs.Println("[WARNING][MIGRATION] error parsing JSON in file:", infoFile, err.Error())
					continue
				}
				if err := SetUnitInfo(uuid, info); err != nil {
					logs.Logs.Println("[WARNING][MIGRATION] error setting unit info for", uuid, ":", err.Error())
				}
				// remove the file
				if err := os.Remove(infoFile); err != nil {
					logs.Logs.Println("[WARNING][MIGRATION] error removing file:", infoFile, err.Error())
				} else {
					logs.Logs.Println("[INFO][MIGRATION] removed file:", infoFile)
				}
			}
			ret = append(ret, uuid)
		}
	}
	logs.Logs.Println("[INFO][MIGRATION] migrated", len(ret), "units from file to Postgres")
	return ret
}

func UnitExists(uuid string) (bool, error) {
	pgpool, pgctx := ReportInstance()
	var exists bool
	err := pgpool.QueryRow(pgctx, "SELECT EXISTS (SELECT 1 FROM units WHERE uuid = $1)", uuid).Scan(&exists)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][UNIT_EXISTS] error in query execution:" + err.Error())
		return false, err
	}
	return exists, nil
}

// AddUnitGroup adds a new unit group. Only admin can execute.
func AddUnitGroup(group models.UnitGroup) (int, error) {
	pgpool, pgctx := ReportInstance()
	var id int
	unitArray := "{" + strings.Join(group.Units, ",") + "}"
	err := pgpool.QueryRow(pgctx,
		`INSERT INTO unit_groups (name, description, units, created_at, updated_at) VALUES ($1, $2, $3::uuid[], NOW(), NOW()) RETURNING id`,
		group.Name, group.Description, unitArray).Scan(&id)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][ADD_UNIT_GROUP] error in insert unit_groups query: " + err.Error())
	}

	ReloadACLs()

	return id, err
}

func UpdateUnitGroup(groupId int, group models.UnitGroup) error {
	pgpool, pgctx := ReportInstance()
	unitArray := "{" + strings.Join(group.Units, ",") + "}"
	res, err := pgpool.Exec(pgctx,
		`UPDATE unit_groups SET name = $1, description = $2, units = $3::uuid[], updated_at = NOW() WHERE id = $4`,
		group.Name, group.Description, unitArray, groupId)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][EDIT_UNIT_GROUP] error in update unit_groups query: " + err.Error())
		return err
	}
	if res.RowsAffected() == 0 {
		logs.Logs.Println("[WARN][STORAGE][EDIT_UNIT_GROUP] no unit group updated with id " + strconv.Itoa(groupId))
		return fmt.Errorf("no unit group updated with id %d", groupId)
	}

	ReloadACLs()

	return nil
}

func DeleteUnitGroup(groupID int) error {
	pgpool, pgctx := ReportInstance()
	res, err := pgpool.Exec(pgctx, `DELETE FROM unit_groups WHERE id = $1`, groupID)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][DELETE_UNIT_GROUP] error in delete unit_groups query: " + err.Error())
		return err
	}
	if res.RowsAffected() == 0 {
		logs.Logs.Println("[WARN][STORAGE][DELETE_UNIT_GROUP] no unit group deleted with id " + strconv.Itoa(groupID))
		return fmt.Errorf("no unit group deleted with id %d", groupID)
	}

	ReloadACLs()

	return nil
}

func ListUnitGroups() ([]models.UnitGroup, error) {
	pgpool, pgctx := ReportInstance()
	rows, err := pgpool.Query(pgctx, `SELECT id, name, description, units, created_at, updated_at FROM unit_groups`)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][GET_UNIT_GROUPS] error in query execution:" + err.Error())
		return nil, err
	}
	defer rows.Close()

	var groups []models.UnitGroup
	for rows.Next() {
		var group models.UnitGroup
		var unitsArray []string
		if err := rows.Scan(&group.ID, &group.Name, &group.Description, &unitsArray, &group.CreatedAt, &group.UpdatedAt); err != nil {
			logs.Logs.Println("[ERR][STORAGE][GET_UNIT_GROUPS] error in query row extraction" + err.Error())
			continue
		}
		group.Units = unitsArray
		groups = append(groups, group)
	}
	return groups, nil
}

func GetUnitGroup(groupID int) (models.UnitGroup, error) {
	pgpool, pgctx := ReportInstance()
	row := pgpool.QueryRow(pgctx, `SELECT id, name, description, units, created_at, updated_at FROM unit_groups WHERE id = $1`, groupID)

	var group models.UnitGroup
	var unitsArray []string
	if err := row.Scan(&group.ID, &group.Name, &group.Description, &unitsArray, &group.CreatedAt, &group.UpdatedAt); err != nil {
		logs.Logs.Println("[ERR][STORAGE][GET_UNIT_GROUP] error in query row extraction" + err.Error())
		return group, err
	}
	group.Units = unitsArray
	return group, nil
}

func IsUnitGroupUsed(groupID int) (bool, error) {
	pgpool, pgctx := ReportInstance()
	var exists bool
	query := `
		SELECT EXISTS (
			SELECT 1 FROM accounts
			WHERE $1 = ANY(unit_groups)
		)
	`
	err := pgpool.QueryRow(pgctx, query, groupID).Scan(&exists)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][IS_UNIT_GROUP_USED] error in query execution:" + err.Error())
		return false, err
	}
	return exists, nil
}

func UnitGroupExists(groupID int) (bool, error) {
	pgpool, pgctx := ReportInstance()
	var exists bool
	err := pgpool.QueryRow(pgctx, "SELECT EXISTS (SELECT 1 FROM unit_groups WHERE id = $1)", groupID).Scan(&exists)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][UNIT_GROUP_EXISTS] error in query execution:" + err.Error())
		return false, err
	}
	return exists, nil
}

func GetUserUnits() map[string][]string {
	// If userUnits is already loaded, return it
	if len(userUnits) > 0 {
		return userUnits
	}

	// Load user units from the database
	userUnitsMap, err := LoadUserUnitsMap()
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][GET_USER_UNITS] error loading user units: " + err.Error())
		return nil
	}

	userUnits = userUnitsMap
	return userUnits
}

func LoadUserUnitsMap() (map[string][]string, error) {
	pgpool, pgctx := ReportInstance()
	UserUnits := make(map[string][]string)

	// Use a join to get username and units in a single query
	rows, err := pgpool.Query(pgctx, `
		SELECT a.username, COALESCE(u.units, '{}') AS units
		FROM accounts a
		LEFT JOIN LATERAL (
			SELECT array_agg(DISTINCT group_id) AS group_ids
			FROM accounts acc, unnest(acc.unit_groups) AS group_id
			WHERE acc.username = a.username AND acc.unit_groups IS NOT NULL AND array_length(acc.unit_groups, 1) > 0
		) ag ON true
		LEFT JOIN LATERAL (
			SELECT array_agg(DISTINCT unit_id) AS units
			FROM unit_groups ug, unnest(ug.units) AS unit_id
			WHERE ag.group_ids IS NOT NULL AND ug.id = ANY(ag.group_ids)
		) u ON true
	`)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][GET_USER_UNITS_MAP] error in query execution:" + err.Error())
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var username string
		var unitsArr []string
		if err := rows.Scan(&username, &unitsArr); err != nil {
			logs.Logs.Println("[ERR][STORAGE][GET_USER_UNITS_MAP] error in row scan: " + err.Error())
			continue
		}
		// If unitsArr is nil, assign empty slice
		if unitsArr == nil {
			unitsArr = []string{}
		}
		UserUnits[username] = unitsArr
	}
	return UserUnits, nil
}

func LoadAdminUsersList() ([]string, error) {
	pgpool, pgctx := ReportInstance()
	rows, err := pgpool.Query(pgctx, "SELECT username FROM accounts WHERE admin = true")
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][LOAD_ADMIN_USERS] error in query execution:" + err.Error())
		return nil, err
	}
	defer rows.Close()

	admins := make([]string, 0)
	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			logs.Logs.Println("[ERR][STORAGE][LOAD_ADMIN_USERS] error in row scan: " + err.Error())
			continue
		}
		admins = append(admins, username)
	}
	return admins, nil
}

func ReloadACLs() {
	// Reload user units from the database
	userUnitsMap, err := LoadUserUnitsMap()
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][RELOAD_USER_UNITS] error loading user units: " + err.Error())
		return
	}
	userUnits = userUnitsMap
	logs.Logs.Println("[INFO][STORAGE][RELOAD_USER_UNITS] user units reloaded successfully")

	// Reload admin users
	admins, err := LoadAdminUsersList()
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][RELOAD_ADMIN_USERS] error loading admin users: " + err.Error())
		return
	}
	adminUsers = admins
	logs.Logs.Println("[INFO][STORAGE][RELOAD_ADMIN_USERS] admin users reloaded successfully")
}

func GetFreeIP() string {
	// get all ips
	IPs, _ := utils.ListIPs(configuration.Config.OpenVPNNetwork, configuration.Config.OpenVPNNetmask)
	// remove first ip used for tun
	IPs = IPs[1:]

	pgpool, pgctx := ReportInstance()
	rows, err := pgpool.Query(pgctx, "SELECT vpn_address FROM units WHERE vpn_address IS NOT NULL")
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][GET_FREE_IP] error in query execution:" + err.Error())
		return ""
	}
	defer rows.Close()

	usedIPs := make([]string, 0)
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			logs.Logs.Println("[ERR][STORAGE][GET_FREE_IP] error in row scan: " + err.Error())
			continue
		}
		usedIPs = append(usedIPs, ip)
	}
	// usedIPs now contains all used IP addresses from the units table
	// loop all IPs
	for _, ip := range IPs {
		if !utils.Contains(ip, usedIPs) {
			return ip
		}
	}
	return ""
}

func ListUnits() ([]map[string]interface{}, error) {

	pgpool, pgctx := ReportInstance()
	rows, err := pgpool.Query(pgctx, "SELECT uuid, vpn_address, info::text, vpn_connected_since FROM units ORDER BY created_at ASC")
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][LIST_UNITS] error in query execution:" + err.Error())
		return nil, err
	}
	defer rows.Close()

	units := make([]map[string]interface{}, 0)
	for rows.Next() {
		var uuid sql.NullString
		var ipaddress sql.NullString
		var infoStr sql.NullString
		var connectedSince sql.NullTime
		var info map[string]interface{}
		vpn_info := make(map[string]interface{})
		unit := make(map[string]interface{})

		if err := rows.Scan(&uuid, &ipaddress, &infoStr, &connectedSince); err != nil {
			logs.Logs.Println("[ERR][STORAGE][LIST_UNITS] error in row scan: " + err.Error())
			continue
		}

		unit["id"] = uuid.String
		unit["ipaddress"] = ipaddress.String
		unit["netmask"] = configuration.Config.OpenVPNNetmask
		unit["vpn"] = vpn_info

		if infoStr.Valid && infoStr.String != "" {
			if err := json.Unmarshal([]byte(infoStr.String), &info); err == nil {
				unit["info"] = info
			} else {
				unit["info"] = map[string]interface{}{}
			}
		} else {
			unit["info"] = map[string]interface{}{}
		}

		unit["join_code"] = utils.GetJoinCode(uuid.String)
		if connectedSince.Valid {
			vpn_info["connected_since"] = connectedSince.Time.Unix()
		}

		units = append(units, unit)
	}
	return units, nil
}

func ListConnectedUnits() ([]string, error) {
	pgpool, pgctx := ReportInstance()
	rows, err := pgpool.Query(pgctx, "SELECT uuid FROM units WHERE vpn_connected_since IS NOT NULL")
	if err != nil {
		logs.Logs.Println("[INFO][STORAGE][LIST_CONNECTED_UNITS] error in query execution:" + err.Error())
		return nil, err
	}
	defer rows.Close()

	var uuids []string
	for rows.Next() {
		var uuid string
		if err := rows.Scan(&uuid); err != nil {
			logs.Logs.Println("[ERR][STORAGE][LIST_CONNECTED_UNITS] error in row scan: " + err.Error())
			continue
		}
		uuids = append(uuids, uuid)
	}
	return uuids, nil
}

func UpdateUnitVpnStatus(uuid string, connectedSince int) error {
	pgpool, pgctx := ReportInstance()
	// Convert connectedSince (seconds since epoch) to time.Time
	connectedTime := time.Unix(int64(connectedSince), 0)
	_, err := pgpool.Exec(pgctx, `
		UPDATE units 
		SET vpn_connected_since = $1, updated_at = NOW() 
		WHERE uuid = $2
	`, connectedTime, uuid)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][UPDATE_UNIT_VPN_STATUS] error in query execution:" + err.Error())
		return err
	}
	return nil
}

func GetUnit(uuid string) (map[string]interface{}, error) {
	pgpool, pgctx := ReportInstance()
	row := pgpool.QueryRow(pgctx, "SELECT uuid, vpn_address, info::text, vpn_connected_since FROM units WHERE uuid = $1", uuid)

	var unit map[string]interface{}
	var ipaddress sql.NullString
	var infoStr sql.NullString
	var connectedSince sql.NullTime

	if err := row.Scan(&uuid, &ipaddress, &infoStr, &connectedSince); err != nil {
		logs.Logs.Println("[ERR][STORAGE][GET_UNIT] error in query execution:" + err.Error())
		return nil, err
	}

	unit = make(map[string]interface{})
	unit["id"] = uuid
	unit["ipaddress"] = ipaddress.String
	unit["netmask"] = configuration.Config.OpenVPNNetmask
	vpn_info := make(map[string]interface{})
	vpn_info["connected_since"] = 0

	if infoStr.Valid && infoStr.String != "" {
		var info map[string]interface{}
		if err := json.Unmarshal([]byte(infoStr.String), &info); err == nil {
			unit["info"] = info
		} else {
			unit["info"] = map[string]interface{}{}
		}
	} else {
		unit["info"] = map[string]interface{}{}
	}

	if connectedSince.Valid {
		vpn_info["connected_since"] = connectedSince.Time.Unix()
	}

	unit["vpn"] = vpn_info
	unit["join_code"] = utils.GetJoinCode(uuid)

	return unit, nil
}

func DeleteUnit(uuid string) error {
	pgpool, pgctx := ReportInstance()
	// Delete the unit from the database
	res, err := pgpool.Exec(pgctx, "DELETE FROM units WHERE uuid = $1", uuid)
	if err != nil {
		logs.Logs.Println("[ERR][STORAGE][DELETE_UNIT] error in query execution:" + err.Error())
		return err
	}
	if res.RowsAffected() == 0 {
		logs.Logs.Println("[WARN][STORAGE][DELETE_UNIT] no unit deleted with uuid " + uuid)
		return fmt.Errorf("no unit deleted with uuid %s", uuid)
	}

	return nil
}

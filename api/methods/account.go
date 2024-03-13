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
	"net/http"
	"time"

	"github.com/NethServer/nethsecurity-api/response"
	"github.com/NethServer/nethsecurity-controller/api/models"
	"github.com/NethServer/nethsecurity-controller/api/storage"
	"github.com/fatih/structs"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
)

func GetAccounts(c *gin.Context) {
	// check auth for not admin users
	isAdmin, _ := storage.IsAdmin(jwt.ExtractClaims(c)["id"].(string))
	if !isAdmin {
		c.JSON(http.StatusForbidden, structs.Map(response.StatusForbidden{
			Code:    403,
			Message: "can't access this resource",
			Data:    nil,
		}))
		return
	}

	// execute query
	accounts, err := storage.GetAccounts()

	if err != nil {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Code:    500,
			Message: "get accounts error",
			Data:    err.Error(),
		}))
		return
	}

	// check results
	if len(accounts) == 0 {
		c.JSON(http.StatusNotFound, structs.Map(response.StatusNotFound{
			Code:    404,
			Message: "not found",
			Data:    nil,
		}))
		return
	}

	// return ok
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "success",
		Data:    gin.H{"accounts": accounts, "total": len(accounts)},
	}))
}

func GetAccount(c *gin.Context) {
	// check auth for not admin users
	isAdmin, _ := storage.IsAdmin(jwt.ExtractClaims(c)["id"].(string))
	if !isAdmin {
		c.JSON(http.StatusForbidden, structs.Map(response.StatusForbidden{
			Code:    403,
			Message: "can't access this resource",
			Data:    nil,
		}))
		return
	}

	// get account id
	accountID := c.Param("account_id")

	// execute query
	accounts, err := storage.GetAccount(accountID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Code:    500,
			Message: "get account error",
			Data:    err.Error(),
		}))
		return
	}

	// check results
	if len(accounts) == 0 {
		c.JSON(http.StatusNotFound, structs.Map(response.StatusNotFound{
			Code:    404,
			Message: "not found",
			Data:    nil,
		}))
		return
	}

	// return ok
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "success",
		Data:    gin.H{"account": accounts[0]},
	}))
}

func AddAccount(c *gin.Context) {
	// check auth for not admin users
	isAdmin, _ := storage.IsAdmin(jwt.ExtractClaims(c)["id"].(string))
	if !isAdmin {
		c.JSON(http.StatusForbidden, structs.Map(response.StatusForbidden{
			Code:    403,
			Message: "can't access this resource",
			Data:    nil,
		}))
		return
	}

	// get account fields
	var json models.Account
	if err := c.BindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "request fields malformed", "error": err.Error()})
		return
	}

	// create account
	json.Created = time.Now()
	err := storage.AddAccount(json)

	// check results
	if err != nil {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Code:    500,
			Message: "add account error",
			Data:    err.Error(),
		}))
		return
	}

	// return ok
	c.JSON(http.StatusCreated, structs.Map(response.StatusCreated{
		Code:    201,
		Message: "success",
		Data:    nil,
	}))
}

func UpdateAccount(c *gin.Context) {
	// get account id
	accountID := c.Param("account_id")

	// check auth for not admin users
	isAdmin, _ := storage.IsAdmin(jwt.ExtractClaims(c)["id"].(string))
	if !isAdmin {
		c.JSON(http.StatusForbidden, structs.Map(response.StatusForbidden{
			Code:    403,
			Message: "can't access this resource",
			Data:    nil,
		}))
		return
	}

	// get account fields
	var json models.AccountUpdate
	if err := c.BindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "request fields malformed", "error": err.Error()})
		return
	}

	// update account
	err := storage.UpdateAccount(accountID, json)

	// check results
	if err != nil {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Code:    500,
			Message: "add account error",
			Data:    err.Error(),
		}))
		return
	}

	// return ok
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "success",
		Data:    nil,
	}))
}

func DeleteAccount(c *gin.Context) {
	// check auth
	isAdmin, _ := storage.IsAdmin(jwt.ExtractClaims(c)["id"].(string))
	if !isAdmin {
		c.JSON(http.StatusForbidden, structs.Map(response.StatusForbidden{
			Code:    403,
			Message: "can't access this resource",
			Data:    nil,
		}))
		return
	}

	// get account id
	accountID := c.Param("account_id")

	// execute query
	err := storage.DeleteAccount(accountID)

	// check results
	if err != nil {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Code:    500,
			Message: "delete account error",
			Data:    err.Error(),
		}))
		return
	}

	// return ok
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "success",
		Data:    nil,
	}))
}

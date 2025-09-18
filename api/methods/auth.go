/*
 * Copyright (C) 2023 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Edoardo Spadoni <edoardo.spadoni@nethesis.it>
 */

package methods

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/NethServer/nethsecurity-controller/api/logs"
	"github.com/NethServer/nethsecurity-controller/api/models"
	"github.com/NethServer/nethsecurity-controller/api/response"
	"github.com/NethServer/nethsecurity-controller/api/storage"
	"github.com/NethServer/nethsecurity-controller/api/utils"
	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	jwtl "github.com/golang-jwt/jwt/v4"

	"github.com/NethServer/nethsecurity-controller/api/configuration"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

var activeTokens sync.Map
var tempOtpSecrets sync.Map

func CheckTokenValidation(username string, token string) bool {
	value, ok := activeTokens.Load(username)
	if !ok {
		return false
	}
	tokens := value.([]string)
	return slices.Contains(tokens, token)
}

func SetTokenValidation(username string, token string) bool {
	value, _ := activeTokens.LoadOrStore(username, []string{})
	tokens := value.([]string)

	// Avoid duplicates
	if !slices.Contains(tokens, token) {
		tokens = append(tokens, token)
		activeTokens.Store(username, tokens)
	}
	return true
}

func DelTokenValidation(username string, token string) bool {
	value, ok := activeTokens.Load(username)
	if !ok {
		return false
	}
	tokens := value.([]string)

	// Remove the token from the user's tokens slice
	newTokens := slices.DeleteFunc(tokens, func(s string) bool {
		return s == token
	})
	if len(newTokens) == 0 {
		activeTokens.Delete(username)
	} else {
		activeTokens.Store(username, newTokens)
	}
	return true
}

func OTPVerify(c *gin.Context) {
	// get payload
	var jsonOTP models.OTPJson
	if err := c.ShouldBindBodyWith(&jsonOTP, binding.JSON); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "request fields malformed",
			Data:    err.Error(),
		}))
		return
	}

	// verify JWT
	if !ValidateAuth(jsonOTP.Token, false) {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "JWT token invalid",
			Data:    "",
		}))
		return
	}

	// get secret for the user
	secret := storage.GetUserOtpSecret(jsonOTP.Username)

	// check secret
	if len(secret) == 0 {
		c.JSON(http.StatusNotFound, structs.Map(response.StatusNotFound{
			Code:    404,
			Message: "user secret not found",
			Data:    "",
		}))
		return
	}

	// verifiy OTP
	valid := false
	err := error(nil)
	valid, err = totp.ValidateCustom(jsonOTP.OTP, secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      3, // window size
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil || !valid {

		// check if OTP is a recovery code
		recoveryCodes := storage.GetRecoveryCodes(jsonOTP.Username)

		if !utils.Contains(jsonOTP.OTP, recoveryCodes) {
			// compose validation error
			jsonParsed, _ := gabs.ParseJSON([]byte(`{
				"validation": {
				  "errors": [
					{
					  "message": "invalid_otp",
					  "parameter": "otp",
					  "value": ""
					}
				  ]
				}
			}`))

			// return validation error
			c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
				Code:    400,
				Message: "validation_failed",
				Data:    jsonParsed,
			}))
			return
		}

		// remove used recovery OTP
		recoveryCodes = utils.Remove(jsonOTP.OTP, recoveryCodes)

		// update recovery codes file
		if !UpdateRecoveryCodes(jsonOTP.Username, recoveryCodes) {
			c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
				Code:    400,
				Message: "OTP recovery codes not updated",
				Data:    "",
			}))
			return
		}

	}

	// Just fail if 2FA is not enabled
	if !storage.Is2FAEnabled(jsonOTP.Username) {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "2fa_disabled",
			Data:    "",
		}))
		return
	}

	// set auth token to valid
	if !SetTokenValidation(jsonOTP.Username, jsonOTP.Token) {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "token validation set error",
			Data:    "",
		}))
		return
	}

	// response
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "OTP verified",
		Data:    jsonOTP.Token,
	}))
}

func ValidateAuth(tokenString string, ensureTokenExists bool) bool {
	// convert token string and validate it
	if tokenString != "" {
		token, err := jwtl.Parse(tokenString, func(token *jwtl.Token) (interface{}, error) {
			// validate the alg
			if _, ok := token.Method.(*jwtl.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			// return secret
			return []byte(configuration.Config.SecretJWT), nil
		})

		if err != nil {
			logs.Logs.Println("[ERR][JWT] error in JWT token validation: " + err.Error())
			return false
		}

		if claims, ok := token.Claims.(jwtl.MapClaims); ok && token.Valid {
			if claims["id"] != nil {
				if ensureTokenExists {
					username := claims["id"].(string)

					if !CheckTokenValidation(username, tokenString) {
						logs.Logs.Println("[ERR][JWT] error JWT token not found")
						return false
					}
				}
				return true
			}
		} else {
			logs.Logs.Println("[ERR][JWT] error in JWT token claims")
			return false
		}
	}
	return false
}

func UpdateRecoveryCodes(username string, codes []string) bool {
	err := storage.SetUserRecoveryCodes(username, codes)
	// check error
	return err == nil
}

func Get2FAStatus(c *gin.Context) {
	// get claims from token
	claims := jwt.ExtractClaims(c)
	var message string
	var recoveryCodes []string

	twofa_enabled := storage.Is2FAEnabled(claims["id"].(string))
	if twofa_enabled {
		message = "2FA set for this user"
		recoveryCodes = storage.GetRecoveryCodes(claims["id"].(string))
	} else {
		message = "2FA not set for this user"
		recoveryCodes = []string{}
	}

	// return response
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: message,
		Data:    gin.H{"status": twofa_enabled, "recovery_codes": recoveryCodes},
	}))
}

func Del2FAStatus(c *gin.Context) {
	// get claims from token
	claims := jwt.ExtractClaims(c)

	// revoke 2FA secret
	err := storage.SetUserOtpSecret(claims["id"].(string), "")
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "error in revoke 2FA for user",
			Data:    nil,
		}))
		return
	}

	// revoke 2FA recovery codes
	err = storage.SetUserRecoveryCodes(claims["id"].(string), []string{})
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "error in revoke 2FA recovery codes for user",
			Data:    nil,
		}))
		return
	}

	// response
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "2FA revocate successfully",
		Data:    "",
	}))
}

func Generate2FASecret(c *gin.Context) {
	// generate random secret
	secret := make([]byte, 20)
	_, err := rand.Read(secret)
	if err != nil {
		logs.Logs.Println("[ERR][2FA] Failed to generate random secret for QRCode: " + err.Error())
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Code:    500,
			Message: "failed to generate random secret",
			Data:    err.Error(),
		}))
		return
	}

	// get user account from claims
	claims := jwt.ExtractClaims(c)
	account := claims["id"].(string)

	// store temporary secret
	secretBase32 := base32.StdEncoding.EncodeToString(secret)
	tempOtpSecrets.Store(account, secretBase32)

	// prepare QR code
	issuer := configuration.Config.Issuer2FA

	// define URL
	URL, _ := url.Parse("otpauth://totp")
	// add params
	URL.Path += "/" + issuer + ":" + account
	params := url.Values{}
	params.Add("secret", secretBase32)
	params.Add("issuer", issuer)
	params.Add("algorithm", "SHA1")
	params.Add("digits", "6")
	params.Add("period", "30")
	URL.RawQuery = params.Encode()

	// response
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "QR code string",
		Data:    gin.H{"url": URL.String(), "key": secretBase32},
	}))
}

func Set2FASecret(c *gin.Context) {
	// get payload
	var otpRequest models.OTP
	if err := c.ShouldBindBodyWith(&otpRequest, binding.JSON); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "request fields malformed",
			Data:    err.Error(),
		}))
		return
	}

	// get user account from claims
	claims := jwt.ExtractClaims(c)
	account := claims["id"].(string)

	secretBase32, ok := tempOtpSecrets.Load(account)
	if !ok {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "no temporary secret found for user, please generate a new one",
			Data:    "",
		}))
		return
	}

	// verifiy OTP
	valid, err := totp.ValidateCustom(otpRequest.OTP, secretBase32.(string), time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      3, // window size
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})

	// OTP not valid, return error
	if err != nil || !valid {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "invalid OTP code",
			Data:    "",
		}))
		return
	}

	// OTP is valid, set secret for user
	result, _ := SetUserSecret(account, secretBase32.(string))
	if !result {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "user secret set error",
			Data:    "",
		}))
		return
	}
	// save recovery codes
	storage.SetUserRecoveryCodes(account, generateRecoveryCodes())

	// response
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "2FA enabled successfully",
		Data:    "",
	}))
}

func Del2FASecret(c *gin.Context) {
	// get user account from claims
	claims := jwt.ExtractClaims(c)
	account := claims["id"].(string)

	// delete temporary secret
	tempOtpSecrets.Delete(account)

	// response
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "temporary secret deleted successfully",
		Data:    "",
	}))
}

func SetUserSecret(username string, secret string) (bool, string) {
	err := storage.SetUserOtpSecret(username, secret)
	return err == nil, secret
}

func generateRecoveryCodes() []string {
	recoveryCodes := make([]string, 10)
	for i := 0; i < 10; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(1000000))
		if err != nil {
			recoveryCodes[i] = "000000" // fallback in case of error
			continue
		}
		recoveryCodes[i] = fmt.Sprintf("%06d", num.Int64())
	}
	return recoveryCodes
}

func UserCanAccessUnit(user string, unitID string) bool {
	if storage.IsAdmin(user) {
		return true
	}
	userUnits := storage.GetUserUnits()
	units, ok := userUnits[user]
	if !ok {
		return false
	}
	for _, u := range units {
		if u == unitID {
			return true
		}
	}
	return false
}

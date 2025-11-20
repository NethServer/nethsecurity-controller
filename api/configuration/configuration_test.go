/*
 * Copyright (C) 2024 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Edoardo Spadoni <edoardo.spadoni@nethesis.it>
 */

package configuration

import (
	"os"
	"testing"

	"github.com/NethServer/nethsecurity-controller/api/logs"
	"github.com/stretchr/testify/assert"
)

func TestInit(t *testing.T) {
	logs.Init("test")
	// Save original config
	originalConfig := Config
	defer func() {
		Config = originalConfig
	}()

	// Clean up env vars
	os.Unsetenv("ENCRYPTION_KEY")
	os.Unsetenv("GRAFANA_POSTGRES_PASSWORD")
	os.Unsetenv("REPORT_DB_URI")
	os.Unsetenv("GRAFANA_PATH")
	os.Unsetenv("WEBSSH_PATH")
	os.Unsetenv("PROMETHEUS_PATH")
	os.Unsetenv("PROMTAIL_PORT")
	os.Unsetenv("PROMTAIL_ADDRESS")
	os.Unsetenv("ISSUER_2FA")
	os.Unsetenv("DATA_DIR")
	os.Unsetenv("CREDENTIALS_DIR")
	os.Unsetenv("REGISTRATION_TOKEN")
	os.Unsetenv("SECRET_JWT")
	os.Unsetenv("ADMIN_PASSWORD")
	os.Unsetenv("ADMIN_USERNAME")
	os.Unsetenv("LISTEN_ADDRESS")
	os.Unsetenv("SENSITIVE_LIST")
	os.Unsetenv("OVPN_DIR")
	os.Unsetenv("SECRETS_DIR")
	os.Unsetenv("FQDN")
	os.Unsetenv("VALID_SUBSCRIPTION")

	// Set required env vars to avoid os.Exit
	os.Setenv("ENCRYPTION_KEY", "12345678901234567890123456789012")
	os.Setenv("GRAFANA_POSTGRES_PASSWORD", "grafana_pass")
	os.Setenv("REPORT_DB_URI", "postgres://user:pass@localhost/db")
	os.Setenv("GRAFANA_PATH", "/grafana")
	os.Setenv("WEBSSH_PATH", "/webssh")
	os.Setenv("PROMETHEUS_PATH", "/prometheus")
	os.Setenv("PROMTAIL_PORT", "3100")
	os.Setenv("PROMTAIL_ADDRESS", "localhost")
	os.Setenv("ISSUER_2FA", "issuer")
	os.Setenv("DATA_DIR", "/tmp/data")
	os.Setenv("CREDENTIALS_DIR", "/tmp/creds")
	os.Setenv("REGISTRATION_TOKEN", "token")
	os.Setenv("SECRET_JWT", "secret")
	os.Setenv("ADMIN_PASSWORD", "password")
	os.Setenv("ADMIN_USERNAME", "admin")

	// Test with custom LISTEN_ADDRESS
	os.Setenv("LISTEN_ADDRESS", "127.0.0.1:8080,0.0.0.0:9090")
	os.Setenv("SENSITIVE_LIST", "pass,secret,key")
	os.Setenv("OVPN_DIR", "/etc/openvpn_custom")
	os.Setenv("SECRETS_DIR", "/tmp/secrets")
	os.Setenv("FQDN", "example.com")
	os.Setenv("VALID_SUBSCRIPTION", "true")

	Init()

	assert.Equal(t, "12345678901234567890123456789012", Config.EncryptionKey)
	assert.Equal(t, "grafana_pass", Config.GrafanaPostgresPassword)
	assert.Equal(t, "postgres://user:pass@localhost/db", Config.ReportDbUri)
	assert.Equal(t, "/grafana", Config.GrafanaPath)
	assert.Equal(t, "/webssh", Config.WebSSHPath)
	assert.Equal(t, "/prometheus", Config.PrometheusPath)
	assert.Equal(t, "3100", Config.PromtailPort)
	assert.Equal(t, "localhost", Config.PromtailAddress)
	assert.Equal(t, "issuer", Config.Issuer2FA)
	assert.Equal(t, "/tmp/data", Config.DataDir)
	assert.Equal(t, "/tmp/creds", Config.CredentialsDir)
	assert.Equal(t, "token", Config.RegistrationToken)
	assert.Equal(t, "secret", Config.SecretJWT)
	assert.Equal(t, "password", Config.AdminPassword)
	assert.Equal(t, "admin", Config.AdminUsername)
	assert.Equal(t, []string{"127.0.0.1:8080", "0.0.0.0:9090"}, Config.ListenAddress)
	assert.Equal(t, []string{"pass", "secret", "key"}, Config.SensitiveList)
	assert.Equal(t, "/etc/openvpn_custom", Config.OpenVPNDir)
	assert.Equal(t, "/tmp/secrets", Config.SecretsDir)
	assert.Equal(t, "example.com", Config.FQDN)
	assert.True(t, Config.ValidSubscription)
}

func TestInitDefaults(t *testing.T) {
	logs.Init("test")
	// Save original config
	originalConfig := Config
	defer func() {
		Config = originalConfig
	}()

	// Clean up env vars
	os.Unsetenv("ENCRYPTION_KEY")
	os.Unsetenv("GRAFANA_POSTGRES_PASSWORD")
	os.Unsetenv("REPORT_DB_URI")
	os.Unsetenv("GRAFANA_PATH")
	os.Unsetenv("WEBSSH_PATH")
	os.Unsetenv("PROMETHEUS_PATH")
	os.Unsetenv("PROMTAIL_PORT")
	os.Unsetenv("PROMTAIL_ADDRESS")
	os.Unsetenv("ISSUER_2FA")
	os.Unsetenv("DATA_DIR")
	os.Unsetenv("CREDENTIALS_DIR")
	os.Unsetenv("REGISTRATION_TOKEN")
	os.Unsetenv("SECRET_JWT")
	os.Unsetenv("ADMIN_PASSWORD")
	os.Unsetenv("ADMIN_USERNAME")
	os.Unsetenv("LISTEN_ADDRESS")
	os.Unsetenv("SENSITIVE_LIST")
	os.Unsetenv("OVPN_DIR")
	os.Unsetenv("SECRETS_DIR")
	os.Unsetenv("FQDN")
	os.Unsetenv("VALID_SUBSCRIPTION")
	os.Unsetenv("PROMETHEUS_AUTH_PASSWORD")
	os.Unsetenv("PROMETHEUS_AUTH_USERNAME")
	os.Unsetenv("RETENTION_DAYS")
	os.Unsetenv("CACHE_TTL")
	os.Unsetenv("OVPN_UDP_PORT")
	os.Unsetenv("OVPN_NETMASK")
	os.Unsetenv("OVPN_NETWORK")

	// Set only required env vars
	os.Setenv("ENCRYPTION_KEY", "12345678901234567890123456789012")
	os.Setenv("GRAFANA_POSTGRES_PASSWORD", "grafana_pass")
	os.Setenv("REPORT_DB_URI", "postgres://user:pass@localhost/db")
	os.Setenv("GRAFANA_PATH", "/grafana")
	os.Setenv("WEBSSH_PATH", "/webssh")
	os.Setenv("PROMETHEUS_PATH", "/prometheus")
	os.Setenv("PROMTAIL_PORT", "3100")
	os.Setenv("PROMTAIL_ADDRESS", "localhost")
	os.Setenv("ISSUER_2FA", "issuer")
	os.Setenv("DATA_DIR", "/tmp/data")
	os.Setenv("CREDENTIALS_DIR", "/tmp/creds")
	os.Setenv("REGISTRATION_TOKEN", "token")
	os.Setenv("SECRET_JWT", "secret")
	os.Setenv("ADMIN_PASSWORD", "password")
	os.Setenv("ADMIN_USERNAME", "admin")

	Init()

	// Check defaults
	assert.Equal(t, "prometheus", Config.PrometheusAuthPassword)
	assert.Equal(t, "prometheus", Config.PrometheusAuthUsername)
	assert.Equal(t, "60", Config.RetentionDays)
	assert.False(t, Config.ValidSubscription)
	assert.Equal(t, "7200", Config.CacheTTL)
	assert.Equal(t, "1194", Config.OpenVPNUDPPort)
	assert.Equal(t, "255.255.0.0", Config.OpenVPNNetmask)
	assert.Equal(t, "172.21.0.0", Config.OpenVPNNetwork)
	assert.Equal(t, "/etc/openvpn", Config.OpenVPNDir)
	assert.Equal(t, []string{"password", "secret", "token", "passphrase", "private", "key"}, Config.SensitiveList)
	assert.Equal(t, []string{"127.0.0.1:5000"}, Config.ListenAddress)
}

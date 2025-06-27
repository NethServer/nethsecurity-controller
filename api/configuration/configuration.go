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
	"encoding/json"
	"os"
	"strings"

	"github.com/NethServer/nethsecurity-controller/api/logs"
	"github.com/NethServer/nethsecurity-controller/api/models"
	"github.com/Showmax/go-fqdn"
)

type Configuration struct {
	OpenVPNDir     string `json:"openvpn_dir"`
	OpenVPNNetwork string `json:"openvpn_network"`
	OpenVPNNetmask string `json:"openvpn_netmask"`
	OpenVPNUDPPort string `json:"openvpn_udp_port"`

	OpenVPNStatusDir string `json:"openvpn_status_dir"` // Deprecated: it can be removed in the future
	OpenVPNCCDDir    string `json:"openvpn_ccd_dir"`
	OpenVPNProxyDir  string `json:"openvpn_proxy_dir"`
	OpenVPNPKIDir    string `json:"openvpn_pki_dir"`
	OpenVPNMGMTSock  string `json:"openvpn_mgmt_sock"`

	ListenAddress []string `json:"listen_address"`

	AdminUsername     string   `json:"admin_username"`
	AdminPassword     string   `json:"admin_password"`
	SecretJWT         string   `json:"secret_jwt"`
	SensitiveList     []string `json:"sensitive_list"`
	RegistrationToken string   `json:"registration_token"`

	TokensDir      string `json:"tokens_dir"`
	CredentialsDir string `json:"credentials_dir"`
	DataDir        string `json:"data_dir"`
	Issuer2FA      string `json:"issuer_2fa"`
	SecretsDir     string `json:"secrets_dir"` // Deprecated: it can be removed in the future

	PromtailAddress string `json:"promtail_address"`
	PromtailPort    string `json:"promtail_port"`
	PrometheusPath  string `json:"prometheus_path"`
	WebSSHPath      string `json:"webssh_path"`
	GrafanaPath     string `json:"grafana_path"`

	EasyRSAPath string `json:"easy_rsa_path"`

	ProxyProtocol string `json:"proxy_protocol"`
	ProxyHost     string `json:"proxy_host"`
	ProxyPort     string `json:"proxy_port"`
	LoginEndpoint string `json:"login_endpoint"`

	FQDN string `json:"fqdn"`

	CacheTTL string `json:"cache_ttl"`

	ValidSubscription bool `json:"valid_subscription"`

	ReportDbUri string `json:"report_db_uri"`

	GeoIPDbDir     string `json:"geoip_db_dir"`
	MaxmindLicense string `json:"maxmind_license"`

	GrafanaPostgresPassword string `json:"grafana_postgres_password"`

	RetentionDays string `json:"retention_days"`

	EncryptionKey string `json:"encryption_key"`

	PlatformInfo models.PlatformInfo `json:"platform_info"`
}

var Config = Configuration{}

func Init() {
	// read configuration from ENV
	if os.Getenv("LISTEN_ADDRESS") != "" {
		Config.ListenAddress = strings.Split(os.Getenv("LISTEN_ADDRESS"), ",")
	} else {
		Config.ListenAddress = []string{"127.0.0.1:5000"}
	}

	if os.Getenv("ADMIN_USERNAME") != "" {
		Config.AdminUsername = os.Getenv("ADMIN_USERNAME")
	} else {
		logs.Logs.Println("[CRITICAL][ENV] ADMIN_USERNAME variable is empty")
		os.Exit(1)
	}
	if os.Getenv("ADMIN_PASSWORD") != "" {
		Config.AdminPassword = os.Getenv("ADMIN_PASSWORD")
	} else {
		logs.Logs.Println("[CRITICAL][ENV] ADMIN_PASSWORD variable is empty")
		os.Exit(1)
	}
	if os.Getenv("SECRET_JWT") != "" {
		Config.SecretJWT = os.Getenv("SECRET_JWT")
	} else {
		logs.Logs.Println("[CRITICAL][ENV] SECRET_JWT variable is empty")
		os.Exit(1)
	}
	if os.Getenv("SENSITIVE_LIST") != "" {
		Config.SensitiveList = strings.Split(os.Getenv("SENSITIVE_LIST"), ",")
	} else {
		Config.SensitiveList = []string{"password", "secret", "token", "passphrase", "private", "key"}
	}
	if os.Getenv("REGISTRATION_TOKEN") != "" {
		Config.RegistrationToken = os.Getenv("REGISTRATION_TOKEN")
	} else {
		logs.Logs.Println("[CRITICAL][ENV] REGISTRATION_TOKEN variable is empty")
		os.Exit(1)
	}

	if os.Getenv("TOKENS_DIR") != "" {
		Config.TokensDir = os.Getenv("TOKENS_DIR")
	} else {
		logs.Logs.Println("[CRITICAL][ENV] TOKENS_DIR variable is empty")
		os.Exit(1)
	}
	if os.Getenv("CREDENTIALS_DIR") != "" {
		Config.CredentialsDir = os.Getenv("CREDENTIALS_DIR")
	} else {
		logs.Logs.Println("[CRITICAL][ENV] CREDENTIALS_DIR variable is empty")
		os.Exit(1)
	}
	if os.Getenv("DATA_DIR") != "" {
		Config.DataDir = os.Getenv("DATA_DIR")
	} else {
		logs.Logs.Println("[CRITICAL][ENV] DATA_DIR variable is empty")
		os.Exit(1)
	}

	if os.Getenv("ISSUER_2FA") != "" {
		Config.Issuer2FA = os.Getenv("ISSUER_2FA")
	} else {
		logs.Logs.Println("[CRITICAL][ENV] ISSUER_2FA variable is empty")
		os.Exit(1)
	}

	if os.Getenv("SECRETS_DIR") != "" {
		Config.SecretsDir = os.Getenv("SECRETS_DIR")
	} else {
		logs.Logs.Println("[CRITICAL][ENV] SECRETS_DIR variable is empty")
		os.Exit(1)
	}

	if os.Getenv("OVPN_DIR") != "" {
		Config.OpenVPNDir = os.Getenv("OVPN_DIR")
	} else {
		Config.OpenVPNDir = "/etc/openvpn"
	}
	if os.Getenv("OVPN_NETWORK") != "" {
		Config.OpenVPNNetwork = os.Getenv("OVPN_NETWORK")
	} else {
		Config.OpenVPNNetwork = "172.21.0.0"
	}
	if os.Getenv("OVPN_NETMASK") != "" {
		Config.OpenVPNNetmask = os.Getenv("OVPN_NETMASK")
	} else {
		Config.OpenVPNNetmask = "255.255.0.0"
	}
	if os.Getenv("OVPN_UDP_PORT") != "" {
		Config.OpenVPNUDPPort = os.Getenv("OVPN_UDP_PORT")
	} else {
		Config.OpenVPNUDPPort = "1194"
	}

	Config.OpenVPNStatusDir = Config.OpenVPNDir + "/status"
	if os.Getenv("OVPN_C_DIR") != "" {
		Config.OpenVPNCCDDir = os.Getenv("OVPN_C_DIR")
	} else {
		Config.OpenVPNCCDDir = Config.OpenVPNDir + "/ccd"
	}
	if os.Getenv("OVPN_P_DIR") != "" {
		Config.OpenVPNProxyDir = os.Getenv("OVPN_P_DIR")
	} else {
		Config.OpenVPNProxyDir = Config.OpenVPNDir + "/proxy"
	}
	if os.Getenv("OVPN_K_DIR") != "" {
		Config.OpenVPNPKIDir = os.Getenv("OVPN_K_DIR")
	} else {
		Config.OpenVPNPKIDir = Config.OpenVPNDir + "/pki"
	}
	if os.Getenv("OVPN_M_SOCK") != "" {
		Config.OpenVPNMGMTSock = os.Getenv("OVPN_M_SOCK")
	} else {
		Config.OpenVPNMGMTSock = Config.OpenVPNDir + "/run/mgmt.sock"
	}

	if os.Getenv("PROMTAIL_ADDRESS") != "" {
		Config.PromtailAddress = os.Getenv("PROMTAIL_ADDRESS")
	} else {
		logs.Logs.Println("[CRITICAL][ENV] PROMTAIL_ADDRESS variable is empty")
		os.Exit(1)
	}
	if os.Getenv("PROMTAIL_PORT") != "" {
		Config.PromtailPort = os.Getenv("PROMTAIL_PORT")
	} else {
		logs.Logs.Println("[CRITICAL][ENV] PROMTAIL_PORT variable is empty")
		os.Exit(1)
	}
	if os.Getenv("PROMETHEUS_PATH") != "" {
		Config.PrometheusPath = os.Getenv("PROMETHEUS_PATH")
	} else {
		logs.Logs.Println("[CRITICAL][ENV] PROMETHEUS_PATH variable is empty")
		os.Exit(1)
	}
	if os.Getenv("WEBSSH_PATH") != "" {
		Config.WebSSHPath = os.Getenv("WEBSSH_PATH")
	} else {
		logs.Logs.Println("[CRITICAL][ENV] WEBSSH_PATH variable is empty")
		os.Exit(1)
	}
	if os.Getenv("GRAFANA_PATH") != "" {
		Config.GrafanaPath = os.Getenv("GRAFANA_PATH")
	} else {
		logs.Logs.Println("[CRITICAL][ENV] GRAFANA_PATH variable is empty")
		os.Exit(1)
	}

	if os.Getenv("EASYRSA_PATH") != "" {
		Config.EasyRSAPath = os.Getenv("EASYRSA_PATH")
	} else {
		Config.EasyRSAPath = "/usr/share/easy-rsa/easyrsa"
	}

	if os.Getenv("PROXY_PROTOCOL") != "" {
		Config.ProxyProtocol = os.Getenv("PROXY_PROTOCOL")
	} else {
		Config.ProxyProtocol = "http://"
	}
	if os.Getenv("PROXY_HOST") != "" {
		Config.ProxyHost = os.Getenv("PROXY_HOST")
	} else {
		Config.ProxyHost = "localhost"
	}
	if os.Getenv("PROXY_PORT") != "" {
		Config.ProxyPort = os.Getenv("PROXY_PORT")
	} else {
		Config.ProxyPort = "8080"
	}
	if os.Getenv("LOGIN_ENDPOINT") != "" {
		Config.LoginEndpoint = os.Getenv("LOGIN_ENDPOINT")
	} else {
		Config.LoginEndpoint = "/api/login"
	}

	if os.Getenv("FQDN") != "" {
		Config.FQDN = os.Getenv("FQDN")
	} else {
		Config.FQDN, _ = fqdn.FqdnHostname()
	}

	if os.Getenv("CACHE_TTL") != "" {
		Config.CacheTTL = os.Getenv("CACHE_TTL")
	} else {
		Config.CacheTTL = "7200"
	}

	if os.Getenv("VALID_SUBSCRIPTION") != "" {
		Config.ValidSubscription = os.Getenv("VALID_SUBSCRIPTION") == "true"
	} else {
		Config.ValidSubscription = false
	}

	if os.Getenv("REPORT_DB_URI") != "" {
		Config.ReportDbUri = os.Getenv("REPORT_DB_URI")
	} else {
		logs.Logs.Println("[CRITICAL][ENV] REPORT_DB_URI variable is empty")
		os.Exit(1)
	}

	// Assuming the file is named GeoLite2-Country.mmdb
	if os.Getenv("GEOIP_DB_DIR") != "" {
		Config.GeoIPDbDir = os.Getenv("GEOIP_DB_DIR")
	} else {
		Config.GeoIPDbDir = "."
	}

	if os.Getenv("MAXMIND_LICENSE") != "" {
		Config.MaxmindLicense = os.Getenv("MAXMIND_LICENSE")
	} else {
		logs.Logs.Println("[WARNING][ENV] MAXMIND_LICENSE variable is empty")
		Config.MaxmindLicense = ""
	}

	if os.Getenv("GRAFANA_POSTGRES_PASSWORD") != "" {
		Config.GrafanaPostgresPassword = os.Getenv("GRAFANA_POSTGRES_PASSWORD")
	} else {
		logs.Logs.Println("[CRITICAL][ENV] GRAFANA_POSTGRES_PASSWORD variable is empty")
		os.Exit(1)
	}

	if os.Getenv("RETENTION_DAYS") != "" {
		Config.RetentionDays = os.Getenv("RETENTION_DAYS")
	} else {
		Config.RetentionDays = "60"
	}

	if os.Getenv("ENCRYPTION_KEY") != "" {
		Config.EncryptionKey = os.Getenv("ENCRYPTION_KEY")
		if len(Config.EncryptionKey) != 32 {
			logs.Logs.Println("[CRITICAL][ENV] ENCRYPTION_KEY variable is not 32 bytes")
			os.Exit(1)
		}
	} else {
		logs.Logs.Println("[CRITICAL][ENV] ENCRYPTION_KEY variable is empty")
		os.Exit(1)
	}

	if os.Getenv("PLATFORM_INFO") != "" {
		var platformInfo models.PlatformInfo
		err := json.Unmarshal([]byte(os.Getenv("PLATFORM_INFO")), &platformInfo)
		if err != nil {
			logs.Logs.Println("[WARNING][ENV] PLATFORM_INFO variable is not valid JSON:", err)
		}
		Config.PlatformInfo = platformInfo
	} else {
		Config.PlatformInfo = models.PlatformInfo{}
	}
}

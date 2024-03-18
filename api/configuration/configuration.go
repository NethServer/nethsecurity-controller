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
	"strings"

	"github.com/NethServer/nethsecurity-controller/api/logs"
	"github.com/Showmax/go-fqdn"
)

type Configuration struct {
	OpenVPNDir     string `json:"openvpn_dir"`
	OpenVPNNetwork string `json:"openvpn_network"`
	OpenVPNNetmask string `json:"openvpn_netmask"`
	OpenVPNUDPPort string `json:"openvpn_udp_port"`

	OpenVPNCCDDir   string `json:"openvpn_ccd_dir"`
	OpenVPNProxyDir string `json:"openvpn_proxy_dir"`
	OpenVPNPKIDir   string `json:"openvpn_pki_dir"`
	OpenVPNMGMTSock string `json:"openvpn_mgmt_sock"`

	ListenAddress string `json:"listen_address"`

	AdminUsername     string   `json:"admin_username"`
	AdminPassword     string   `json:"admin_password"`
	SecretJWT         string   `json:"secret_jwt"`
	SensitiveList     []string `json:"sensitive_list"`
	RegistrationToken string   `json:"registration_token"`

	TokensDir      string `json:"tokens_dir"`
	CredentialsDir string `json:"credentials_dir"`
	DataDir        string `json:"data_dir"`

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
}

var Config = Configuration{}

func Init() {
	// read configuration from ENV
	if os.Getenv("LISTEN_ADDRESS") != "" {
		Config.ListenAddress = os.Getenv("LISTEN_ADDRESS")
	} else {
		Config.ListenAddress = "127.0.0.1:5000"
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
}

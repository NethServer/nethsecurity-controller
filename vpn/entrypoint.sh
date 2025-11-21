#!/bin/sh

set -e

ovpn_network=${OVPN_NETWORK:-172.21.0.0}
ovpn_netmask=${OVPN_NETMASK:-255.255.0.0}
cn=${OVPN_CN:-nethsec}
ovpn_port=${OVPN_UDP_PORT:-1194}
tun=${OVPN_TUN:-tunsec}
tun_mtu=${OVPN_TUN_MTU:-1500}
mssfix=${OVPN_MSSFIX:-1450}

if [ ! -f /etc/openvpn/pki/ca.crt ]; then
    cd /etc/openvpn
    EASYRSA_BATCH=1 /usr/share/easy-rsa/easyrsa init-pki
    EASYRSA_BATCH=1 EASYRSA_REQ_CN=$cn /usr/share/easy-rsa/easyrsa build-ca nopass
    openssl dhparam -dsaparam -out pki/dh.pem 2048
    EASYRSA_BATCH=1 EASYRSA_REQ_CN=$cn /usr/share/easy-rsa/easyrsa build-server-full server nopass
    EASYRSA_BATCH=1 EASYRSA_CRL_DAYS=3560 EASYRSA_REQ_CN=$cn /usr/share/easy-rsa/easyrsa gen-crl
    cd -
fi

if [ ! -d /etc/openvpn/ccd ]; then
    mkdir -p /etc/openvpn/ccd
fi

if [ ! -d /etc/openvpn/run ]; then
    mkdir -p /etc/openvpn/run
fi

if [ ! -d /etc/openvpn/proxy ]; then
    mkdir -p /etc/openvpn/proxy
fi

if [ ! -d /etc/openvpn/status ]; then
    mkdir -p /etc/openvpn/status
else
    find  /etc/openvpn/status -name "*.vpn" -delete 2>/dev/null || true
fi

cat << EOF > /etc/openvpn/server.conf
dev $tun
dev-type tun
server $ovpn_network $ovpn_netmask
push "route $ovpn_network $ovpn_netmask"

topology subnet
client-config-dir /etc/openvpn/ccd

ifconfig-pool-persist host-to-net.pool 0

port $ovpn_port
script-security 3
float
multihome

tun-mtu $tun_mtu
mssfix $mssfix

tls-server
remote-cert-tls server
dh /etc/openvpn/pki/dh.pem
ca /etc/openvpn/pki/ca.crt
cert /etc/openvpn/pki/issued/server.crt
key /etc/openvpn/pki/private/server.key
crl-verify /etc/openvpn/pki/crl.pem

client-connect /usr/local/bin/handle-connection
client-disconnect /usr/local/bin/handle-disconnection

# configuration for old easy RSA certs
remote-cert-ku e0 80
remote-cert-eku "TLS Web Client Authentication"

management /etc/openvpn/run/mgmt.sock unix

errors-to-stderr
keepalive 20 120
persist-key
persist-tun
verb 3
EOF

exec "$@"

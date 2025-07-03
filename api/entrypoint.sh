#!/bin/sh

mkdir -p /etc/openvpn/sockets

cd /nethsecurity-api

export ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918}" # sha256sum of "admin"
export SECRET_JWT=$(head /dev/urandom | sha256sum) # regenerate SECRET at each restart to invalidate all tokens
export TOKENS_DIR="${TOKENS_DIR:-/nethsecurity-api/tokens}"
export CREDENTIALS_DIR="${CREDENTIALS_DIR:-/nethsecurity-api/credentials}"
export PROMTAIL_ADDRESS="${PROMTAIL_ADDRESS:-127.0.0.1}"
export PROMTAIL_PORT="${PROMTAIL_PORT:-9900}"

socket=/etc/openvpn/run/mgmt.sock
limit=60
while [ ! -e "$socket" ]; do
    echo "Waiting for $socket to appear ..."
    sleep 1
    limit=$((limit - 1))
    if [ "$limit" -le 0 ]; then
        echo "Socket not found!"
        break
    fi
done

# Create database config for OpenVPN hooks
echo REPORT_DB_URI=$REPORT_DB_URI > /etc/openvpn/conf.env
echo OVPN_NETMASK=$OVPN_NETMASK >> /etc/openvpn/conf.env

exec "$@"

#!/bin/sh

mkdir -p /etc/openvpn/sockets
mkdir -p /nethsecurity-api/tokens
mkdir -p /nethsecurity-api/credentials

cd /nethsecurity-api

ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin}"
SECRET_JWT="${SECRET_JWT:-test}"
TOKENS_DIR="${TOKENS_DIR:-/nethsecurity-api/tokens}"
CREDENTIALS_DIR="${CREDENTIALS_DIR:-/nethsecurity-api/credentials}"
PROMTAIL_ADDRESS="${PROMTAIL_ADDRESS:-127.0.0.1}"
PROMTAIL_PORT="${PROMTAIL_PORT:-9900}"

exec "$@"
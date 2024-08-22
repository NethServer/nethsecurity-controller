#!/bin/sh

mkdir -p /etc/openvpn/sockets
mkdir -p /nethsecurity-api/tokens
mkdir -p /nethsecurity-api/credentials

cd /nethsecurity-api

export ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918}" # sha256sum of "admin"
export SECRET_JWT="${SECRET_JWT:-test}"
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

if [ -n "$MAXMIND_LICENSE" ]; then
    # Download GeoLite database
    if [ ! -f GeoLite2-Country.mmdb ]; then
        curl -v -L --fail --retry 5 --retry-max-time 120 \
            'https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key='$MAXMIND_LICENSE'&suffix=tar.gz' \
            -o db.tar.gz && tar xvzf db.tar.gz --strip-components=1
    fi
fi

exec "$@"

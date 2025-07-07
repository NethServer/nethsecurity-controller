#!/bin/bash

# This script manages a Podman pod for the NethSecurity project.
# It can start or stop a pod with multiple containers (VPN, API, UI, Proxy, and TimescaleDB).
# Optionally, it mounts a local directory as the UI's document root if provided: this option is useful for development purposes.

image_tag=${IMAGE_TAG:-latest}
POD="nethsecurity-pod"

start_pod() {
    # Check if network device tunsec exists, if not fail
    if ! ip link show dev tunsec > /dev/null 2>&1; then
        echo "Network device tunsec does not exist, create it using root privileges:"
        echo
        echo "  ip tuntap add dev tunsec mod tun"
        echo "  ip addr add 172.21.0.1/16 dev tunsec"
        echo "  ip link set dev tunsec up"
        exit 1
    fi

    # Stop the pod if it is already running
    if podman pod exists $POD; then
        echo "Pod $POD already exists"
        exit 0
    fi
    echo "Starting pod $POD with image tag $image_tag"
    podman pod create --replace --name $POD
    podman run --rm --detach --network=host --privileged --cap-add=NET_ADMIN --device /dev/net/tun -v ovpn-data:/etc/openvpn/:z --pod $POD --name $POD-vpn  ghcr.io/nethserver/nethsecurity-vpn:$image_tag
    podman run --rm --detach --network=host --name $POD-db --pod $POD -e POSTGRES_PASSWORD=password -e POSTGRES_USER=report docker.io/timescale/timescaledb:2.20.3-pg16
    # Wait for Postgres to be ready
    echo -n "Waiting for Postgres to start..."
    for i in {1..30}; do
        if podman exec $POD-db pg_isready -U report > /dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    # wait for db, pg_isready is not enough
    sleep 5
    echo "OK"
    cat > api.env <<EOF
LISTEN_ADDRESS=0.0.0.0:5000
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin
SECRET_JWT=secret
PROMTAIL_ADDRESS=127.0.0.1
PROMTAIL_PORT=6565
PROMETHEUS_PATH=/prometheus
WEBSSH_PATH=$(uuidgen)
GRAFANA_PATH=/grafana
REGISTRATION_TOKEN=1234
DATA_DIR=data
OVPN_DIR=/etc/openvpn
REPORT_DB_URI=postgres://report:password@127.0.0.1:5432/report
GRAFANA_POSTGRES_PASSWORD=password
ISSUER_2FA=test
ENCRYPTION_KEY=12345678901234567890123456789012
GIN_MODE=debug
FQDN=localhost
VALID_SUBSCRIPTION=true
PLATFORM_INFO={"vpn_port": "20011", "vpn_network": "172.28.222.0/24", "controller_version": "${IMAGE_TAG}", "metrics_retention_days": 15, "logs_retention_days": 180}
EOF
    podman run --rm --detach --network=host --volumes-from=$POD-vpn --pod $POD --name $POD-api --env-file=api.env ghcr.io/nethserver/nethsecurity-api:$image_tag
    podman run --rm --detach --network=host --pod $POD --name $POD-ui ghcr.io/nethserver/nethsecurity-ui:$image_tag
    sleep 2
    podman run --rm --detach --network=host --volumes-from=$POD-vpn --pod $POD --name $POD-proxy ghcr.io/nethserver/nethsecurity-proxy:$image_tag
}

stop_pod() {
    if ! podman pod exists $POD; then
        return
    fi
    podman pod stop $POD
    podman pod rm $POD
}

case "$1" in
    start)
        start_pod
        ;;
    stop)
        stop_pod
        ;;
    restart)
        stop_pod
        start_pod
        ;;
    *)
        echo "Usage: $0 {start|stop} [htdocs_path]"
        exit 1
        ;;
esac
